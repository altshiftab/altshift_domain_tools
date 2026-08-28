// Package related finds the domains that belong to the same owner as a given domain, and records
// why each one was attributed.
//
// This is not subdomain finding, and the two answer different questions. A subdomain is a host under
// a domain -- vpn.example.com. A related domain is another registration by the same party --
// example.net, example-group.com. Neither source here would find the first, and no amount of
// certificate transparency finds the second.
//
// Two sources are consulted, neither authoritative on its own: reverse whois, which matches
// registration records, and reverse IP, which matches co-hosted addresses. Each domain carries the
// inferences that produced it so a consumer can weigh them, because the two are not worth the same
// -- a registration record naming the same party is strong evidence; sharing an address is weak.
package related

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sync"

	"github.com/altshiftab/altshift_domain_tools/pkg/inference"
	"github.com/altshiftab/altshift_domain_tools/pkg/organization"
	"github.com/altshiftab/altshift_domain_tools/pkg/related/related_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/resolver"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/hackertarget"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml"
	whoisXmlTypes "github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml/types"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	"github.com/altshiftab/utils_go/pkg/net/types/domain_parts"
)

// The methods this package attributes a domain by, and what each is worth.
//
// They differ by an order of magnitude in what they prove: a registration record naming the same
// party is someone stating the relationship, while sharing an address is a fact about a web host.
const (
	MethodReverseWhois             inference.Method = "reverse whois"
	MethodReverseWhoisOrganization inference.Method = "reverse whois organization"
	MethodReverseIp                inference.Method = "reverse ip"

	ReverseWhoisConfidence = inference.ConfidenceStrong
	// ReverseWhoisOrganizationConfidence is a step below what an address at the domain is worth, and
	// deliberately so. An address at the domain is the party stating the relationship; a name in the
	// organisation field is a substring that matched, and nothing here can check that the party it
	// matched is the same party -- unlike the registry walks, which keep an organisation only where
	// its own contacts carry an address at the domain. It is a published association someone had to
	// arrange, which is what ConfidenceFair is for.
	//
	// Being a method of its own rather than a weaker grade of the same one also means Combined still
	// raises a domain both pivots found, which is exactly the case worth raising.
	ReverseWhoisOrganizationConfidence = inference.ConfidenceFair
	ReverseIpConfidence                = inference.ConfidenceWeak
)

// DefaultSharedHostingDomainLimit bounds how many domains one address may map to before the
// reverse-IP answer is discarded. Past this the address is shared hosting, and co-location says
// nothing about who owns what.
const DefaultSharedHostingDomainLimit = 25

// DefaultReverseWhoisMatchLimit bounds how many domains a search term may match before its results
// are left unbought. It is what the shared-hosting limit is to reverse IP: the point past which a
// term has stopped describing one party.
//
// It is one response's worth, so that the default answer is either whole or not bought at all. A
// term matching more domains than a page holds has matched an address everyone shares -- a privacy
// service's, or a registrar's -- rather than one party's registrations, and the first page of that
// is noise rather than a partial answer. A caller who wants it anyway raises the limit, and the
// search then reads as many pages as the limit allows.
//
// The count this is applied to comes from the preview, which is free, so a term it rejects costs
// nothing rather than a credit. That count stops at what one response holds -- a search for the
// addresses at google.com previews as ten thousand, whatever the true number is -- which is the
// other reason the default sits there: it is the largest figure the API will distinguish, and a
// term that reaches it has said only that it matched too much to count.
const DefaultReverseWhoisMatchLimit = whoisxml.MaximumResponseDomains

// DefaultReverseWhoisOrganizationMatchLimit is the same bound for the organisation pivot, and it
// sits far lower because the pivot is far looser.
//
// An address at a domain belongs to that domain and to nothing else. A name in the organisation
// field is a substring, and matches every party whose name happens to contain it -- so where the
// address search can be trusted up to what a response holds, the name search cannot: at that
// figure it has stopped describing a party and started describing a word. A portfolio is the size
// of Kivra's seventeen, or a large group's few hundred; a term matching thousands has matched the
// language rather than the company.
//
// It is the second of the two gates. The first reads the name and rejects what could not possibly
// discriminate; this one reads the free preview and rejects what turns out not to have.
const DefaultReverseWhoisOrganizationMatchLimit = 250

// DefaultSearchTypes is which registration records a search reads where nobody said.
//
// The current ones alone, because that is the half a run can afford to repeat. The two are not the
// same kind of question: the historic records are a sweep, worth making once per domain because
// they hold what redaction has since removed, while the current records are what a domain looks
// like now and are the thing a monitor asks again every time it runs. Reading both by default would
// have every repeat buy the past over again, at the price of a search each.
//
// It is a function rather than a package-level slice so that a caller cannot change what every
// other caller gets by writing to it.
func DefaultSearchTypes() []string {
	return []string{whoisxml.SearchTypeCurrent}
}

// searchTypes is what the call asked for, or what the finder was configured with, or the default.
func (finder *Finder) searchTypes(requested []string) []string {
	if len(requested) != 0 {
		return requested
	}

	if configured := finder.config.SearchTypes; len(configured) != 0 {
		return configured
	}

	return DefaultSearchTypes()
}

// excludedRegisteredDomains are registered domains co-location can never say anything about,
// because everyone is on them.
var excludedRegisteredDomains = map[string]struct{}{
	"googleusercontent.com": {},
}

// Domain is one attributed domain and why.
//
// It is deliberately lean. The domain security assessment carries a far larger type for the same
// name, holding its DMARC, SPF and DKIM; a discovery run has learned none of that, and a type that
// claimed the fields would be mostly empty.
type Domain struct {
	Domain           string                 `json:"domain"`
	RegisteredDomain string                 `json:"registered_domain,omitzero"`
	Inferences       []*inference.Inference `json:"inferences,omitzero"`
}

// Confidence is what the domain's inferences are worth together.
func (domain *Domain) Confidence() inference.Confidence {
	if domain == nil {
		return 0
	}

	return inference.Combined(domain.Inferences)
}

// Merge collapses domains naming the same host, keeping the union of their inferences so a domain
// found by both sources carries both reasons.
func Merge(domains ...*Domain) []*Domain {
	merged := make(map[string]*Domain)

	for _, domain := range domains {
		if domain == nil || domain.Domain == "" {
			continue
		}

		existing, ok := merged[domain.Domain]
		if !ok {
			merged[domain.Domain] = domain
			continue
		}

		existing.Inferences = inference.Merge(append(existing.Inferences, domain.Inferences...))
	}

	found := slices.Collect(maps.Values(merged))
	slices.SortFunc(found, func(a *Domain, b *Domain) int {
		switch {
		case a.Domain < b.Domain:
			return -1
		case a.Domain > b.Domain:
			return 1
		default:
			return 0
		}
	})

	return found
}

// registeredDomain is the registration behind a name, or the name itself where it cannot be read as
// one. Reverse whois answers with registrable domains, so the two are almost always the same.
func registeredDomain(name string) string {
	if parts := domain_parts.New(name); parts != nil && parts.RegisteredDomain != "" {
		return parts.RegisteredDomain
	}

	return name
}

// registeredDomainNames reduces names to the distinct registrations behind them, so that ten hosts
// of one company count as one domain rather than ten.
func registeredDomainNames(names []string) []string {
	registered := make(map[string]struct{})

	for _, name := range names {
		parts := domain_parts.New(name)
		if parts == nil {
			continue
		}

		if parts.RegisteredDomain != "" && parts.TopLevelDomain != "" {
			registered[parts.RegisteredDomain] = struct{}{}
		}
	}

	return slices.Collect(maps.Keys(registered))
}

// results is what a set of concurrent searches found, and why the ones that failed did not.
//
// Both halves are written from several goroutines at once and both matter at the end: a source that
// answered for one input and failed for another has produced something worth returning as well as
// something worth reporting. Neither search here cancels its siblings on the first error, which is
// what an errgroup would do -- and for reverse whois that would mean abandoning a purchase already
// billed because another term went wrong.
type results struct {
	mutex    sync.Mutex
	domains  []*Domain
	failures []error
}

// collect keeps what one search found.
func (results *results) collect(found []*Domain) {
	results.mutex.Lock()
	defer results.mutex.Unlock()

	results.domains = append(results.domains, found...)
}

// record keeps why one search found nothing.
func (results *results) record(err error) {
	results.mutex.Lock()
	defer results.mutex.Unlock()

	results.failures = append(results.failures, err)
}

// finish reports what was found, having logged what failed.
//
// Every one of them failing with nothing to show is not a domain with no relations -- it is the key,
// or the source -- and an empty answer would read as the former. Where a search that failed still
// left something behind, that is worth more than the error is.
//
// It is called once the searches have been waited for, so the fields are read without the lock.
func (results *results) finish(ctx context.Context, searches int, message string) ([]*Domain, error) {
	if searches > 0 && len(results.domains) == 0 && len(results.failures) == searches {
		return nil, fmt.Errorf("every search failed: %w", errors.Join(results.failures...))
	}

	for _, err := range results.failures {
		slog.ErrorContext(altshiftContext.WithError(ctx, err), message)
	}

	return Merge(results.domains...), nil
}

// Finder holds the source clients, their keys, and the settings a run uses.
type Finder struct {
	whoisXml     *whoisxml.Client
	hackerTarget *hackertarget.Client
	config       *related_config.Config
}

// NewFinder builds a finder. A source the caller did not provide is built with its own defaults, so
// a caller who only has keys to pass passes only keys.
func NewFinder(options ...related_config.Option) *Finder {
	config := related_config.New(options...)

	whoisXmlClient := config.WhoisXml
	if whoisXmlClient == nil {
		whoisXmlClient = whoisxml.NewClient()
	}

	hackerTargetClient := config.HackerTarget
	if hackerTargetClient == nil {
		hackerTargetClient = hackertarget.NewClient()
	}

	return &Finder{whoisXml: whoisXmlClient, hackerTarget: hackerTargetClient, config: config}
}

// sharedHostingDomainLimit is the configured limit, or the default where none was set.
func (finder *Finder) sharedHostingDomainLimit() int {
	if limit := finder.config.SharedHostingDomainLimit; limit > 0 {
		return limit
	}

	return DefaultSharedHostingDomainLimit
}

// reverseWhoisMatchLimit is the configured limit, or the default where none was set.
func (finder *Finder) reverseWhoisMatchLimit() int {
	if limit := finder.config.ReverseWhoisMatchLimit; limit > 0 {
		return limit
	}

	return DefaultReverseWhoisMatchLimit
}

// addressResolver is the configured resolver, or the standard library's where none was set.
func (finder *Finder) addressResolver() resolver.AddressResolver {
	if configured := finder.config.AddressResolver; configured != nil {
		return configured
	}

	return net.DefaultResolver
}

// reverseWhoisOrganizationMatchLimit is the configured limit, or the default where none was set.
func (finder *Finder) reverseWhoisOrganizationMatchLimit() int {
	if limit := finder.config.ReverseWhoisOrganizationMatchLimit; limit > 0 {
		return limit
	}

	return DefaultReverseWhoisOrganizationMatchLimit
}

// pivot is one thing to match a registration on: the field, the term, and what a match on it in the
// current records is worth.
//
// The method travels with the term rather than being decided by the caller afterwards, because the
// pivots are not worth the same and a run issues several: an address at the domain is the party
// saying so, while a name in the organisation field is a substring that matched.
type pivot struct {
	field      string
	term       string
	method     inference.Method
	confidence inference.Confidence
}

// searchTerm is one pivot against one set of records: what is actually asked of the API.
type searchTerm struct {
	field      string
	term       string
	searchType string
	method     inference.Method
	confidence inference.Confidence
}

// expand pairs each pivot with each set of records to read.
//
// A match in the historic records is worth one step less than the same match in the current ones,
// because this package claims present ownership and a registration that has since changed is
// weaker evidence of it. One step and not two: redaction means the past is frequently the only
// place the evidence survives at all, so a historic-only match is often a current domain whose
// record went dark rather than one the party let go.
//
// The method is the same either way, deliberately. Two search types are not two independent methods
// agreeing -- they are one search run against two copies of the same registry -- and making them
// separate methods would have Combined raise every domain that appears in both, which is most of
// them.
func expand(pivots []*pivot, searchTypes []string) []*searchTerm {
	terms := make([]*searchTerm, 0, len(pivots)*len(searchTypes))

	for _, searchType := range searchTypes {
		for _, item := range pivots {
			confidence := item.confidence
			if searchType == whoisxml.SearchTypeHistoric {
				confidence = max(confidence-1, inference.Lowest)
			}

			terms = append(
				terms,
				&searchTerm{
					field:      item.field,
					term:       item.term,
					searchType: searchType,
					method:     item.method,
					confidence: confidence,
				},
			)
		}
	}

	return terms
}

// searchRun is what every term of one call shares.
type searchRun struct {
	apiKey       string
	domainName   string
	limit        int
	fetchOptions []fetch_config.Option
}

// pageLimit is how many pages a purchase may read, which is what the run's limit allows to be
// bought. At a limit of one response's worth the two are the same number and nothing pages.
func (run *searchRun) pageLimit() int {
	return (run.limit + whoisxml.MaximumResponseDomains - 1) / whoisxml.MaximumResponseDomains
}

// search previews one term, buys it where the preview says it is worth buying, and records what it
// found or why it did not.
//
// The preview is what makes the deciding free: the API bills a purchase and not a preview, so a
// term matching nothing, and a term matching more than the run will buy, both cost nothing.
func (finder *Finder) search(ctx context.Context, run *searchRun, term *searchTerm, gathered *results) {
	request := &whoisXmlTypes.ReverseWhoisRequest{
		ApiKey: run.apiKey,
		AdvancedSearchTerms: []*whoisXmlTypes.AdvancedSearchTerms{
			{Field: term.field, Term: term.term},
		},
		SearchType: term.searchType,
		Mode:       whoisxml.ModePreview,
	}

	preview, err := finder.whoisXml.QueryReverseWhois(ctx, request, run.fetchOptions...)
	if err != nil {
		gathered.record(
			altshiftErrors.New(
				fmt.Errorf("query reverse whois (preview): %w", err),
				term.field, term.term, term.searchType,
			),
		)

		return
	}
	if preview == nil {
		gathered.record(altshiftErrors.NewWithTrace(nil_error.New("reverse whois preview response"), term.term))

		return
	}

	if preview.DomainsCount == 0 {
		return
	}

	// The preview counts no higher than one response holds: a count at that ceiling means "this
	// many, or ten times this many", so it is a floor rather than a total and cannot be compared
	// against a limit as though it were exact.
	atCeiling := preview.DomainsCount >= whoisxml.MaximumResponseDomains

	// A term every registration carries says nothing about who owns what, and the preview is what
	// says so before a credit is spent finding out. A count at the ceiling is left alone too where
	// only one page would be bought, because the answer would then be a page of an unknown number
	// and would not look like one.
	if preview.DomainsCount > run.limit || (atCeiling && run.limit <= whoisxml.MaximumResponseDomains) {
		slog.WarnContext(
			ctx,
			"A reverse whois term matched more domains than the limit allows, and was left unbought.",
			slog.String("field", term.field),
			slog.String("term", term.term),
			slog.String("search_type", term.searchType),
			slog.Int("domains_count", preview.DomainsCount),
			slog.Bool("domains_count_at_ceiling", atCeiling),
			slog.Int("limit", run.limit),
		)

		return
	}

	// A purchase differs from the preview only in its mode, and the preview must not be mutated:
	// copying keeps the search terms identical between the two calls.
	purchaseRequest := *request
	purchaseRequest.Mode = whoisxml.ModePurchase

	// Pages already read come back with the error, so a purchase that failed part way through is
	// still worth what it bought.
	names, truncated, err := finder.whoisXml.QueryReverseWhoisPages(
		ctx,
		&purchaseRequest,
		run.pageLimit(),
		run.fetchOptions...,
	)
	if err != nil {
		gathered.record(
			altshiftErrors.New(
				fmt.Errorf("query reverse whois pages (purchase): %w", err),
				term.field, term.term, term.searchType,
			),
		)
	} else if truncated {
		// The preview said the results fit, and the cursor says they did not. Which of the two is
		// wrong does not matter; what matters is that the answer is short and does not look it.
		slog.WarnContext(
			ctx,
			"A reverse whois purchase left pages unread, so its domains are not all of them.",
			slog.String("field", term.field),
			slog.String("term", term.term),
			slog.String("search_type", term.searchType),
			slog.Int("domains_count", preview.DomainsCount),
			slog.Int("page_limit", run.pageLimit()),
		)
	}

	found := make([]*Domain, 0, len(names))
	for _, name := range names {
		if name == "" || name == run.domainName {
			continue
		}

		found = append(found, &Domain{
			Domain: name,
			// Set here as well as on the reverse-IP side, so that the field means the same thing
			// whichever source filled it in. The API answers with registrable domains, so this is
			// almost always the name itself; going through domain_parts makes it right anyway where
			// one comes back with a host on the front.
			RegisteredDomain: registeredDomain(name),
			Inferences: []*inference.Inference{
				inference.New(term.method, term.confidence, term.field, term.term, term.searchType),
			},
		})
	}

	gathered.collect(found)
}

// searchAll runs the terms concurrently and gathers what they found.
func (finder *Finder) searchAll(
	ctx context.Context,
	run *searchRun,
	terms []*searchTerm,
	message string,
) ([]*Domain, error) {
	var (
		gathered  results
		waitGroup sync.WaitGroup
	)

	for _, term := range terms {
		waitGroup.Go(func() { finder.search(ctx, run, term, &gathered) })
	}

	waitGroup.Wait()

	return gathered.finish(ctx, len(terms), message)
}

// searchRun builds what the terms of one call share, or says why the call cannot be made.
func (finder *Finder) newSearchRun(
	domainName string,
	options []fetch_config.Option,
	limit int,
) (*searchRun, error) {
	apiKey := finder.config.WhoisXmlApiKey
	if apiKey == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("whoisxml api key"))
	}

	return &searchRun{
		apiKey:     apiKey,
		domainName: domainName,
		limit:      limit,
		// slices.Concat rather than append: the terms are queried concurrently off this slice, and
		// appending into a shared slice's spare capacity would have them overwrite one another's.
		fetchOptions: slices.Concat(finder.config.FetchOptions, options),
	}, nil
}

// ReverseWhois finds domains whose registration records carry an address at the given domain.
//
// The API bills per search, so each term is previewed for a match count before the results are
// bought: a term that matches nothing costs a preview rather than a purchase, and so does one
// matching more than DefaultReverseWhoisMatchLimit, which has stopped describing one party.
//
// A term that fails does not take the others down with it. A purchase already made is not worth
// discarding because a second search went wrong, so failures are reported and what was bought is
// kept -- unless every term failed with nothing to show, which is the key or the API rather than a
// domain with no relations, and is returned as the error it is.
//
// searchTypes says which records to read; nil is whatever the finder was configured with, and
// failing that DefaultSearchTypes. Each type is a search of its own and bills as one.
func (finder *Finder) ReverseWhois(
	ctx context.Context,
	domainName string,
	searchTypes []string,
	options ...fetch_config.Option,
) ([]*Domain, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if finder == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("finder"))
	}

	if domainName == "" {
		return nil, nil
	}

	run, err := finder.newSearchRun(domainName, options, finder.reverseWhoisMatchLimit())
	if err != nil {
		return nil, fmt.Errorf("new search run: %w", err)
	}

	// Both the domain itself and any subdomain of it: a registrant address at either is the same
	// party.
	pivots := []*pivot{
		{
			field:      whoisxml.FieldEmail,
			term:       "*@" + domainName,
			method:     MethodReverseWhois,
			confidence: ReverseWhoisConfidence,
		},
		{
			field:      whoisxml.FieldEmail,
			term:       "*@*." + domainName,
			method:     MethodReverseWhois,
			confidence: ReverseWhoisConfidence,
		},
	}

	terms := expand(pivots, finder.searchTypes(searchTypes))

	return finder.searchAll(ctx, run, terms, "An error occurred when searching the registration records.")
}

// ReverseWhoisOrganization finds domains registered to the party that holds the given domain.
//
// It is the pivot that survives redaction. Most gTLD registrations made since 2018 carry no
// registrant e-mail at all, so the address search finds nothing for them however many domains the
// party holds -- kivra.com matches none, and its organisation matches seventeen.
//
// What it does not have is a check. The ARIN walk in pkg/network_range keeps only the organisations
// whose own contacts carry an address at the domain, because a name is a poor thing to attribute on;
// here the API answers with bare domain names and there is nothing to check them against. So the
// name is judged before it is searched and the count is judged before it is bought, and what
// survives both is attributed at ReverseWhoisOrganizationConfidence rather than at what an address
// at the domain is worth.
//
// An empty organizationName is guessed from the domain's own label, which is what most parties are
// registered under. A guess that does not survive the name gate is dropped with a warning rather
// than returned as an error, the caller having asked for a search of the domain rather than for
// that name in particular; a name the caller did name and that fails the gate is an error, because
// the caller asked for something that cannot be done.
func (finder *Finder) ReverseWhoisOrganization(
	ctx context.Context,
	domainName string,
	organizationName string,
	searchTypes []string,
	options ...fetch_config.Option,
) ([]*Domain, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if finder == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("finder"))
	}

	if domainName == "" {
		return nil, nil
	}

	provided := organizationName != ""
	if !provided {
		organizationName = organization.Label(domainName)
	}

	// The company form and the words every company shares are dropped, both because what is left is
	// the fairer thing to judge and because the shorter term matches strictly more: the search is a
	// substring one, so "Kivra" finds "Kivra AB" and whatever else the record spells differently.
	distinctive := organization.Distinctive(organizationName)

	if err := organization.Check(organizationName); err != nil {
		if provided {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("organization check: %w", err),
				organizationName,
			)
		}

		slog.WarnContext(
			ctx,
			"The name guessed from the domain is not worth searching on, so no organisation search was made.",
			slog.String("domain", domainName),
			slog.String("organization", organizationName),
			slog.String("reason", err.Error()),
		)

		return nil, nil
	}

	run, err := finder.newSearchRun(domainName, options, finder.reverseWhoisOrganizationMatchLimit())
	if err != nil {
		return nil, fmt.Errorf("new search run: %w", err)
	}

	// The organisation field and the contact name, because a party is written into whichever of them
	// the registrar asked for: Kivra matches seventeen domains on the first and nine on the second.
	pivots := []*pivot{
		{
			field:      whoisxml.FieldRegistrantOrganization,
			term:       distinctive,
			method:     MethodReverseWhoisOrganization,
			confidence: ReverseWhoisOrganizationConfidence,
		},
		{
			field:      whoisxml.FieldRegistrantName,
			term:       distinctive,
			method:     MethodReverseWhoisOrganization,
			confidence: ReverseWhoisOrganizationConfidence,
		},
	}

	terms := expand(pivots, finder.searchTypes(searchTypes))

	return finder.searchAll(ctx, run, terms, "An error occurred when searching for the party's registrations.")
}

// ReverseIp finds domains resolving to the same addresses as the given one.
//
// An address serving more domains than the shared-hosting limit is discarded rather than reported:
// it is shared hosting, and everything on it would be attributed to everything else.
//
// One address failing does not discard what the others found, as in ReverseWhois: a domain resolving
// to four addresses has four independent answers, and losing three of them to the fourth's rate
// limit would be a worse answer reported as a whole one. Every address failing is returned as the
// error it is.
func (finder *Finder) ReverseIp(
	ctx context.Context,
	domainName string,
	options ...fetch_config.Option,
) ([]*Domain, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if finder == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("finder"))
	}

	if domainName == "" {
		return nil, nil
	}

	apiKey := finder.config.HackerTargetApiKey
	if apiKey == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("hackertarget api key"))
	}

	// The reverse IP lookup is IPv4 only, so only the A records are asked for.
	addresses, err := finder.addressResolver().LookupIP(ctx, "ip4", domainName)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("lookup ip: %w", err), domainName)
	}

	// slices.Concat rather than append: the addresses are queried concurrently off this slice.
	fetchOptions := slices.Concat(finder.config.FetchOptions, options)

	limit := finder.sharedHostingDomainLimit()

	var (
		gathered  results
		waitGroup sync.WaitGroup
	)

	for _, address := range addresses {
		waitGroup.Go(func() {
			names, err := finder.hackerTarget.QueryReverseIp(ctx, address, apiKey, fetchOptions...)
			if err != nil {
				gathered.record(altshiftErrors.New(fmt.Errorf("query reverse ip: %w", err), address.String()))

				return
			}

			// An address everyone is on says nothing about who owns what.
			registered := registeredDomainNames(names)
			if len(registered) > limit {
				return
			}

			found := make([]*Domain, 0, len(registered))
			for _, name := range registered {
				if name == "" || name == domainName {
					continue
				}
				if _, excluded := excludedRegisteredDomains[name]; excluded {
					continue
				}

				found = append(found, &Domain{
					Domain:           name,
					RegisteredDomain: name,
					Inferences: []*inference.Inference{
						inference.New(MethodReverseIp, ReverseIpConfidence, address.String()),
					},
				})
			}

			gathered.collect(found)
		})
	}

	waitGroup.Wait()

	return gathered.finish(ctx, len(addresses), "An error occurred when looking up an address's other domains.")
}
