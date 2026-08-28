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
	"fmt"
	"maps"
	"net"
	"slices"
	"sync"

	"github.com/altshiftab/altshift_domain_tools/pkg/related/related_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/hackertarget"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml"
	whoisXmlTypes "github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml/types"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	"github.com/altshiftab/utils_go/pkg/net/types/domain_parts"
	"golang.org/x/sync/errgroup"
)

// The confidence each source is worth, on a one-to-five scale.
const (
	ReverseWhoisConfidence = 4
	ReverseIpConfidence    = 2
)

// DefaultSharedHostingDomainLimit bounds how many domains one address may map to before the
// reverse-IP answer is discarded. Past this the address is shared hosting, and co-location says
// nothing about who owns what.
const DefaultSharedHostingDomainLimit = 25

// excludedRegisteredDomains are registered domains co-location can never say anything about,
// because everyone is on them.
var excludedRegisteredDomains = map[string]struct{}{
	"googleusercontent.com": {},
}

// Inference is one reason a domain was attributed, with a confidence and the steps that produced
// it -- for example "reverse whois" followed by the search term that matched.
type Inference struct {
	Confidence int      `json:"confidence"`
	Chain      []string `json:"chain"`
}

// Domain is one attributed domain and why.
//
// It is deliberately lean. The domain security assessment carries a far larger type for the same
// name, holding its DMARC, SPF and DKIM; a discovery run has learned none of that, and a type that
// claimed the fields would be mostly empty.
type Domain struct {
	Domain           string       `json:"domain"`
	RegisteredDomain string       `json:"registered_domain,omitzero"`
	Inferences       []*Inference `json:"inferences,omitzero"`
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

		existing.Inferences = append(existing.Inferences, domain.Inferences...)
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

// ReverseWhois finds domains whose registration records carry an address at the given domain.
//
// The API bills per search, so each term is previewed for a match count before the results are
// bought: a term that matches nothing costs a preview rather than a purchase.
func (finder *Finder) ReverseWhois(
	ctx context.Context,
	domainName string,
	historical bool,
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

	apiKey := finder.config.WhoisXmlApiKey
	if apiKey == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("whoisxml api key"))
	}

	searchType := whoisxml.SearchTypeCurrent
	if historical {
		searchType = whoisxml.SearchTypeHistoric
	}

	// Both the domain itself and any subdomain of it: a registrant address at either is the same
	// party.
	terms := []string{"*@" + domainName, "*@*." + domainName}

	// slices.Concat rather than append: the terms are queried concurrently off this slice, and
	// appending into a shared slice's spare capacity would have them overwrite one another's.
	fetchOptions := slices.Concat(finder.config.FetchOptions, options)

	var (
		domains      []*Domain
		domainsMutex sync.Mutex
	)

	errGroup, groupCtx := errgroup.WithContext(ctx)

	for _, term := range terms {
		errGroup.Go(func() error {
			request := &whoisXmlTypes.ReverseWhoisRequest{
				ApiKey: apiKey,
				AdvancedSearchTerms: []*whoisXmlTypes.AdvancedSearchTerms{
					{Field: "Email", Term: term},
				},
				SearchType: searchType,
				Mode:       whoisxml.ModePreview,
			}

			preview, err := finder.whoisXml.QueryReverseWhois(groupCtx, request, fetchOptions...)
			if err != nil {
				return altshiftErrors.New(fmt.Errorf("query reverse whois (preview): %w", err), term, searchType)
			}
			if preview == nil {
				return altshiftErrors.NewWithTrace(nil_error.New("reverse whois preview response"), term)
			}

			if preview.DomainsCount == 0 {
				return nil
			}

			// A purchase differs from the preview only in its mode, and the preview must not be
			// mutated: copying keeps the search terms identical between the two calls.
			purchaseRequest := *request
			purchaseRequest.Mode = whoisxml.ModePurchase

			purchase, err := finder.whoisXml.QueryReverseWhois(groupCtx, &purchaseRequest, fetchOptions...)
			if err != nil {
				return altshiftErrors.New(fmt.Errorf("query reverse whois (purchase): %w", err), term, searchType)
			}
			if purchase == nil {
				return altshiftErrors.NewWithTrace(nil_error.New("reverse whois purchase response"), term)
			}

			found := make([]*Domain, 0, len(purchase.DomainsList))
			for _, name := range purchase.DomainsList {
				if name == "" || name == domainName {
					continue
				}

				found = append(found, &Domain{
					Domain:     name,
					Inferences: []*Inference{{Confidence: ReverseWhoisConfidence, Chain: []string{"reverse whois", term}}},
				})
			}

			domainsMutex.Lock()
			defer domainsMutex.Unlock()
			domains = append(domains, found...)

			return nil
		})
	}

	if err := errGroup.Wait(); err != nil {
		return nil, fmt.Errorf("err group wait: %w", err)
	}

	return Merge(domains...), nil
}

// ReverseIp finds domains resolving to the same addresses as the given one.
//
// An address serving more domains than the shared-hosting limit is discarded rather than reported:
// it is shared hosting, and everything on it would be attributed to everything else.
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
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip4", domainName)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("lookup ip: %w", err), domainName)
	}

	// slices.Concat rather than append: the addresses are queried concurrently off this slice.
	fetchOptions := slices.Concat(finder.config.FetchOptions, options)

	limit := finder.sharedHostingDomainLimit()

	var (
		domains      []*Domain
		domainsMutex sync.Mutex
	)

	errGroup, groupCtx := errgroup.WithContext(ctx)

	for _, address := range addresses {
		errGroup.Go(func() error {
			names, err := finder.hackerTarget.QueryReverseIp(groupCtx, address, apiKey, fetchOptions...)
			if err != nil {
				return altshiftErrors.New(fmt.Errorf("query reverse ip: %w", err), address.String())
			}

			// An address everyone is on says nothing about who owns what.
			registered := registeredDomainNames(names)
			if len(registered) > limit {
				return nil
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
					Inferences: []*Inference{
						{Confidence: ReverseIpConfidence, Chain: []string{"reverse ip", address.String()}},
					},
				})
			}

			domainsMutex.Lock()
			defer domainsMutex.Unlock()
			domains = append(domains, found...)

			return nil
		})
	}

	if err := errGroup.Wait(); err != nil {
		return nil, fmt.Errorf("err group wait: %w", err)
	}

	return Merge(domains...), nil
}
