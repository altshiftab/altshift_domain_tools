// Package finder finds the address space a domain's owner holds.
//
// Three sources answer, and they find different things. A registry knows what a party was allocated,
// including space it is not using; a mail policy declares what it sends from, including space it
// uses under someone else's allocation. None is a superset of another, so all three run and the
// answers are merged.
//
// The two registries are two of the five, covering between them Europe, the Middle East, Central
// Asia and North America. A party whose space is registered with APNIC, AFRINIC or LACNIC is not
// found by either, so an empty answer is still not evidence that a party holds nothing.
//
// A range more than one source found carries all of their inferences, which is what lets a consumer
// tell a range independent sources agree on from one a single weak signal produced.
package finder

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/altshiftab/altshift_domain_tools/pkg/inference"
	"github.com/altshiftab/altshift_domain_tools/pkg/network_range/finder/finder_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/network_range/reverse"
	"github.com/altshiftab/altshift_domain_tools/pkg/network_range/spf"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/arin"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/rdap"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/rdap/rdap_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripe"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripestat"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whois"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	"log/slog"
)

// Method is how a registry attributes a range, and Confidence what that is worth: a registry record
// is a party stating what it holds.
//
// The registries are separate methods rather than one, because they are separate databases
// answering about separate parts of the world -- so a range more than one of them names is a range
// independent records agree on, which is worth more than any of them alone.
//
// All four are worth the same, because all four rest on the same thing: an address at the domain,
// found in the registry's own record. What differs between them is the route taken to it, and that
// is what an inference's steps say.
const (
	MethodRipe     inference.Method = "ripe registry"
	RipeConfidence                  = inference.ConfidenceStrong

	MethodArin     inference.Method = "arin registry"
	ArinConfidence                  = inference.ConfidenceStrong

	MethodApnic     inference.Method = "apnic registry"
	ApnicConfidence                  = inference.ConfidenceStrong

	MethodAfrinic     inference.Method = "afrinic registry"
	AfrinicConfidence                  = inference.ConfidenceStrong
)

// The methods that attribute a range through a party's networks rather than through its
// allocations, and what each is worth.
//
// They are a second axis, and it finds what the first cannot: an allocation is what a party was
// given, a prefix is what its network authorises or announces, and space routed under someone
// else's allocation appears only here. They are also the one route into the region no registry
// search reaches, the routing data being global where a registry is not.
const (
	// MethodRpki is a route origin authorisation: the address holder signing, under RPKI, that the
	// network may originate the prefix. A signed statement by the party is worth what a registry
	// record is worth, and is rather harder to fake.
	MethodRpki     inference.Method = "rpki authorisation"
	RpkiConfidence                  = inference.ConfidenceStrong

	// MethodRouteObject is the registry's own version of the same statement: the maintainer of the
	// address space authorising a network to announce it.
	MethodRouteObject     inference.Method = "route object"
	RouteObjectConfidence                  = inference.ConfidenceStrong

	// MethodBgp is an observation rather than a claim, and is worth less for a reason that matters:
	// a transit provider originates its customers' space, so an announcement alone attributes a
	// customer's addresses to its provider. It is evidence the prefix and the network belong
	// together, not evidence of who holds the addresses.
	MethodBgp     inference.Method = "bgp announcement"
	BgpConfidence                  = inference.ConfidenceFair
)

// The steps an inference names where a range came from one of the two routes into a registry that
// offers no search from a domain.
const (
	// ViaAbuseMailbox is the inverse search on the conventional abuse@<domain>.
	ViaAbuseMailbox = "abuse mailbox"
	// ViaName is the name search, checked against the address on the party's contact card.
	ViaName = "name"
)

// Tenure is whether the party holds the address space or merely uses it.
//
// The two are different facts and both are worth having. A party with an address inside a provider's
// block genuinely has that address -- reporting it is right -- but it cannot keep it, cannot route
// it, and will be given another when the provider reassigns it. So the address is the party's today
// and the block is the provider's always, and a consumer deciding what a party owns needs to be able
// to tell the two apart.
//
// It matters most as a rule about what not to do: space a party only uses must never be expanded
// from. Attributing one address inside a provider's block is correct; treating that address as an
// anchor and taking the block around it would hand a customer its provider's entire estate, which is
// the same mistake as following an SPF record into a mail provider.
type Tenure string

const (
	// TenureUnknown is a range nothing said either way about. Most sources say nothing: a routing
	// announcement and a mail policy describe use rather than title.
	TenureUnknown Tenure = ""
	// TenureHeld is space registered to the party itself, which it keeps and can route.
	TenureHeld Tenure = "held"
	// TenureUsed is space the party uses inside somebody else's allocation.
	TenureUsed Tenure = "used"
)

// TenureFromStatus reads what a registry's status says about who holds the space.
//
// The registries word it differently and mean the same thing. RIPE writes provider-aggregatable
// against provider-independent -- an ASSIGNED PA range sits inside an allocation somebody else
// holds, where ASSIGNED PI is the party's own and portable. APNIC and AFRINIC say portable and
// non-portable outright. An LIR's own ALLOCATED PA is held: the allocation is the thing it was
// given.
func TenureFromStatus(status string) Tenure {
	status = strings.ToUpper(strings.TrimSpace(status))
	if status == "" {
		return TenureUnknown
	}

	switch {
	case strings.Contains(status, "NON-PORTABLE"):
		return TenureUsed
	case strings.Contains(status, "PORTABLE"):
		return TenureHeld
	// The v6 statuses say who handed the space over, and an LIR passing space on is passing on part
	// of an allocation it holds itself. The order matters: ALLOCATED-BY-LIR opens like an allocation
	// of the party's own and is the opposite of one.
	case strings.Contains(status, "BY-LIR"):
		return TenureUsed
	case strings.Contains(status, "BY-RIR"):
		return TenureHeld
	case strings.HasPrefix(status, "ASSIGNED PA"), strings.HasPrefix(status, "SUB-ALLOCATED"):
		return TenureUsed
	// A bare ASSIGNED is how v6 writes an end user's assignment out of an LIR's allocation.
	case status == "ASSIGNED":
		return TenureUsed
	case strings.Contains(status, " PI"), strings.Contains(status, "LEGACY"),
		strings.HasPrefix(status, "ALLOCATED"), strings.HasPrefix(status, "ASSIGNED ANYCAST"):
		return TenureHeld
	}

	return TenureUnknown
}

// Range is one network attributed to the domain's owner.
type Range struct {
	// Network is the range in CIDR notation.
	Network string `json:"network"`
	// NetName and Status are what the registry called it, where the registry is what found it.
	NetName string `json:"net_name,omitzero"`
	Status  string `json:"status,omitzero"`
	Country string `json:"country,omitzero"`
	// Tenure is whether the party holds the range or only uses it, where a source said so.
	Tenure Tenure `json:"tenure,omitzero"`

	Inferences []*inference.Inference `json:"inferences,omitzero"`
}

// Confidence is what the range's inferences are worth together.
func (networkRange *Range) Confidence() inference.Confidence {
	if networkRange == nil {
		return 0
	}

	return inference.Combined(networkRange.Inferences)
}

// registry is one of the databases reached without a search from a domain.
//
// Both routes into it are held together because they are two ways to the same registry's records
// and are worth the same: whichever finds a range, the range is the registry's answer.
type registry struct {
	method inference.Method
	// whois answers inverse queries over port 43, which is the abuse mailbox route.
	whois *whois.Client
	// rdap answers a name search over HTTPS, which is the name route.
	rdap *rdap.Client
}

// DefaultMaxAutNums bounds how many of a party's networks are followed to their prefixes.
//
// Each one is several requests, and a party running more than a handful of networks is one whose
// prefixes the first few already describe.
const DefaultMaxAutNums = 10

// Finder holds the sources a run uses.
type Finder struct {
	ripe       *ripe.Client
	arin       *arin.Client
	ripestat   *ripestat.Client
	registries []*registry
	config     *finder_config.Config
}

func (finder *Finder) maxAutNums() int {
	if maxAutNums := finder.config.MaxAutNums; maxAutNums > 0 {
		return maxAutNums
	}

	return DefaultMaxAutNums
}

// NewFinder builds a finder. A source the caller did not provide is built with its own defaults, so
// the zero-option call is the ordinary one.
func NewFinder(options ...finder_config.Option) *Finder {
	config := finder_config.New(options...)

	ripeClient := config.Ripe
	if ripeClient == nil {
		ripeClient = ripe.NewClient()
	}

	arinClient := config.Arin
	if arinClient == nil {
		arinClient = arin.NewClient()
	}

	ripestatClient := config.Ripestat
	if ripestatClient == nil {
		ripestatClient = ripestat.NewClient()
	}

	return &Finder{
		ripe:       ripeClient,
		arin:       arinClient,
		ripestat:   ripestatClient,
		registries: registries(config),
		config:     config,
	}
}

// registries builds the clients for the two databases that offer no search from a domain.
//
// A caller that supplied its own gets those and no more, which is how a run is confined to the
// servers a caller means -- a test's, or one registry's. Otherwise both are built with the settings
// each of their servers needs, which do not agree: APNIC matches a name by prefix and needs a
// trailing asterisk, AFRINIC matches by token and needs none.
func registries(config *finder_config.Config) []*registry {
	if len(config.Whois) != 0 || len(config.Rdap) != 0 {
		return pair(config.Whois, config.Rdap)
	}

	return []*registry{
		{
			method: MethodApnic,
			whois:  whois.NewClient(whois.ApnicHost),
			rdap: rdap.NewClient(
				rdap_config.WithBaseUrl(rdap.ApnicBaseUrl),
				rdap_config.WithNameSuffix(rdap.ApnicNameSuffix),
			),
		},
		{
			method: MethodAfrinic,
			whois:  whois.NewClient(whois.AfrinicHost),
			rdap:   rdap.NewClient(rdap_config.WithBaseUrl(rdap.AfrinicBaseUrl)),
		},
	}
}

// pair puts a caller's clients together by the method they answer for, so that a caller supplying
// one route for a registry and both for another gets what it asked for either way.
func pair(whoisClients map[inference.Method]*whois.Client, rdapClients map[inference.Method]*rdap.Client) []*registry {
	methods := make([]inference.Method, 0, len(whoisClients)+len(rdapClients))
	for method := range whoisClients {
		methods = append(methods, method)
	}
	for method := range rdapClients {
		if _, ok := whoisClients[method]; !ok {
			methods = append(methods, method)
		}
	}

	// Sorted, so that a run does not depend on map iteration.
	slices.Sort(methods)

	built := make([]*registry, 0, len(methods))
	for _, method := range methods {
		built = append(
			built,
			&registry{method: method, whois: whoisClients[method], rdap: rdapClients[method]},
		)
	}

	return built
}

// reverseResolver is what the reverse-delegation walk asks. It needs more of a resolver than the SPF
// walk does, so a caller's SPF resolver is used only where it answers these too.
func (finder *Finder) reverseResolver() reverse.Resolver {
	if resolver := finder.config.ReverseResolver; resolver != nil {
		return resolver
	}

	if resolver, ok := finder.config.Resolver.(reverse.Resolver); ok && resolver != nil {
		return resolver
	}

	return net.DefaultResolver
}

func (finder *Finder) resolver() spf.Resolver {
	if resolver := finder.config.Resolver; resolver != nil {
		return resolver
	}

	return net.DefaultResolver
}

// Find returns the address space the domain's owner holds.
//
// A source that fails is logged and skipped rather than failing the run: they are independent, and
// one being down should not cost the answers of the others. A run where all of them fail returns
// nothing rather than an error, which is the same answer as a party that holds no address space --
// so a consumer that needs to tell those apart should read the log.
func (finder *Finder) Find(ctx context.Context, domain string) ([]*Range, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if finder == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("finder"))
	}

	if domain == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))

	var (
		byNetwork = make(map[string]*Range)
		lock      sync.Mutex
		waitGroup sync.WaitGroup
	)

	add := func(network string, details *Range, inferences ...*inference.Inference) {
		if network == "" {
			return
		}

		lock.Lock()
		defer lock.Unlock()

		existing, ok := byNetwork[network]
		if !ok {
			existing = &Range{Network: network}
			byNetwork[network] = existing
		}

		// The registry knows what a range is called; the mail policy does not, so whichever source
		// has the detail keeps it.
		if details != nil {
			if existing.NetName == "" {
				existing.NetName = details.NetName
			}
			if existing.Status == "" {
				existing.Status = details.Status
			}
			if existing.Country == "" {
				existing.Country = details.Country
			}
		}

		// Held wins over used, and both over nothing said. A range one registry only assigned to the
		// party and another registered to it is the party's: the stronger claim is the true one, and
		// a party is not made a tenant by a second source knowing less.
		if tenure := TenureFromStatus(existing.Status); tenure != TenureUnknown {
			existing.Tenure = tenure
		}
		if existing.Tenure != TenureHeld && details != nil && details.Tenure != TenureUnknown {
			existing.Tenure = details.Tenure
		}

		existing.Inferences = inference.Merge(append(existing.Inferences, inferences...))
	}

	report := func(err error, name string) {
		slog.ErrorContext(
			altshiftContext.WithError(ctx, altshiftErrors.New(fmt.Errorf("%s ranges: %w", name, err), domain)),
			"An error occurred when querying a registry.",
			slog.String("registry", name),
		)
	}

	// The sources that search by domain go first, and not only because they are the good ones. The
	// registries after them cannot search by domain at all and have to be given a name, and the
	// organisations these two attribute are where the best of those names come from.
	//
	// The networks are gathered the same way and for the same reason: they are what the last round
	// follows to the prefixes a party routes, and every one of them was registered to a party this
	// round had already checked against the domain.
	var (
		organizations []string
		autNums       []string
		gatheredLock  sync.Mutex
	)

	gathered := func(names []string, numbers []string) {
		gatheredLock.Lock()
		defer gatheredLock.Unlock()

		organizations = append(organizations, names...)
		autNums = append(autNums, numbers...)
	}

	waitGroup.Go(func() {
		ranges, numbers, err := finder.ripeRanges(ctx, domain)
		if err != nil {
			report(err, "ripe")

			return
		}

		for _, item := range ranges {
			add(item.Network, item, item.Inferences...)
		}

		gathered(nil, numbers)
	})

	waitGroup.Go(func() {
		ranges, names, numbers, err := finder.arinRanges(ctx, domain)
		if err != nil {
			report(err, "arin")

			return
		}

		for _, item := range ranges {
			add(item.Network, item, item.Inferences...)
		}

		gathered(names, numbers)
	})

	waitGroup.Go(func() {
		// A registry hands a reverse zone to the holder of the space and to nobody else, so a
		// delegation pointing into the domain is the registry and the party agreeing about who
		// holds it -- said in the DNS rather than in a database.
		ranges, err := reverse.Networks(ctx, domain, nil, finder.reverseResolver())
		if err != nil {
			slog.ErrorContext(
				altshiftContext.WithError(ctx, altshiftErrors.New(fmt.Errorf("reverse networks: %w", err), domain)),
				"An error occurred when reading the reverse delegations.",
			)

			return
		}

		for _, item := range ranges {
			if item == nil {
				continue
			}
			add(item.Network, nil, item.Inferences...)
		}
	})

	waitGroup.Go(func() {
		ranges, err := spf.Networks(ctx, domain, finder.resolver())
		if err != nil {
			slog.ErrorContext(
				altshiftContext.WithError(ctx, altshiftErrors.New(fmt.Errorf("spf networks: %w", err), domain)),
				"An error occurred when reading the mail policy.",
			)

			return
		}

		for _, item := range ranges {
			if item == nil {
				continue
			}
			add(item.Network, nil, item.Inferences...)
		}
	})

	waitGroup.Wait()

	// The domain's own label, and whatever the first round learned the owner is called. The label
	// alone carries most of them -- a party is usually registered under the name it puts in its
	// domain -- and a name from a registry that did search by domain carries the ones it does not.
	names := arin.SearchNames(domain, organizations)

	for _, source := range finder.registries {
		waitGroup.Go(func() {
			ranges, numbers, err := finder.registryRanges(ctx, source, domain, names)
			// The ranges come back alongside the failure rather than instead of it, one route into a
			// registry being able to fail while the other answers.
			if err != nil {
				report(err, string(source.method))
			}

			for _, item := range ranges {
				add(item.Network, item, item.Inferences...)
			}

			gathered(nil, numbers)
		})
	}

	waitGroup.Wait()

	// Last, the other axis: what the party's own networks authorise and announce. It runs at the end
	// because a network is something the rounds before it found, and every one of them came off a
	// contact or an organisation already checked against the domain -- so the prefixes rest on the
	// same evidence the allocations do, and no further check is owed.
	slices.Sort(autNums)

	ranges, err := finder.networkRanges(ctx, slices.Compact(autNums))
	if err != nil {
		report(err, "routing")
	}

	for _, item := range ranges {
		add(item.Network, item, item.Inferences...)
	}

	return Collapse(slices.Collect(maps.Values(byNetwork))), nil
}

// ripeRanges asks the registry what the domain's contacts administer.
func (finder *Finder) ripeRanges(ctx context.Context, domain string) ([]*Range, []string, error) {
	registrants, err := finder.ripe.Registrants(ctx, domain, finder.config.FetchOptions...)
	if err != nil {
		return nil, nil, fmt.Errorf("registrants: %w", err)
	}

	if registrants == nil {
		return []*Range{}, nil, nil
	}

	found := make([]*Range, 0)
	numbers := make([]string, 0)

	// The contacts a range names, and the organisations it belongs to. Both, because they are
	// different claims: a contact is who to write to about the space, an organisation is whose it
	// is, and a range carries them independently.
	walks := []struct {
		handles []string
		ranges  func(context.Context, string, ...fetch_config.Option) ([]*ripe.Range, error)
	}{
		{handles: nicHandles(registrants.Persons), ranges: finder.ripe.Ranges},
		{handles: organizationHandles(registrants.Organizations), ranges: finder.ripe.OrganizationRanges},
	}

	for _, walk := range walks {
		for _, handle := range walk.handles {
			// The networks registered to the same handle. They lead to prefixes the allocations do
			// not cover, and asking costs one request on a handle already being asked about.
			autNums, err := finder.ripe.AutNums(ctx, handle, finder.config.FetchOptions...)
			if err != nil {
				return nil, nil, altshiftErrors.New(fmt.Errorf("aut nums: %w", err), handle)
			}
			numbers = append(numbers, autNums...)

			// The reverse zones delegated to the same handle. A registry hands one only to the
			// holder of the space, and the delegation is arranged per block rather than per
			// allocation -- so this finds blocks the allocations do not name.
			zones, err := finder.ripe.ReverseZones(ctx, handle, finder.config.FetchOptions...)
			if err != nil {
				return nil, nil, altshiftErrors.New(fmt.Errorf("reverse zones: %w", err), handle)
			}

			for _, network := range zones {
				found = append(
					found,
					&Range{
						Network: network,
						Inferences: []*inference.Inference{
							inference.New(reverse.Method, reverse.Confidence, handle, ripe.Domain),
						},
					},
				)
			}

			ranges, err := walk.ranges(ctx, handle, finder.config.FetchOptions...)
			if err != nil {
				return nil, nil, altshiftErrors.New(fmt.Errorf("ranges: %w", err), handle)
			}

			for _, item := range ranges {
				if item == nil {
					continue
				}

				for _, network := range item.Networks {
					found = append(
						found,
						&Range{
							Network: network,
							NetName: item.NetName,
							Status:  item.Status,
							Country: item.Country,
							Inferences: []*inference.Inference{
								inference.New(MethodRipe, RipeConfidence, handle, item.Inetnum),
							},
						},
					)
				}
			}
		}
	}

	return found, numbers, nil
}

func nicHandles(persons []*ripe.Person) []string {
	handles := make([]string, 0, len(persons))
	for _, person := range persons {
		if person != nil && person.NicHandle != "" {
			handles = append(handles, person.NicHandle)
		}
	}

	return handles
}

func organizationHandles(organizations []*ripe.Organization) []string {
	handles := make([]string, 0, len(organizations))
	for _, organization := range organizations {
		if organization != nil && organization.Handle != "" {
			handles = append(handles, organization.Handle)
		}
	}

	return handles
}

// arinRanges asks the other registry what the domain's contacts' organisations hold.
//
// The walk is the client's rather than this function's, because ARIN's is four steps and the third
// is a check: it offers no search from a contact to the space they administer, so an organisation
// is reached by name and then checked back against the contacts the domain search found.
//
// It also answers with the names of the organisations it attributed, which are the terms given to
// the registries that cannot search by domain at all. A name ARIN checked against the domain's own
// contacts is a far better term than a guess, and it is free here.
func (finder *Finder) arinRanges(
	ctx context.Context,
	domain string,
) ([]*Range, []string, []string, error) {
	ranges, err := finder.arin.Ranges(ctx, domain, finder.config.FetchOptions...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ranges: %w", err)
	}

	found := make([]*Range, 0, len(ranges))
	organizations := make([]string, 0)
	handles := make([]string, 0)

	for _, item := range ranges {
		if item == nil {
			continue
		}

		if item.Organization != nil && item.Organization.Name != "" {
			organizations = append(organizations, item.Organization.Name)
		}
		if item.Organization != nil && item.Organization.Handle != "" {
			handles = append(handles, item.Organization.Handle)
		}

		// The organisation the space was attributed through and the allocation as the registry
		// wrote it, which is what lets an operator check the reasoning: the organisation's contacts
		// are what the attribution rests on, and they are a request away.
		organization := ""
		if item.Organization != nil {
			organization = item.Organization.Handle
		}

		for _, network := range item.Networks {
			found = append(
				found,
				&Range{
					Network: network,
					NetName: item.NetName,
					Inferences: []*inference.Inference{
						inference.New(
							MethodArin,
							ArinConfidence,
							organization,
							item.StartAddress+" - "+item.EndAddress,
						),
					},
				},
			)
		}
	}

	// The networks registered to the organisations the ranges were attributed through. The
	// organisation is already checked against the domain's contacts, so its networks are the
	// party's on the same evidence its allocations are.
	slices.Sort(handles)
	numbers := make([]string, 0)

	for _, handle := range slices.Compact(handles) {
		autNums, err := finder.arin.OrganizationAutNums(ctx, handle, finder.config.FetchOptions...)
		if err != nil {
			return nil, nil, nil, altshiftErrors.New(fmt.Errorf("organization aut nums: %w", err), handle)
		}

		numbers = append(numbers, autNums...)
	}

	return found, organizations, numbers, nil
}

// registryRanges asks a database that offers no search from a domain, both ways it can be asked.
//
// The two routes are independent and neither is a superset of the other, so both run and a failure
// of one does not cost the other: the abuse mailbox finds a party whose registered abuse contact is
// at its own domain, the name finds one whose contact card is, and plenty of parties are only one
// of those.
func (finder *Finder) registryRanges(
	ctx context.Context,
	source *registry,
	domain string,
	names []string,
) ([]*Range, []string, error) {
	if source == nil {
		return nil, nil, altshiftErrors.NewWithTrace(nil_error.New("registry"))
	}

	found := make([]*Range, 0)
	numbers := make([]string, 0)
	problems := make([]error, 0, 2)

	if source.whois != nil {
		ranges, err := source.whois.Ranges(ctx, domain)
		if err != nil {
			problems = append(problems, fmt.Errorf("whois ranges: %w", err))
		}

		// The networks registered to the same contacts the ranges were reached through.
		contacts := make([]string, 0, len(ranges))
		for _, item := range ranges {
			if item != nil && item.Contact != "" {
				contacts = append(contacts, item.Contact)
			}
		}
		slices.Sort(contacts)

		for _, contact := range slices.Compact(contacts) {
			autNums, err := source.whois.AutNums(ctx, contact)
			if err != nil {
				problems = append(problems, altshiftErrors.New(fmt.Errorf("aut nums: %w", err), contact))
			} else {
				numbers = append(numbers, autNums...)
			}

			zones, err := source.whois.ReverseZones(ctx, contact)
			if err != nil {
				problems = append(problems, altshiftErrors.New(fmt.Errorf("reverse zones: %w", err), contact))

				continue
			}

			for _, network := range zones {
				found = append(
					found,
					&Range{
						Network: network,
						Inferences: []*inference.Inference{
							inference.New(reverse.Method, reverse.Confidence, contact, source.whois.Host()),
						},
					},
				)
			}
		}

		for _, item := range ranges {
			if item == nil {
				continue
			}

			for _, network := range item.Networks {
				found = append(
					found,
					&Range{
						Network: network,
						NetName: item.NetName,
						Status:  item.Status,
						Country: item.Country,
						Inferences: []*inference.Inference{
							inference.New(
								source.method,
								inference.ConfidenceStrong,
								ViaAbuseMailbox,
								item.Contact,
								item.Inetnum,
							),
						},
					},
				)
			}
		}
	}

	if source.rdap != nil {
		ranges, err := source.rdap.Ranges(ctx, domain, names, finder.config.FetchOptions...)
		if err != nil {
			problems = append(problems, fmt.Errorf("rdap ranges: %w", err))
		}

		for _, item := range ranges {
			if item == nil {
				continue
			}

			handle := ""
			if item.Entity != nil {
				handle = item.Entity.Handle
				// The server answers with the party's networks alongside its allocations, so these
				// cost nothing at all.
				numbers = append(numbers, item.Entity.AutNums...)
			}

			for _, network := range item.Networks {
				found = append(
					found,
					&Range{
						Network: network,
						NetName: item.NetName,
						Country: item.Country,
						Inferences: []*inference.Inference{
							inference.New(source.method, inference.ConfidenceStrong, ViaName, handle),
						},
					},
				)
			}
		}
	}

	// What one route found is kept whatever the other did, so the ranges come back alongside the
	// failure rather than instead of it.
	if len(problems) != 0 {
		return found, numbers, errors.Join(problems...)
	}

	return found, numbers, nil
}

// networkRanges asks what a party's own networks authorise and announce.
//
// It is the second axis, and the reason for it is that an allocation and a prefix are different
// things: an allocation is what a party was given, a prefix is what its network routes, and a party
// routing space under someone else's allocation holds no record of it anywhere a registry search
// would look. The routing data is also global, so this is what reaches the region no registry
// search here does.
//
// The three answers are kept apart because they are worth different things. A signed authorisation
// and a route object are statements about whose the addresses are; an announcement is an
// observation of what is being routed, which a transit provider's network makes about its
// customers' space as readily as about its own.
func (finder *Finder) networkRanges(ctx context.Context, numbers []string) ([]*Range, error) {
	found := make([]*Range, 0)
	problems := make([]error, 0)

	add := func(network string, method inference.Method, confidence inference.Confidence, via ...string) {
		found = append(
			found,
			&Range{
				Network:    network,
				Inferences: []*inference.Inference{inference.New(method, confidence, via...)},
			},
		)
	}

	for index, number := range numbers {
		if index >= finder.maxAutNums() {
			break
		}

		if finder.ripestat != nil {
			roas, err := finder.ripestat.Roas(ctx, number, finder.config.FetchOptions...)
			if err != nil {
				problems = append(problems, altshiftErrors.New(fmt.Errorf("roas: %w", err), number))
			}

			for _, item := range roas {
				if item != nil && item.Prefix != "" {
					add(item.Prefix, MethodRpki, RpkiConfidence, number, item.TrustAnchor)
				}
			}

			announced, err := finder.ripestat.AnnouncedPrefixes(ctx, number, finder.config.FetchOptions...)
			if err != nil {
				problems = append(
					problems,
					altshiftErrors.New(fmt.Errorf("announced prefixes: %w", err), number),
				)
			}

			for _, prefix := range announced {
				add(prefix, MethodBgp, BgpConfidence, number)
			}
		}

		// The route objects live in the registries' own databases, so every database is asked: a
		// party's prefix is declared in whichever of them holds the address space, which is not
		// necessarily the one its network is registered in.
		for _, source := range finder.registries {
			if source == nil || source.whois == nil {
				continue
			}

			prefixes, err := source.whois.RoutePrefixes(ctx, number)
			if err != nil {
				problems = append(
					problems,
					altshiftErrors.New(fmt.Errorf("route prefixes: %w", err), number, source.whois.Host()),
				)

				continue
			}

			for _, prefix := range prefixes {
				add(prefix, MethodRouteObject, RouteObjectConfidence, number, source.whois.Host())
			}
		}

		if finder.ripe != nil {
			prefixes, err := finder.ripe.RoutePrefixes(ctx, number, finder.config.FetchOptions...)
			if err != nil {
				problems = append(
					problems,
					altshiftErrors.New(fmt.Errorf("route prefixes: %w", err), number),
				)

				continue
			}

			for _, prefix := range prefixes {
				add(prefix, MethodRouteObject, RouteObjectConfidence, number, ripe.Domain)
			}
		}
	}

	// What one answer found is kept whatever the others did.
	if len(problems) != 0 {
		return found, errors.Join(problems...)
	}

	return found, nil
}

// Collapse drops ranges wholly contained in another, keeping the inferences of both on the one that
// survives.
//
// A registry answer routinely holds a /16 and several /24s inside it, and reporting all of them
// would make one allocation look like a dozen. The containing range is the one kept, because it is
// the true extent of what the party holds -- but the narrower range's reasoning is worth keeping,
// since it may have come from a source the wider one did not.
func Collapse(ranges []*Range) []*Range {
	parsed := make([]*net.IPNet, len(ranges))
	for index, item := range ranges {
		if item == nil {
			continue
		}
		_, network, err := net.ParseCIDR(item.Network)
		if err == nil {
			parsed[index] = network
		}
	}

	kept := make([]*Range, 0, len(ranges))

	for index, item := range ranges {
		if item == nil || parsed[index] == nil {
			continue
		}

		contained := false

		for otherIndex, other := range parsed {
			if otherIndex == index || other == nil {
				continue
			}

			if !contains(other, parsed[index]) {
				continue
			}

			// Identical ranges contain each other, so the earlier one is kept and the later folded
			// into it. Without that tie-break both would be dropped.
			if contains(parsed[index], other) && otherIndex > index {
				continue
			}

			contained = true
			ranges[otherIndex].Inferences = inference.Merge(
				append(ranges[otherIndex].Inferences, item.Inferences...),
			)

			// A range held inside one only used is still held: the containing range is the extent of
			// what the party was given, and the narrower claim cannot weaken it.
			if item.Tenure == TenureHeld || ranges[otherIndex].Tenure == TenureUnknown {
				ranges[otherIndex].Tenure = item.Tenure
			}

			break
		}

		if !contained {
			kept = append(kept, item)
		}
	}

	// Sorted, so the answer does not depend on map iteration.
	slices.SortFunc(kept, func(a *Range, b *Range) int {
		return strings.Compare(a.Network, b.Network)
	})

	return kept
}

// contains reports whether outer wholly contains inner.
func contains(outer *net.IPNet, inner *net.IPNet) bool {
	if outer == nil || inner == nil {
		return false
	}

	if !outer.Contains(inner.IP) {
		return false
	}

	outerOnes, outerBits := outer.Mask.Size()
	innerOnes, innerBits := inner.Mask.Size()
	if outerBits != innerBits {
		return false
	}

	// A shorter prefix is a larger range, so the outer range contains the inner one only if its
	// prefix is no longer.
	return outerOnes <= innerOnes
}
