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
	"github.com/altshiftab/altshift_domain_tools/pkg/network_range/spf"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/arin"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/rdap"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/rdap/rdap_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripe"
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

// The steps an inference names where a range came from one of the two routes into a registry that
// offers no search from a domain.
const (
	// ViaAbuseMailbox is the inverse search on the conventional abuse@<domain>.
	ViaAbuseMailbox = "abuse mailbox"
	// ViaName is the name search, checked against the address on the party's contact card.
	ViaName = "name"
)

// Range is one network attributed to the domain's owner.
type Range struct {
	// Network is the range in CIDR notation.
	Network string `json:"network"`
	// NetName and Status are what the registry called it, where the registry is what found it.
	NetName string `json:"net_name,omitzero"`
	Status  string `json:"status,omitzero"`
	Country string `json:"country,omitzero"`

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

// Finder holds the sources a run uses.
type Finder struct {
	ripe       *ripe.Client
	arin       *arin.Client
	registries []*registry
	config     *finder_config.Config
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

	return &Finder{
		ripe:       ripeClient,
		arin:       arinClient,
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
	var (
		organizations     []string
		organizationsLock sync.Mutex
	)

	waitGroup.Go(func() {
		ranges, err := finder.ripeRanges(ctx, domain)
		if err != nil {
			report(err, "ripe")

			return
		}

		for _, item := range ranges {
			add(item.Network, item, item.Inferences...)
		}
	})

	waitGroup.Go(func() {
		ranges, names, err := finder.arinRanges(ctx, domain)
		if err != nil {
			report(err, "arin")

			return
		}

		for _, item := range ranges {
			add(item.Network, item, item.Inferences...)
		}

		organizationsLock.Lock()
		defer organizationsLock.Unlock()

		organizations = append(organizations, names...)
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
			ranges, err := finder.registryRanges(ctx, source, domain, names)
			// The ranges come back alongside the failure rather than instead of it, one route into a
			// registry being able to fail while the other answers.
			if err != nil {
				report(err, string(source.method))
			}

			for _, item := range ranges {
				add(item.Network, item, item.Inferences...)
			}
		})
	}

	waitGroup.Wait()

	return Collapse(slices.Collect(maps.Values(byNetwork))), nil
}

// ripeRanges asks the registry what the domain's contacts administer.
func (finder *Finder) ripeRanges(ctx context.Context, domain string) ([]*Range, error) {
	registrants, err := finder.ripe.Registrants(ctx, domain, finder.config.FetchOptions...)
	if err != nil {
		return nil, fmt.Errorf("registrants: %w", err)
	}

	if registrants == nil {
		return []*Range{}, nil
	}

	found := make([]*Range, 0)

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
			ranges, err := walk.ranges(ctx, handle, finder.config.FetchOptions...)
			if err != nil {
				return nil, altshiftErrors.New(fmt.Errorf("ranges: %w", err), handle)
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

	return found, nil
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
func (finder *Finder) arinRanges(ctx context.Context, domain string) ([]*Range, []string, error) {
	ranges, err := finder.arin.Ranges(ctx, domain, finder.config.FetchOptions...)
	if err != nil {
		return nil, nil, fmt.Errorf("ranges: %w", err)
	}

	found := make([]*Range, 0, len(ranges))
	organizations := make([]string, 0)

	for _, item := range ranges {
		if item == nil {
			continue
		}

		if item.Organization != nil && item.Organization.Name != "" {
			organizations = append(organizations, item.Organization.Name)
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

	return found, organizations, nil
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
) ([]*Range, error) {
	if source == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("registry"))
	}

	found := make([]*Range, 0)
	problems := make([]error, 0, 2)

	if source.whois != nil {
		ranges, err := source.whois.Ranges(ctx, domain)
		if err != nil {
			problems = append(problems, fmt.Errorf("whois ranges: %w", err))
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
