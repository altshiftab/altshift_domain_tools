// Package finder finds the address space a domain's owner holds.
//
// Two sources answer, and they find different things. The registry knows what a party was allocated,
// including space it is not using; a mail policy declares what it sends from, including space it
// uses under someone else's allocation. Neither is a superset of the other, so both run and the
// answers are merged.
//
// A range found by both carries both inferences, which is what lets a consumer tell a range two
// independent sources agree on from one a single weak signal produced.
package finder

import (
	"context"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/altshiftab/altshift_domain_tools/pkg/inference"
	"github.com/altshiftab/altshift_domain_tools/pkg/network_range/finder/finder_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/network_range/spf"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripe"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"log/slog"
)

// Method is how the registry attributes a range, and Confidence what that is worth: a registry
// record is a party stating what it holds.
const (
	MethodRipe     inference.Method = "ripe registry"
	RipeConfidence                  = inference.ConfidenceStrong
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

// Finder holds the sources a run uses.
type Finder struct {
	ripe   *ripe.Client
	config *finder_config.Config
}

// NewFinder builds a finder. A source the caller did not provide is built with its own defaults, so
// the zero-option call is the ordinary one.
func NewFinder(options ...finder_config.Option) *Finder {
	config := finder_config.New(options...)

	ripeClient := config.Ripe
	if ripeClient == nil {
		ripeClient = ripe.NewClient()
	}

	return &Finder{ripe: ripeClient, config: config}
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
// one being down should not cost the answers of the other. A run where both fail returns nothing
// rather than an error, which is the same answer as a party that holds no address space -- so a
// consumer that needs to tell those apart should read the log.
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

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()

		ranges, err := finder.ripeRanges(ctx, domain)
		if err != nil {
			slog.ErrorContext(
				altshiftContext.WithError(ctx, altshiftErrors.New(fmt.Errorf("ripe ranges: %w", err), domain)),
				"An error occurred when querying the registry.",
			)

			return
		}

		for _, item := range ranges {
			add(item.Network, item, item.Inferences...)
		}
	}()

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()

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
	}()

	waitGroup.Wait()

	return Collapse(slices.Collect(maps.Values(byNetwork))), nil
}

// ripeRanges asks the registry what the domain's contacts administer.
func (finder *Finder) ripeRanges(ctx context.Context, domain string) ([]*Range, error) {
	persons, err := finder.ripe.Persons(ctx, domain, finder.config.FetchOptions...)
	if err != nil {
		return nil, fmt.Errorf("persons: %w", err)
	}

	found := make([]*Range, 0)

	for _, person := range persons {
		if person == nil || person.NicHandle == "" {
			continue
		}

		ranges, err := finder.ripe.Ranges(ctx, person.NicHandle, finder.config.FetchOptions...)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("ranges: %w", err), person.NicHandle)
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
							inference.New(MethodRipe, RipeConfidence, person.NicHandle, item.Inetnum),
						},
					},
				)
			}
		}
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
