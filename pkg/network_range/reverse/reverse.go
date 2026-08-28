// Package reverse reads the address space a domain's reverse DNS is delegated to it.
//
// A registry hands a reverse zone to the holder of the address space and to nobody else: getting
// 8.8.8.in-addr.arpa answered by ns1.google.com is something only the party that was allocated
// 8.8.8.0/24 can arrange. So a delegation pointing into a domain is close to a statement of holding,
// and it is one made in the DNS rather than in a registry -- which is what makes it worth asking
// even where the registry has already answered, and the only thing that answers where no registry
// search reaches.
//
// It is not the same as a PTR. A reverse record says what an address is called, which the operator
// of the address decides: an address of a customer's inside a provider's block is named by the
// provider, so a PTR reveals who runs the machine rather than who holds the block. The delegation
// is a level above that and says who the block was handed to.
//
// The awkward part is that a delegation sits at whatever boundary the holder took. Google's is a
// /24, SUNET's is a /16, and nothing in an address says which -- so finding it means asking for the
// most specific zone first and walking up until one answers.
package reverse

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/altshiftab/altshift_domain_tools/pkg/cidr"
	"github.com/altshiftab/altshift_domain_tools/pkg/inference"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/net/types/domain_parts"
)

// Method is how this package attributes a range, and Confidence what that is worth: a registry hands
// a reverse zone to the holder of the space and to nobody else, so a delegation into the domain is
// the registry and the party agreeing about who holds it.
const (
	Method     inference.Method = "reverse delegation"
	Confidence                  = inference.ConfidenceStrong
)

// DefaultMaxAddresses bounds how many addresses a walk starts from.
const DefaultMaxAddresses = 16

// Resolver is the DNS this package asks. *net.Resolver satisfies it.
type Resolver interface {
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error)
}

// Range is one delegated block and why it is attributed.
type Range struct {
	Network    string                 `json:"network"`
	Inferences []*inference.Inference `json:"inferences,omitzero"`
}

// Networks returns the blocks whose reverse DNS is delegated into the domain.
//
// The addresses are where the walk starts, and a caller with none of its own gets the domain's own:
// a party's website and mail almost always sit in space it holds, and where they do not the walk
// finds nothing rather than something wrong.
func Networks(
	ctx context.Context,
	domain string,
	addresses []netip.Addr,
	resolver Resolver,
) ([]*Range, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if domain == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	if resolver == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("resolver"))
	}

	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))

	registered := domain
	if parts := domain_parts.New(domain); parts != nil && parts.RegisteredDomain != "" {
		registered = parts.RegisteredDomain
	}

	if len(addresses) == 0 {
		addresses = hostAddresses(ctx, domain, resolver)
	}

	byNetwork := make(map[string][]*inference.Inference)
	asked := make(map[string]struct{})

	for index, address := range addresses {
		if index >= DefaultMaxAddresses {
			break
		}

		for _, zone := range cidr.ReverseZones(address) {
			// The same zone is reached from every address inside it, which for a walk starting from
			// several addresses of one party is most of them.
			if _, ok := asked[zone]; ok {
				break
			}
			asked[zone] = struct{}{}

			nameServers, err := resolver.LookupNS(ctx, zone)
			if err != nil || len(nameServers) == 0 {
				// Not a delegation point, or a name that does not resolve. The zone above it might
				// still be one, so the walk carries on rather than stopping here.
				continue
			}

			// The delegation was found. Whether it is the domain's is the next question, but the
			// walk stops either way: a zone above this one is delegated to whoever this party's
			// provider is, and that is not evidence about this party.
			if !delegatedTo(nameServers, registered) {
				break
			}

			network, err := cidr.FromReverseZone(zone)
			if err != nil {
				break
			}

			byNetwork[network] = append(
				byNetwork[network],
				inference.New(
					Method,
					Confidence,
					slices.Concat([]string{zone}, nameServerNames(nameServers))...,
				),
			)

			break
		}
	}

	ranges := make([]*Range, 0, len(byNetwork))
	for network, inferences := range byNetwork {
		ranges = append(ranges, &Range{Network: network, Inferences: inference.Merge(inferences)})
	}

	slices.SortFunc(ranges, func(a *Range, b *Range) int {
		return strings.Compare(a.Network, b.Network)
	})

	return ranges, nil
}

// hostAddresses is where the domain itself resolves, which is where a walk starts when a caller
// brings nothing of its own.
func hostAddresses(ctx context.Context, domain string, resolver Resolver) []netip.Addr {
	found, err := resolver.LookupNetIP(ctx, "ip", domain)
	if err != nil {
		return nil
	}

	addresses := make([]netip.Addr, 0, len(found))
	for _, address := range found {
		address = address.Unmap().WithZone("")
		// A party's own space is public space. A loopback or a private address is a resolver
		// answering about something else entirely.
		if address.IsValid() && address.IsGlobalUnicast() && !address.IsPrivate() {
			addresses = append(addresses, address)
		}
	}

	return addresses
}

// delegatedTo reports whether the zone was handed to nameservers within the domain.
//
// Every one of them rather than any: a zone served by the party's nameservers and a stranger's is a
// zone the party shares, and a single name inside the domain would otherwise attribute a block on
// the strength of a secondary somebody agreed to run.
func delegatedTo(nameServers []*net.NS, domain string) bool {
	inDomain := 0

	for _, nameServer := range nameServers {
		if nameServer == nil {
			continue
		}

		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(nameServer.Host), "."))
		if host == "" {
			continue
		}

		parts := domain_parts.New(host)
		if parts == nil || parts.RegisteredDomain != domain {
			return false
		}

		inDomain++
	}

	return inDomain != 0
}

// nameServerNames is what answered, which is what lets an operator check the reasoning.
func nameServerNames(nameServers []*net.NS) []string {
	names := make([]string, 0, len(nameServers))
	for _, nameServer := range nameServers {
		if nameServer != nil && nameServer.Host != "" {
			names = append(names, strings.TrimSuffix(nameServer.Host, "."))
		}
	}

	slices.Sort(names)

	return slices.Compact(names)
}
