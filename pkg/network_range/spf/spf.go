// Package spf reads the address space a domain's mail policy declares.
//
// An SPF record names the addresses allowed to send mail as the domain, which is a party stating in
// public which ranges it sends from. That is weaker evidence of ownership than a registry record --
// a range can be declared without being held -- but it is evidence the party published itself, and
// it finds space no registry search will, because a great deal of address space is used under
// someone else's allocation.
//
// The record can delegate through include: and redirect:, so this walks the chain. Two bounds keep
// that honest: the lookup limit RFC 7208 sets on evaluating a record at all, and a rule that only
// delegations within the same registered domain are followed. Without the second, a domain that
// includes its mail provider would contribute that provider's entire address space to the customer,
// which would be wrong and enormous.
package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/altshiftab/altshift_domain_tools/pkg/inference"
	altshiftSpf "github.com/altshiftab/utils_go/pkg/dns/spf"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/net/types/domain_parts"
)

// Method is how this package attributes a range, and Confidence what that is worth: the party said
// so itself, but said it about sending mail rather than about owning address space.
const (
	Method     inference.Method = "spf directive"
	Confidence                  = inference.ConfidenceModest
)

// MaxLookups is how many records a walk reads. It is the limit RFC 7208 puts on evaluating an SPF
// record, and a chain longer than it is one no mail server would follow either.
const MaxLookups = 10

// Resolver is the DNS lookup this package makes. *net.Resolver satisfies it.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Range is one declared network and why it is attributed.
type Range struct {
	Network    string                 `json:"network"`
	Inferences []*inference.Inference `json:"inferences,omitzero"`
}

// Networks returns the address space the domain's mail policy declares.
//
// A domain with no SPF record returns nothing rather than failing: most domains have none, and that
// is an answer.
func Networks(ctx context.Context, domain string, resolver Resolver) ([]*Range, error) {
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

	registered := ""
	if parts := domain_parts.New(domain); parts != nil {
		registered = parts.RegisteredDomain
	}

	byNetwork := make(map[string][]*inference.Inference)
	looked := make(map[string]struct{})
	queue := []string{domain}

	for len(queue) != 0 && len(looked) < MaxLookups {
		current := queue[0]
		queue = queue[1:]

		if current == "" {
			continue
		}
		if _, ok := looked[current]; ok {
			continue
		}
		looked[current] = struct{}{}

		records, err := lookup(ctx, current, resolver)
		if err != nil {
			// One name in the chain failing is not the walk failing: the rest of the chain still
			// declares what it declares.
			continue
		}

		for _, record := range records {
			// passOnly: a directive that is not a pass is the domain saying an address may not
			// send as it, which is the opposite of a claim on the address.
			for _, network := range altshiftSpf.ExtractNetworks(record, true) {
				if network == nil {
					continue
				}

				networkString := network.String()
				byNetwork[networkString] = append(
					byNetwork[networkString],
					inference.New(Method, Confidence, current),
				)
			}

			for _, delegate := range delegates(record) {
				if _, ok := looked[delegate]; ok {
					continue
				}

				// Only within the same registration. A domain that includes its mail provider must
				// not contribute the provider's address space to its owner.
				parts := domain_parts.New(delegate)
				if parts == nil || registered == "" || parts.RegisteredDomain != registered {
					continue
				}

				queue = append(queue, delegate)
			}
		}
	}

	ranges := make([]*Range, 0, len(byNetwork))
	for network, inferences := range byNetwork {
		ranges = append(ranges, &Range{Network: network, Inferences: inference.Merge(inferences)})
	}

	return ranges, nil
}

// lookup reads the domain's SPF records.
func lookup(ctx context.Context, domain string, resolver Resolver) ([]*altshiftSpf.Record, error) {
	texts, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) && dnsError.IsNotFound {
			return nil, nil
		}

		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("lookup txt: %w", err), domain)
	}

	records := make([]*altshiftSpf.Record, 0, 1)

	for _, text := range texts {
		// A domain's TXT records hold everything from verification tokens to DKIM keys; only the
		// ones announcing themselves as SPF are policy.
		if !strings.HasPrefix(strings.ToLower(text), strings.ToLower(altshiftSpf.Prefix)) {
			continue
		}

		record, err := altshiftSpf.ParseSpfRecord([]byte(text))
		if err != nil {
			// A record that does not parse is the domain's problem rather than the walk's.
			continue
		}
		if record == nil {
			continue
		}

		records = append(records, record)
	}

	return records, nil
}

// delegates returns the names the record hands evaluation on to.
func delegates(record *altshiftSpf.Record) []string {
	found := make([]string, 0)

	for _, value := range altshiftSpf.ExtractIncludeValues(record) {
		if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
			found = append(found, value)
		}
	}
	for _, value := range altshiftSpf.ExtractRedirectValues(record) {
		if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
			found = append(found, value)
		}
	}

	return found
}
