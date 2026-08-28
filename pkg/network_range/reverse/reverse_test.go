package reverse

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/inference"
)

// stubResolver is a zone that answers and a name that resolves, and nothing else: a name it was not
// given is a name that is not a delegation point, which is what the walk is looking for.
type stubResolver struct {
	nameServers map[string][]string
	addresses   map[string][]string

	asked []string
	lock  sync.Mutex
}

func (stub *stubResolver) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	stub.lock.Lock()
	defer stub.lock.Unlock()

	stub.asked = append(stub.asked, name)

	hosts, ok := stub.nameServers[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}

	found := make([]*net.NS, 0, len(hosts))
	for _, host := range hosts {
		found = append(found, &net.NS{Host: host})
	}

	return found, nil
}

func (stub *stubResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	stub.lock.Lock()
	defer stub.lock.Unlock()

	addresses, ok := stub.addresses[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	found := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		found = append(found, netip.MustParseAddr(address))
	}

	return found, nil
}

func (stub *stubResolver) queries() []string {
	stub.lock.Lock()
	defer stub.lock.Unlock()

	return slices.Clone(stub.asked)
}

func networksOf(ranges []*Range) []string {
	found := make([]string, 0, len(ranges))
	for _, item := range ranges {
		found = append(found, item.Network)
	}

	return found
}

// TestNetworks holds the walk. A delegation sits at whatever boundary the holder took and nothing in
// an address says which, so the most specific zone is asked for first and the walk climbs until one
// answers.
func TestNetworks(t *testing.T) {
	t.Parallel()

	resolver := &stubResolver{
		// Delegated at a /16, so the /24 and the /32 below it answer with nothing.
		nameServers: map[string][]string{
			"0.198.in-addr.arpa": {"ns1.example.com.", "ns2.example.com."},
		},
	}

	ranges, err := Networks(
		t.Context(),
		"example.com",
		[]netip.Addr{netip.MustParseAddr("198.0.2.5")},
		resolver,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"198.0.0.0/16"}) {
		t.Fatalf("expected the delegated block, got %v", networksOf(ranges))
	}

	// The zone and what answered for it, which is what lets an operator check the reasoning.
	via := ranges[0].Inferences[0].Via
	if len(via) == 0 || via[0] != "0.198.in-addr.arpa" {
		t.Errorf("expected the zone named, got %v", via)
	}
	if !slices.Contains(via, "ns1.example.com") {
		t.Errorf("expected the nameservers named, got %v", via)
	}

	// It climbed rather than guessing: the /32 and the /24 were asked for first.
	asked := resolver.queries()
	if !slices.Equal(asked, []string{"5.2.0.198.in-addr.arpa", "2.0.198.in-addr.arpa", "0.198.in-addr.arpa"}) {
		t.Errorf("expected the walk to climb, got %v", asked)
	}
}

// TestNetworksStopsAtTheFirstDelegation holds why the walk stops rather than climbing past a zone
// that answered. The zone above a party's is delegated to whoever its provider is, and that is not
// evidence about this party.
func TestNetworksStopsAtTheFirstDelegation(t *testing.T) {
	t.Parallel()

	resolver := &stubResolver{
		nameServers: map[string][]string{
			// The /24 is a stranger's, and the /8 above it happens to be the domain's.
			"2.0.192.in-addr.arpa": {"ns1.someone-else.test."},
			"192.in-addr.arpa":     {"ns1.example.com."},
		},
	}

	ranges, err := Networks(
		t.Context(),
		"example.com",
		[]netip.Addr{netip.MustParseAddr("192.0.2.5")},
		resolver,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ranges) != 0 {
		t.Errorf("expected the walk to stop at the stranger's delegation, got %v", networksOf(ranges))
	}
	if slices.Contains(resolver.queries(), "192.in-addr.arpa") {
		t.Errorf("expected nothing asked past the delegation, got %v", resolver.queries())
	}
}

// TestDelegatedTo holds the check. A zone served by the party's nameservers and a stranger's is a
// zone the party shares, and a single name inside the domain would otherwise attribute a block on
// the strength of a secondary somebody agreed to run.
func TestDelegatedTo(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		nameServers []string
		expect      bool
	}{
		{name: "all within the domain", nameServers: []string{"ns1.example.com.", "ns2.example.com."}, expect: true},
		{name: "a subdomain of it", nameServers: []string{"ns1.dns.example.com."}, expect: true},
		{name: "one of them a stranger's", nameServers: []string{"ns1.example.com.", "ns1.elsewhere.test."}, expect: false},
		{name: "all strangers", nameServers: []string{"ns1.elsewhere.test."}, expect: false},
		// A name that merely ends the same way belongs to somebody else entirely.
		{name: "a domain ending the same way", nameServers: []string{"ns1.notexample.com."}, expect: false},
		{name: "none at all", nameServers: nil, expect: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			found := make([]*net.NS, 0, len(testCase.nameServers))
			for _, host := range testCase.nameServers {
				found = append(found, &net.NS{Host: host})
			}

			if got := delegatedTo(found, "example.com"); got != testCase.expect {
				t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expect, got)
			}
		})
	}
}

// TestNetworksResolvesTheDomainWhereGivenNoAddresses holds where a walk starts when a caller brings
// nothing: a party's website almost always sits in space it holds.
func TestNetworksResolvesTheDomainWhereGivenNoAddresses(t *testing.T) {
	t.Parallel()

	resolver := &stubResolver{
		addresses: map[string][]string{
			// A private address is a resolver answering about something else entirely, and is not
			// followed.
			"example.com": {"203.0.113.9", "10.0.0.1"},
		},
		nameServers: map[string][]string{
			"113.0.203.in-addr.arpa": {"ns1.example.com."},
		},
	}

	ranges, err := Networks(t.Context(), "example.com", nil, resolver)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"203.0.113.0/24"}) {
		t.Errorf("expected the block behind the domain, got %v", networksOf(ranges))
	}
	if slices.ContainsFunc(resolver.queries(), func(name string) bool {
		return name == "1.0.0.10.in-addr.arpa"
	}) {
		t.Errorf("expected the private address left alone, got %v", resolver.queries())
	}
}

// TestNetworksIsWorthWhatARegistryRecordIs holds the grading. A registry hands a reverse zone to the
// holder of the space and to nobody else.
func TestNetworksConfidence(t *testing.T) {
	t.Parallel()

	resolver := &stubResolver{
		nameServers: map[string][]string{"113.0.203.in-addr.arpa": {"ns1.example.com."}},
	}

	ranges, err := Networks(
		t.Context(),
		"example.com",
		[]netip.Addr{netip.MustParseAddr("203.0.113.9")},
		resolver,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ranges) != 1 {
		t.Fatalf("expected one range, got %d", len(ranges))
	}

	if got := inference.Combined(ranges[0].Inferences); got != Confidence {
		t.Errorf("expected the delegation to be worth a registry record, got %d", got)
	}
}

func TestArgumentChecks(t *testing.T) {
	t.Parallel()

	if _, err := Networks(t.Context(), "", nil, &stubResolver{}); err == nil {
		t.Error("expected an empty domain to be an error")
	}
	if _, err := Networks(t.Context(), "example.com", nil, nil); err == nil {
		t.Error("expected a nil resolver to be an error")
	}
}
