package spf

import (
	"context"
	"net"
	"slices"
	"sync"
	"testing"
)

// stubResolver answers with the TXT records filed under each name.
type stubResolver struct {
	records map[string][]string

	lock   sync.Mutex
	looked []string
}

func (stub *stubResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	stub.lock.Lock()
	stub.looked = append(stub.looked, name)
	stub.lock.Unlock()

	records, ok := stub.records[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}

	return records, nil
}

func (stub *stubResolver) lookedAt(name string) bool {
	stub.lock.Lock()
	defer stub.lock.Unlock()

	return slices.Contains(stub.looked, name)
}

func networksOf(ranges []*Range) []string {
	found := make([]string, 0, len(ranges))
	for _, item := range ranges {
		found = append(found, item.Network)
	}
	slices.Sort(found)

	return found
}

func TestNetworks(t *testing.T) {
	t.Parallel()

	stub := &stubResolver{
		records: map[string][]string{
			"example.com": {
				// Not policy: a domain's TXT records hold verification tokens and much else.
				"google-site-verification=abc",
				"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all",
			},
		},
	}

	ranges, err := Networks(t.Context(), "example.com", stub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"192.0.2.0/24", "2001:db8::/32"}) {
		t.Errorf("expected both declared networks, got %v", networksOf(ranges))
	}

	for _, item := range ranges {
		if len(item.Inferences) != 1 || item.Inferences[0].Method != Method {
			t.Errorf("expected the range to carry its reason, got %+v", item.Inferences)
		}
		// The step is the domain whose record declared it, which is what lets an operator check
		// the reasoning rather than take it on faith.
		if len(item.Inferences[0].Via) == 0 || item.Inferences[0].Via[0] != "example.com" {
			t.Errorf("expected the declaring domain to be recorded, got %+v", item.Inferences[0])
		}
	}
}

// TestNetworksFollowsItsOwnDelegations holds that the walk follows include: and redirect: within
// the same registration, which is how a party splits its policy across records it controls.
func TestNetworksFollowsItsOwnDelegations(t *testing.T) {
	t.Parallel()

	stub := &stubResolver{
		records: map[string][]string{
			"example.com":       {"v=spf1 ip4:192.0.2.0/24 include:_spf1.example.com redirect=_spf2.example.com -all"},
			"_spf1.example.com": {"v=spf1 ip4:198.51.100.0/24 -all"},
			"_spf2.example.com": {"v=spf1 ip4:203.0.113.0/24 -all"},
		},
	}

	ranges, err := Networks(t.Context(), "example.com", stub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}
	if !slices.Equal(networksOf(ranges), expected) {
		t.Errorf("expected the whole chain, got %v", networksOf(ranges))
	}
}

// TestNetworksDoesNotFollowSomeoneElsesPolicy holds the guard that matters most. A domain that
// includes its mail provider would otherwise contribute that provider's entire address space to
// the customer -- wrong, and enormous.
func TestNetworksDoesNotFollowSomeoneElsesPolicy(t *testing.T) {
	t.Parallel()

	stub := &stubResolver{
		records: map[string][]string{
			"example.com":     {"v=spf1 ip4:192.0.2.0/24 include:_spf.google.com ~all"},
			"_spf.google.com": {"v=spf1 ip4:8.8.0.0/16 ip4:35.190.0.0/17 ~all"},
		},
	}

	ranges, err := Networks(t.Context(), "example.com", stub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"192.0.2.0/24"}) {
		t.Errorf("expected the provider's space to be left alone, got %v", networksOf(ranges))
	}
	if stub.lookedAt("_spf.google.com") {
		t.Error("expected the provider's record not even to be read")
	}
}

// TestNetworksSkipsFailingDirectives holds that a directive saying an address may *not* send is the
// opposite of a claim on it, so it must not be attributed.
func TestNetworksSkipsFailingDirectives(t *testing.T) {
	t.Parallel()

	stub := &stubResolver{
		records: map[string][]string{
			"example.com": {"v=spf1 ip4:192.0.2.0/24 -ip4:198.51.100.0/24 -all"},
		},
	}

	ranges, err := Networks(t.Context(), "example.com", stub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"192.0.2.0/24"}) {
		t.Errorf("expected only the permitted range, got %v", networksOf(ranges))
	}
}

// TestNetworksStopsAtTheLookupLimit holds the bound RFC 7208 puts on evaluating a record at all. A
// chain longer than it is one no mail server would follow either.
func TestNetworksStopsAtTheLookupLimit(t *testing.T) {
	t.Parallel()

	records := map[string][]string{}
	// A chain far longer than the limit, each link declaring one range.
	for index := range 30 {
		name := "example.com"
		if index != 0 {
			name = spfName(index)
		}
		records[name] = []string{
			"v=spf1 ip4:192.0.2." + itoa(index) + "/32 include:" + spfName(index+1) + " -all",
		}
	}

	stub := &stubResolver{records: records}

	ranges, err := Networks(t.Context(), "example.com", stub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ranges) > MaxLookups {
		t.Errorf("expected the walk to stop at the limit, got %d ranges", len(ranges))
	}
}

func spfName(index int) string {
	return "_spf" + itoa(index) + ".example.com"
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}

	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}

	return digits
}

// TestNetworksWithoutARecord holds that most domains have no SPF record, and that is an answer
// rather than a failure.
func TestNetworksWithoutARecord(t *testing.T) {
	t.Parallel()

	ranges, err := Networks(t.Context(), "example.com", &stubResolver{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ranges) != 0 {
		t.Errorf("expected nothing, got %+v", ranges)
	}
}

func TestArgumentChecks(t *testing.T) {
	t.Parallel()

	if _, err := Networks(t.Context(), "", &stubResolver{}); err == nil {
		t.Error("expected an empty domain to be an error")
	}
	if _, err := Networks(t.Context(), "example.com", nil); err == nil {
		t.Error("expected a nil resolver to be an error")
	}
}
