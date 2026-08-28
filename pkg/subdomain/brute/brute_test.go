package brute_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/resolver"
	"github.com/altshiftab/altshift_domain_tools/pkg/subdomain/brute"
)

// stubResolver answers from a set of names that exist, and can be made to fail.
type stubResolver struct {
	exists map[string]bool
	// err is returned for any name matching errFor.
	err    error
	errFor string

	mutex sync.Mutex
	asked []string
}

func (stub *stubResolver) DomainExists(_ context.Context, domain string) (bool, error) {
	stub.mutex.Lock()
	stub.asked = append(stub.asked, domain)
	stub.mutex.Unlock()

	if stub.err != nil && (stub.errFor == "" || strings.HasPrefix(domain, stub.errFor)) {
		return false, stub.err
	}

	return stub.exists[domain], nil
}

func (stub *stubResolver) askedNames() []string {
	stub.mutex.Lock()
	defer stub.mutex.Unlock()

	return slices.Clone(stub.asked)
}

var errLookup = errors.New("the lookup failed")

func TestCanBrute(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		resolver resolver.Resolver
		expect   bool
	}{
		{
			name:     "a domain that does not answer to a name nobody registered can be brute forced",
			resolver: &stubResolver{exists: map[string]bool{}},
			expect:   true,
		},
		{
			// A wildcard answers for anything, including the probe, so every name in the list would
			// come back as a hit and none would mean anything.
			name:     "a domain with a wildcard record cannot",
			resolver: &wildcardResolver{},
			expect:   false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := brute.CanBrute(t.Context(), "example.com", testCase.resolver)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}
			if got != testCase.expect {
				t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expect, got)
			}
		})
	}
}

// wildcardResolver answers yes to everything, which is what a wildcard record does.
type wildcardResolver struct{}

func (*wildcardResolver) DomainExists(context.Context, string) (bool, error) {
	return true, nil
}

func TestLookup(t *testing.T) {
	t.Parallel()

	stub := &stubResolver{
		exists: map[string]bool{
			"www.example.com":  true,
			"mail.example.com": true,
		},
	}

	found, err := brute.Lookup(
		t.Context(),
		"example.com",
		slices.Values([]string{"www", "mail", "nothing", "", "  "}),
		stub,
		4,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	slices.Sort(found)
	if !slices.Equal(found, []string{"mail.example.com", "www.example.com"}) {
		t.Errorf("expected the two names that resolve, got %v", found)
	}

	// The list carries leading labels; the domain is appended here.
	for _, asked := range stub.askedNames() {
		if !strings.HasSuffix(asked, ".example.com") {
			t.Errorf("expected every lookup to be under the domain, got %q", asked)
		}
	}
	// Blank entries are not asked about.
	if len(stub.askedNames()) != 3 {
		t.Errorf("expected 3 lookups, got %d: %v", len(stub.askedNames()), stub.askedNames())
	}
}

// TestLookupSurvivesAFailure holds that one name failing does not lose the whole answer: a brute
// force of thousands will have some fail, and an all-or-nothing run would be useless.
func TestLookupSurvivesAFailure(t *testing.T) {
	t.Parallel()

	stub := &stubResolver{
		exists: map[string]bool{"www.example.com": true},
		err:    errLookup,
		errFor: "broken",
	}

	found, err := brute.Lookup(
		t.Context(),
		"example.com",
		slices.Values([]string{"www", "broken"}),
		stub,
		2,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(found, []string{"www.example.com"}) {
		t.Errorf("expected the name that resolved to survive the one that failed, got %v", found)
	}
}

// TestLookupStopsWhenRefused holds the other half: a resolver that refuses will refuse the rest, so
// the run stops rather than working through the list being told no.
func TestLookupStopsWhenRefused(t *testing.T) {
	t.Parallel()

	names := make([]string, 500)
	for index := range names {
		names[index] = "name" + strings.Repeat("x", index%5) + string(rune('a'+index%26))
	}

	stub := &stubResolver{err: &resolver.RefusedError{Domain: "example.com", Rcode: 5}}

	found, err := brute.Lookup(t.Context(), "example.com", slices.Values(names), stub, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("expected nothing found, got %d", len(found))
	}

	// It must give up well short of the whole list.
	if asked := len(stub.askedNames()); asked >= len(names) {
		t.Errorf("expected the run to stop early, it asked about %d of %d names", asked, len(names))
	}
}

func TestLookupArgumentChecks(t *testing.T) {
	t.Parallel()

	stub := &stubResolver{exists: map[string]bool{}}

	if _, err := brute.Lookup(t.Context(), "", slices.Values([]string{"www"}), stub, 1); err == nil {
		t.Error("expected an empty domain to be an error")
	}
	if _, err := brute.Lookup(t.Context(), "example.com", nil, stub, 1); err == nil {
		t.Error("expected a nil sequence to be an error")
	}
	if _, err := brute.Lookup(t.Context(), "example.com", slices.Values([]string{"www"}), nil, 1); err == nil {
		t.Error("expected a nil resolver to be an error")
	}
	if _, err := brute.Lookup(t.Context(), "example.com", slices.Values([]string{"www"}), stub, -1); err == nil {
		t.Error("expected a negative concurrency to be an error")
	}

	// Zero means the default rather than running nothing.
	if _, err := brute.Lookup(t.Context(), "example.com", slices.Values([]string{"www"}), stub, 0); err != nil {
		t.Errorf("expected zero concurrency to mean the default, got %v", err)
	}
}
