package related

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/inference"
	"github.com/altshiftab/altshift_domain_tools/pkg/related/related_config"
)

// errNoSuchHost stands in for a domain with no delegation, which is not a failure of the check but
// an answer it has nothing to say about.
var errNoSuchHost = errors.New("no such host")

// stubResolver answers from a table, so a test decides where each domain's DNS is served from.
type stubResolver map[string][]string

func (stub stubResolver) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	hosts, ok := stub[name]
	if !ok {
		return nil, errNoSuchHost
	}

	found := make([]*net.NS, 0, len(hosts))
	for _, host := range hosts {
		found = append(found, &net.NS{Host: host})
	}

	return found, nil
}

// found is a domain as a registration search hands it over, with the one inference that found it.
func attributed(name string) *Domain {
	return &Domain{
		Domain:     name,
		Inferences: []*inference.Inference{inference.New(MethodReverseWhoisOrganization, ReverseWhoisOrganizationConfidence, "kivra")},
	}
}

// methods is the distinct methods a domain carries, for asserting what the check added.
func methods(domain *Domain) []inference.Method {
	return inference.Methods(domain.Inferences)
}

// TestCorroborate holds the check that stands in for the one the registration search cannot make.
// The cases are Kivra's own answer, which is what the check was built against: a portfolio split
// between the party's own nameservers and its brand-protection registrar's, with strangers that
// merely contain the name sitting on their own.
func TestCorroborate(t *testing.T) {
	t.Parallel()

	// The party's own DNS is on a large provider, which is exactly why matching it proves nothing:
	// Cloud DNS hands out a few dozen fixed sets between millions of zones.
	kivraOwn := []string{
		"ns-cloud-e1.googledomains.com.",
		"ns-cloud-e2.googledomains.com.",
	}
	// The registrar's own nameservers, which no one else is on.
	zacco := []string{"dns1.zaccodigitaltrustlabs.com.", "ns1.zaccodns.com."}

	resolver := stubResolver{
		"kivra.com": kivraOwn,
		// Served from the same place as the searched domain -- but that place is everybody's.
		"kivra.se": kivraOwn,
		// The defensive registrations, clustered at the registrar rather than with the party.
		"kivra.at":  zacco,
		"kivra.dk":  zacco,
		"civra.me":  zacco,
		"ciwra.biz": zacco,
		// A stranger that merely contains the name, on its own nameservers.
		"kivralife.cl": {"ns-1531.awsdns-63.org."},
		// Another, on nameservers nobody else here is on.
		"kivracompany.com.br": {"ns1.brasil121-7429.com.br."},
		// kivra.ai is absent from the table: registered, never delegated.
	}

	domains := []*Domain{
		attributed("kivra.se"),
		attributed("kivra.at"),
		attributed("kivra.dk"),
		attributed("civra.me"),
		attributed("ciwra.biz"),
		attributed("kivralife.cl"),
		attributed("kivracompany.com.br"),
		attributed("kivra.ai"),
	}

	finder := NewFinder(related_config.WithNameServerResolver(resolver))

	corroborated, err := finder.Corroborate(t.Context(), "kivra.com", domains)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]bool{
		// The registrar cluster: four domains on one set no provider owns.
		"kivra.at":  true,
		"kivra.dk":  true,
		"civra.me":  true,
		"ciwra.biz": true,
		// Served from the searched domain's own nameservers -- but they are a large provider's, so
		// the match says nothing and is not counted.
		"kivra.se": false,
		// Strangers, each alone on its own nameservers.
		"kivralife.cl":        false,
		"kivracompany.com.br": false,
		// No delegation at all, which is not evidence of anything either way.
		"kivra.ai": false,
	}

	for _, domain := range corroborated {
		got := slices.Contains(methods(domain), MethodSharedNameServers)
		if want := expected[domain.Domain]; got != want {
			t.Errorf("expected %s corroborated=%t, got %t", domain.Domain, want, got)
		}

		// Nothing is removed and nothing loses what found it.
		if !slices.Contains(methods(domain), MethodReverseWhoisOrganization) {
			t.Errorf("expected %s to keep the search that found it", domain.Domain)
		}
	}

	if len(corroborated) != len(domains) {
		t.Errorf("expected the check to add and remove nothing, got %d of %d", len(corroborated), len(domains))
	}
}

// TestCorroborateRaisesWhatTwoThingsAgreeOn is the point of it being a method of its own. A domain a
// registration search found and the DNS independently agrees with is better attributed than one
// only the search found, and Combined is what expresses that.
func TestCorroborateRaisesWhatTwoThingsAgreeOn(t *testing.T) {
	t.Parallel()

	vanity := []string{"dns1.example-registrar.com.", "dns2.example-registrar.com."}

	resolver := stubResolver{
		"seed.example":  {"ns1.seed.example."},
		"one.example":   vanity,
		"two.example":   vanity,
		"three.example": vanity,
	}

	domains := []*Domain{attributed("one.example"), attributed("two.example"), attributed("three.example")}

	corroborated, err := NewFinder(related_config.WithNameServerResolver(resolver)).
		Corroborate(t.Context(), "seed.example", domains)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, domain := range corroborated {
		if got := domain.Confidence(); got != ReverseWhoisOrganizationConfidence+1 {
			t.Errorf(
				"expected %s to be raised to %d by the second method, got %d",
				domain.Domain, ReverseWhoisOrganizationConfidence+1, got,
			)
		}
	}
}

// TestNameServerSet holds what makes a set worth comparing at all.
func TestNameServerSet(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		hosts    []string
		expected string
	}{
		{
			name:     "sorted and lower-cased, so the order the resolver answers in does not matter",
			hosts:    []string{"NS2.Example.com.", "ns1.example.com."},
			expected: "ns1.example.com ns2.example.com",
		},
		{
			name:  "a large provider's set says nothing, however exactly it matches",
			hosts: []string{"ns-cloud-e1.googledomains.com.", "ns-cloud-e2.googledomains.com."},
		},
		{
			name:  "and one shared host in the set is enough to spoil it",
			hosts: []string{"ns1.example.com.", "ns-1531.awsdns-63.org."},
		},
		{
			name:  "a domain with no nameservers has nothing to compare",
			hosts: []string{},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			resolver := stubResolver{"example.test": testCase.hosts}

			if got := nameServerSet(t.Context(), resolver, "example.test"); got != testCase.expected {
				t.Errorf("expected %q, got %q", testCase.expected, got)
			}
		})
	}

	// A lookup that fails is a domain the check has nothing to say about, not an error.
	if got := nameServerSet(t.Context(), stubResolver{}, "missing.test"); got != "" {
		t.Errorf("expected a failed lookup to say nothing, got %q", got)
	}
}

// TestCorroborateArgumentChecks holds that the check is safe to call on whatever a search returned.
func TestCorroborateArgumentChecks(t *testing.T) {
	t.Parallel()

	finder := NewFinder(related_config.WithNameServerResolver(stubResolver{}))

	domains, err := finder.Corroborate(t.Context(), "", []*Domain{attributed("one.example")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 1 {
		t.Errorf("expected the domains back untouched, got %d", len(domains))
	}

	if _, err := finder.Corroborate(t.Context(), "example.com", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var nilFinder *Finder
	if _, err := nilFinder.Corroborate(t.Context(), "example.com", nil); err == nil {
		t.Error("expected a nil finder to be an error")
	}
}
