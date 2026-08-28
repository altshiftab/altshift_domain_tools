package related

import (
	"slices"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/related/related_config"
)

func TestMerge(t *testing.T) {
	t.Parallel()

	// The same domain found by both sources keeps both reasons, so a consumer can see it was
	// attributed twice rather than once.
	merged := Merge(
		&Domain{Domain: "example.net", Inferences: []*Inference{{Confidence: ReverseWhoisConfidence, Chain: []string{"reverse whois"}}}},
		&Domain{Domain: "example.net", Inferences: []*Inference{{Confidence: ReverseIpConfidence, Chain: []string{"reverse ip"}}}},
		&Domain{Domain: "example.org", Inferences: []*Inference{{Confidence: ReverseIpConfidence}}},
		&Domain{Domain: ""},
		nil,
	)

	if len(merged) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(merged))
	}

	// Sorted, so the answer does not depend on map iteration.
	if merged[0].Domain != "example.net" || merged[1].Domain != "example.org" {
		t.Errorf("expected the domains sorted, got %q then %q", merged[0].Domain, merged[1].Domain)
	}

	if len(merged[0].Inferences) != 2 {
		t.Errorf("expected both reasons to be kept, got %d", len(merged[0].Inferences))
	}
}

// TestConfidences holds the weighting the two sources are worth. A registration record naming the
// same party is strong evidence; sharing an address is weak, and a consumer that treated them alike
// would attribute half the internet to whoever shares a host.
func TestConfidences(t *testing.T) {
	t.Parallel()

	if ReverseWhoisConfidence <= ReverseIpConfidence {
		t.Errorf(
			"expected a registration match (%d) to outweigh co-location (%d)",
			ReverseWhoisConfidence,
			ReverseIpConfidence,
		)
	}
	for _, confidence := range []int{ReverseWhoisConfidence, ReverseIpConfidence} {
		if confidence < 1 || confidence > 5 {
			t.Errorf("expected a confidence on the one-to-five scale, got %d", confidence)
		}
	}
}

func TestRegisteredDomainNames(t *testing.T) {
	t.Parallel()

	// Ten hosts of one company count as one domain rather than ten, which is what the shared
	// hosting limit is counted against.
	got := registeredDomainNames([]string{
		"www.example.com",
		"mail.example.com",
		"example.com",
		"other.co.uk",
		"not a domain",
		"",
	})

	slices.Sort(got)
	if !slices.Equal(got, []string{"example.com", "other.co.uk"}) {
		t.Errorf("expected the distinct registrations, got %v", got)
	}
}

func TestArgumentChecks(t *testing.T) {
	t.Parallel()

	// A finder with no keys: neither source is anonymous, so both must refuse rather than call.
	keyless := NewFinder()
	if _, err := keyless.ReverseWhois(t.Context(), "example.com", false); err == nil {
		t.Error("expected an empty whoisxml api key to be an error")
	}
	if _, err := keyless.ReverseIp(t.Context(), "example.com"); err == nil {
		t.Error("expected an empty hackertarget api key to be an error")
	}

	var nilFinder *Finder
	if _, err := nilFinder.ReverseWhois(t.Context(), "example.com", false); err == nil {
		t.Error("expected a nil finder to be an error")
	}
	if _, err := nilFinder.ReverseIp(t.Context(), "example.com"); err == nil {
		t.Error("expected a nil finder to be an error")
	}

	// An empty domain searches nothing rather than failing.
	keyed := NewFinder(related_config.WithWhoisXmlApiKey("the-key"))
	domains, err := keyed.ReverseWhois(t.Context(), "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if domains != nil {
		t.Errorf("expected nothing, got %d", len(domains))
	}
}

// TestSharedHostingLimitIsMeaningful records why the limit exists: an address serving more domains
// than this is shared hosting, where co-location says nothing about who owns what.
func TestSharedHostingLimitIsMeaningful(t *testing.T) {
	t.Parallel()

	if DefaultSharedHostingDomainLimit < 2 {
		t.Errorf("expected a limit that admits genuine co-location, got %d", DefaultSharedHostingDomainLimit)
	}
	if _, excluded := excludedRegisteredDomains["googleusercontent.com"]; !excluded {
		t.Error("expected the known shared domains to be excluded outright")
	}

	// A configured limit overrides the default; an unset one falls back to it.
	if got := NewFinder(related_config.WithSharedHostingDomainLimit(3)).sharedHostingDomainLimit(); got != 3 {
		t.Errorf("expected the configured limit, got %d", got)
	}
	if got := NewFinder().sharedHostingDomainLimit(); got != DefaultSharedHostingDomainLimit {
		t.Errorf("expected the default limit, got %d", got)
	}
}
