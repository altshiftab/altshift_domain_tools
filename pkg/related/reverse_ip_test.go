package related

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/inference"
	"github.com/altshiftab/altshift_domain_tools/pkg/related/related_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/hackertarget"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/hackertarget/hackertarget_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

// errNoAddress stands in for a domain that does not resolve.
var errNoAddress = errors.New("no address")

// stubAddressResolver answers from a table, so a test decides what a domain resolves to. It is what
// the resolver being an interface buys: the reverse-IP search is reached without a real lookup, and
// so without the network deciding what the test asserts on.
type stubAddressResolver map[string][]string

func (stub stubAddressResolver) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	addresses, ok := stub[host]
	if !ok {
		return nil, errNoAddress
	}

	found := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		found = append(found, net.ParseIP(address))
	}

	return found, nil
}

// reverseIpFinder builds a finder whose reverse-IP source answers from the given tables: the names
// each address is host to, and the addresses the domain resolves to. An address mapped to no names
// at all is answered with a failure.
func reverseIpFinder(
	t *testing.T,
	addresses map[string][]string,
	hosts map[string][]string,
	options ...related_config.Option,
) *Finder {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		address := request.URL.Query().Get("q")

		names, known := hosts[address]
		if !known {
			writer.WriteHeader(http.StatusInternalServerError)

			return
		}

		if _, err := writer.Write([]byte(strings.Join(names, "\n"))); err != nil {
			t.Errorf("could not write: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("could not parse the server url: %v", err)
	}

	return NewFinder(
		slices.Concat(
			[]related_config.Option{
				related_config.WithHackerTargetApiKey("the-key"),
				related_config.WithHackerTarget(
					hackertarget.NewClient(hackertarget_config.WithBaseUrl(serverUrl)),
				),
				related_config.WithAddressResolver(stubAddressResolver(addresses)),
				related_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
			},
			options,
		)...,
	)
}

// TestReverseIp holds what the search does with what an address is host to.
func TestReverseIp(t *testing.T) {
	t.Parallel()

	// Twenty-six distinct registrations behind one address, which is over the default limit.
	crowded := make([]string, 0, DefaultSharedHostingDomainLimit+1)
	for i := range DefaultSharedHostingDomainLimit + 1 {
		crowded = append(crowded, fmt.Sprintf("tenant%d.net", i))
	}

	testCases := []struct {
		name            string
		addresses       []string
		hosts           map[string][]string
		options         []related_config.Option
		expectedDomains []string
		expectedError   bool
	}{
		{
			name:      "the registrations behind an address, deduplicated",
			addresses: []string{"192.0.2.1"},
			hosts: map[string][]string{
				// Three hosts of one company count as one domain rather than three.
				"192.0.2.1": {"www.other.net", "mail.other.net", "other.net"},
			},
			expectedDomains: []string{"other.net"},
		},
		{
			name:      "every address the domain has, merged",
			addresses: []string{"192.0.2.1", "192.0.2.2"},
			hosts: map[string][]string{
				"192.0.2.1": {"one.net"},
				"192.0.2.2": {"two.org"},
			},
			expectedDomains: []string{"one.net", "two.org"},
		},
		{
			name:      "the searched domain is not one of its own relations",
			addresses: []string{"192.0.2.1"},
			hosts:     map[string][]string{"192.0.2.1": {"example.com", "other.net"}},
			// example.com is what was asked about, so it is not part of the answer.
			expectedDomains: []string{"other.net"},
		},
		{
			name:      "an address everyone is on says nothing about who owns what",
			addresses: []string{"192.0.2.1"},
			hosts:     map[string][]string{"192.0.2.1": crowded},
			// Over the shared-hosting limit, so the whole address is discarded rather than reported.
			expectedDomains: []string{},
		},
		{
			name:      "and a lowered limit discards more",
			addresses: []string{"192.0.2.1"},
			hosts:     map[string][]string{"192.0.2.1": {"one.net", "two.org", "three.net"}},
			options:   []related_config.Option{related_config.WithSharedHostingDomainLimit(2)},
			// Three registrations against a limit of two.
			expectedDomains: []string{},
		},
		{
			name:      "the domains co-location can never say anything about are left out",
			addresses: []string{"192.0.2.1"},
			hosts: map[string][]string{
				"192.0.2.1": {"something.googleusercontent.com", "other.net"},
			},
			expectedDomains: []string{"other.net"},
		},
		{
			name:      "one address failing does not discard what the others found",
			addresses: []string{"192.0.2.1", "192.0.2.2"},
			hosts: map[string][]string{
				"192.0.2.1": {"one.net"},
				// 192.0.2.2 is absent from the table, so the lookup for it fails.
			},
			expectedDomains: []string{"one.net"},
		},
		{
			name:          "every address failing is the key or the source, and is an error",
			addresses:     []string{"192.0.2.1", "192.0.2.2"},
			hosts:         map[string][]string{},
			expectedError: true,
		},
		{
			name:      "a domain that does not resolve is an error rather than an empty answer",
			addresses: nil,
			hosts:     map[string][]string{},
			// No addresses in the table at all, so the lookup itself fails.
			expectedError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			addresses := map[string][]string{}
			if testCase.addresses != nil {
				addresses["example.com"] = testCase.addresses
			}

			finder := reverseIpFinder(t, addresses, testCase.hosts, testCase.options...)

			domains, err := finder.ReverseIp(t.Context(), "example.com")

			if testCase.expectedError {
				if err == nil {
					t.Fatal("expected an error")
				}

				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			names := make([]string, 0, len(domains))
			for _, domain := range domains {
				names = append(names, domain.Domain)

				// Both name fields are filled in on this side, the answer having already been
				// reduced to registrations.
				if domain.RegisteredDomain != domain.Domain {
					t.Errorf("expected %s to carry its own registration, got %q", domain.Domain, domain.RegisteredDomain)
				}

				for _, item := range domain.Inferences {
					if item.Method != MethodReverseIp {
						t.Errorf("expected the reverse-IP method, got %q", item.Method)
					}
					if item.Confidence != ReverseIpConfidence {
						t.Errorf("expected co-location to stay weak, got %d", item.Confidence)
					}
					// The address is the reasoning, so an operator can check it rather than take
					// the attribution on faith.
					if len(item.Via) != 1 || !slices.Contains(testCase.addresses, item.Via[0]) {
						t.Errorf("expected the address in the reasoning, got %v", item.Via)
					}
				}
			}

			slices.Sort(names)
			expected := slices.Clone(testCase.expectedDomains)
			slices.Sort(expected)

			if !slices.Equal(names, expected) {
				t.Errorf("expected %v, got %v", expected, names)
			}
		})
	}
}

// TestReverseIpMergesTheAddressesADomainShares records that a domain behind two of the searched
// domain's addresses carries both, rather than whichever answered first. It is one method seen
// twice, so it is worth no more than once -- Combined is what holds that line.
func TestReverseIpMergesTheAddressesADomainShares(t *testing.T) {
	t.Parallel()

	finder := reverseIpFinder(
		t,
		map[string][]string{"example.com": {"192.0.2.1", "192.0.2.2"}},
		map[string][]string{
			"192.0.2.1": {"other.net"},
			"192.0.2.2": {"other.net"},
		},
	)

	domains, err := finder.ReverseIp(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(domains) != 1 {
		t.Fatalf("expected the one domain, got %d", len(domains))
	}
	if len(domains[0].Inferences) != 2 {
		t.Errorf("expected both addresses to be kept as reasons, got %d", len(domains[0].Inferences))
	}
	if got := len(inference.Methods(domains[0].Inferences)); got != 1 {
		t.Errorf("expected one method however many addresses found it, got %d", got)
	}
	// Five reverse-IP hits are one piece of evidence seen five times, not five pieces.
	if got := domains[0].Confidence(); got != ReverseIpConfidence {
		t.Errorf("expected co-location seen twice to be worth what it is worth once, got %d", got)
	}
}
