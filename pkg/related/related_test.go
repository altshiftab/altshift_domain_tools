package related

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/inference"
	"github.com/altshiftab/altshift_domain_tools/pkg/related/related_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml"
	whoisXmlTypes "github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml/types"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml/whoisxml_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

func TestMerge(t *testing.T) {
	t.Parallel()

	// The same domain found by both sources keeps both reasons, so a consumer can see it was
	// attributed twice rather than once.
	merged := Merge(
		&Domain{
			Domain:     "example.net",
			Inferences: []*inference.Inference{inference.New(MethodReverseWhois, ReverseWhoisConfidence, "a@b")},
		},
		&Domain{
			Domain:     "example.net",
			Inferences: []*inference.Inference{inference.New(MethodReverseIp, ReverseIpConfidence, "192.0.2.1")},
		},
		&Domain{
			Domain:     "example.org",
			Inferences: []*inference.Inference{inference.New(MethodReverseIp, ReverseIpConfidence)},
		},
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

	// Two independent methods agreeing is worth more than either alone, but only by one step: the
	// evidence is not additive.
	if got := merged[0].Confidence(); got != ReverseWhoisConfidence+1 {
		t.Errorf("expected two methods to raise the confidence by one, got %d", got)
	}
	// One method on its own is worth exactly what it is worth.
	if got := merged[1].Confidence(); got != ReverseIpConfidence {
		t.Errorf("expected a single method to stand at its own confidence, got %d", got)
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
	// The scale is the shared one, so a value off it is a mistake rather than a grade.
	for _, confidence := range []inference.Confidence{ReverseWhoisConfidence, ReverseIpConfidence} {
		if !confidence.Valid() {
			t.Errorf("expected a confidence on the scale, got %d", confidence)
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
	if _, err := keyless.ReverseWhois(t.Context(), "example.com", nil); err == nil {
		t.Error("expected an empty whoisxml api key to be an error")
	}
	if _, err := keyless.ReverseIp(t.Context(), "example.com"); err == nil {
		t.Error("expected an empty hackertarget api key to be an error")
	}

	var nilFinder *Finder
	if _, err := nilFinder.ReverseWhois(t.Context(), "example.com", nil); err == nil {
		t.Error("expected a nil finder to be an error")
	}
	if _, err := nilFinder.ReverseIp(t.Context(), "example.com"); err == nil {
		t.Error("expected a nil finder to be an error")
	}

	// An empty domain searches nothing rather than failing.
	keyed := NewFinder(related_config.WithWhoisXmlApiKey("the-key"))
	domains, err := keyed.ReverseWhois(t.Context(), "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if domains != nil {
		t.Errorf("expected nothing, got %d", len(domains))
	}
}

// whoisXmlFinder builds a finder whose reverse-whois client answers from the given handler.
//
// Retries are turned off: a test that means to see a failure should see it rather than wait out the
// back-off a rate limit deserves.
func whoisXmlFinder(t *testing.T, handler http.HandlerFunc, options ...related_config.Option) *Finder {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("could not parse the server url: %v", err)
	}

	return NewFinder(
		slices.Concat(
			[]related_config.Option{
				related_config.WithWhoisXmlApiKey("the-key"),
				related_config.WithWhoisXml(whoisxml.NewClient(whoisxml_config.WithBaseUrl(serverUrl))),
				related_config.WithFetchOptions(
					fetch_config.WithHttpClient(server.Client()),
					fetch_config.WithRetryConfig(nil),
				),
			},
			options,
		)...,
	)
}

// reverseWhoisHandler answers previews with the count the term maps to, and purchases with domains
// named after it. A term mapped to a negative count is answered with a failure.
func reverseWhoisHandler(t *testing.T, counts map[string]int, purchases *atomic.Int64) http.HandlerFunc {
	t.Helper()

	return func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("could not read the request: %v", err)

			return
		}

		var sent whoisXmlTypes.ReverseWhoisRequest
		if err := json.Unmarshal(body, &sent); err != nil {
			t.Errorf("could not unmarshal the request: %v", err)

			return
		}

		if len(sent.AdvancedSearchTerms) != 1 || sent.AdvancedSearchTerms[0] == nil {
			t.Errorf("expected one search term, got %+v", sent.AdvancedSearchTerms)

			return
		}
		term := sent.AdvancedSearchTerms[0].Term

		count, known := counts[term]
		if !known || count < 0 {
			writer.WriteHeader(http.StatusInternalServerError)

			return
		}

		response := &whoisXmlTypes.ReverseWhoisResponse{DomainsCount: count}
		if sent.Mode == whoisxml.ModePurchase {
			if purchases != nil {
				purchases.Add(1)
			}

			// Named after the term that found them, so that the two terms a search issues answer
			// with different domains rather than the same ones twice over.
			label := "root"
			if strings.HasPrefix(term, "*@*.") {
				label = "sub"
			}

			for i := range count {
				response.DomainsList = append(response.DomainsList, fmt.Sprintf("%d.%s.example", i, label))
			}
		}

		data, err := json.Marshal(response)
		if err != nil {
			t.Errorf("could not marshal: %v", err)

			return
		}

		writer.Header().Set("Content-Type", "application/json")
		if _, err := writer.Write(data); err != nil {
			t.Errorf("could not write: %v", err)
		}
	}
}

// TestReverseWhoisLeavesBroadTermsUnbought holds the guard the preview is there to make possible. A
// term matching more domains than the limit allows has matched an address everyone shares rather
// than one party's registrations, and the preview says so for free -- so no credit is spent on it.
//
// The count stops at what one response holds, so a term at that ceiling has said only that it
// matched too much to count, and is treated as over the limit rather than exactly at it.
func TestReverseWhoisLeavesBroadTermsUnbought(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		count             int
		options           []related_config.Option
		expectedPurchases int64
		expectedDomains   int
	}{
		{
			name:              "a term within the limit is bought",
			count:             3,
			expectedPurchases: 2,
			expectedDomains:   6,
		},
		{
			name:              "a term at the counting ceiling is not",
			count:             whoisxml.MaximumResponseDomains,
			expectedPurchases: 0,
		},
		{
			name:              "nor is one over a lowered limit",
			count:             30,
			options:           []related_config.Option{related_config.WithReverseWhoisMatchLimit(10)},
			expectedPurchases: 0,
		},
		{
			name:              "a term matching nothing is not bought either",
			count:             0,
			expectedPurchases: 0,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var purchases atomic.Int64

			// Both terms the search issues, mapped to the same count.
			counts := map[string]int{"*@example.com": testCase.count, "*@*.example.com": testCase.count}

			finder := whoisXmlFinder(t, reverseWhoisHandler(t, counts, &purchases), testCase.options...)

			domains, err := finder.ReverseWhois(t.Context(), "example.com", nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := purchases.Load(); got != testCase.expectedPurchases {
				t.Errorf("expected %d purchases, got %d", testCase.expectedPurchases, got)
			}
			if len(domains) != testCase.expectedDomains {
				t.Errorf("expected %d domains, got %d", testCase.expectedDomains, len(domains))
			}
		})
	}
}

// TestReverseWhoisKeepsWhatOneTermBought records that a failed term does not discard the others. A
// purchase already billed is not worth throwing away because a second search went wrong, which is
// what cancelling the siblings on the first error would do.
func TestReverseWhoisKeepsWhatOneTermBought(t *testing.T) {
	t.Parallel()

	// The subdomain term fails; the domain term matches three.
	counts := map[string]int{"*@example.com": 3, "*@*.example.com": -1}

	finder := whoisXmlFinder(t, reverseWhoisHandler(t, counts, nil))

	domains, err := finder.ReverseWhois(t.Context(), "example.com", nil)
	if err != nil {
		t.Fatalf("expected the failing term to be survived, got %v", err)
	}
	if len(domains) != 3 {
		t.Errorf("expected the three domains the other term bought, got %d", len(domains))
	}
}

// TestReverseWhoisEveryTermFailing holds the other half of that. Every search failing is the key or
// the API rather than a domain with no relations, and an empty answer would read as the latter.
func TestReverseWhoisEveryTermFailing(t *testing.T) {
	t.Parallel()

	finder := whoisXmlFinder(t, reverseWhoisHandler(t, map[string]int{}, nil))

	if _, err := finder.ReverseWhois(t.Context(), "example.com", nil); err == nil {
		t.Error("expected every search failing to be an error rather than an empty answer")
	}
}

// The failures a results test stands up, named rather than built inline so that what they are is
// the point rather than what they say.
var (
	errFirstSearch  = errors.New("the first search failed")
	errSecondSearch = errors.New("the second search failed")
)

// TestReverseWhoisOrganization holds the pivot that survives redaction, and the two gates standing
// in for the check it cannot make.
func TestReverseWhoisOrganization(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		domain            string
		organization      string
		counts            map[string]int
		options           []related_config.Option
		expectedPurchases int64
		expectedDomains   int
		expectedError     bool
	}{
		{
			name:   "the name is guessed from the label, and its terms are bought",
			domain: "kivra.com",
			// Both fields are searched on the label, and both answer.
			counts:            map[string]int{"kivra": 3},
			expectedPurchases: 2,
			// The same three domains from each field, merged by name.
			expectedDomains: 3,
		},
		{
			name:              "a provided name is searched for instead of the label",
			domain:            "kivra.com",
			organization:      "Kivra AB",
			counts:            map[string]int{"Kivra": 2},
			expectedPurchases: 2,
			expectedDomains:   2,
		},
		{
			name:              "a term matching more than the limit is left unbought",
			domain:            "kivra.com",
			counts:            map[string]int{"kivra": DefaultReverseWhoisOrganizationMatchLimit + 1},
			expectedPurchases: 0,
		},
		{
			name:              "and the limit is far below what an address search would allow",
			domain:            "kivra.com",
			counts:            map[string]int{"kivra": 30},
			options:           []related_config.Option{related_config.WithReverseWhoisOrganizationMatchLimit(10)},
			expectedPurchases: 0,
		},
		{
			name:   "a guessed name that could not identify anyone is dropped, not searched",
			domain: "ab.se",
			// Nothing is mapped, so any request at all would fail the test by 500ing.
			counts:            map[string]int{},
			expectedPurchases: 0,
		},
		{
			name:              "a provided name that could not identify anyone is an error",
			domain:            "kivra.com",
			organization:      "Data Group AB",
			counts:            map[string]int{},
			expectedPurchases: 0,
			expectedError:     true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var purchases atomic.Int64

			finder := whoisXmlFinder(t, reverseWhoisHandler(t, testCase.counts, &purchases), testCase.options...)

			domains, err := finder.ReverseWhoisOrganization(
				t.Context(),
				testCase.domain,
				testCase.organization,
				nil,
			)

			if testCase.expectedError {
				if err == nil {
					t.Fatal("expected a name that cannot identify a party to be an error")
				}

				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := purchases.Load(); got != testCase.expectedPurchases {
				t.Errorf("expected %d purchases, got %d", testCase.expectedPurchases, got)
			}
			if len(domains) != testCase.expectedDomains {
				t.Errorf("expected %d domains, got %d", testCase.expectedDomains, len(domains))
			}

			// Whatever it found is attributed to the organisation pivot rather than to the address
			// one, so a consumer can weigh a substring match for what it is.
			for _, domain := range domains {
				for _, item := range domain.Inferences {
					if item.Method != MethodReverseWhoisOrganization {
						t.Errorf("expected the organisation method, got %q", item.Method)
					}
				}
			}
		})
	}
}

// TestOrganizationPivotIsWeigtedBelowTheAddressOne records the weighting the two pivots carry. An
// address at the domain is the party stating the relationship; a name in the organisation field is
// a substring that matched, and nothing in this package can check that the party it matched is the
// same party. Being separate methods is what lets a domain both of them found outrank either.
func TestOrganizationPivotIsWeigtedBelowTheAddressOne(t *testing.T) {
	t.Parallel()

	if ReverseWhoisOrganizationConfidence >= ReverseWhoisConfidence {
		t.Errorf(
			"expected a name match (%d) to be worth less than an address at the domain (%d)",
			ReverseWhoisOrganizationConfidence,
			ReverseWhoisConfidence,
		)
	}
	if ReverseWhoisOrganizationConfidence <= ReverseIpConfidence {
		t.Errorf(
			"expected a name match (%d) to be worth more than co-location (%d)",
			ReverseWhoisOrganizationConfidence,
			ReverseIpConfidence,
		)
	}
	if !ReverseWhoisOrganizationConfidence.Valid() {
		t.Errorf("expected a confidence on the scale, got %d", ReverseWhoisOrganizationConfidence)
	}
	if MethodReverseWhoisOrganization == MethodReverseWhois {
		t.Error("expected the organisation pivot to be a method of its own")
	}

	// A domain both pivots found is better attributed than one either found alone.
	both := Merge(
		&Domain{
			Domain:     "example.net",
			Inferences: []*inference.Inference{inference.New(MethodReverseWhois, ReverseWhoisConfidence, "a@b")},
		},
		&Domain{
			Domain: "example.net",
			Inferences: []*inference.Inference{
				inference.New(MethodReverseWhoisOrganization, ReverseWhoisOrganizationConfidence, "Kivra"),
			},
		},
	)
	if len(both) != 1 {
		t.Fatalf("expected one domain, got %d", len(both))
	}
	if got := both[0].Confidence(); got != ReverseWhoisConfidence+1 {
		t.Errorf("expected the two pivots agreeing to raise the confidence by one, got %d", got)
	}
}

// TestOrganizationMatchLimitIsMeaningful records that the pivot has a bound of its own, far below
// the address search's, because a name matches far more loosely than an address does.
func TestOrganizationMatchLimitIsMeaningful(t *testing.T) {
	t.Parallel()

	if DefaultReverseWhoisOrganizationMatchLimit >= DefaultReverseWhoisMatchLimit {
		t.Errorf(
			"expected the organisation limit (%d) to sit below the address one (%d)",
			DefaultReverseWhoisOrganizationMatchLimit,
			DefaultReverseWhoisMatchLimit,
		)
	}
	// Large enough to admit a real portfolio: Kivra's own is seventeen.
	if DefaultReverseWhoisOrganizationMatchLimit < 100 {
		t.Errorf("expected a limit that admits a real portfolio, got %d", DefaultReverseWhoisOrganizationMatchLimit)
	}

	if got := NewFinder(related_config.WithReverseWhoisOrganizationMatchLimit(3)).reverseWhoisOrganizationMatchLimit(); got != 3 {
		t.Errorf("expected the configured limit, got %d", got)
	}
	if got := NewFinder().reverseWhoisOrganizationMatchLimit(); got != DefaultReverseWhoisOrganizationMatchLimit {
		t.Errorf("expected the default limit, got %d", got)
	}
}

// TestSearchTypes holds what a run reads and what that costs.
//
// The default is the current records alone, because that is the half a monitor repeats: the
// historic sweep holds what redaction has since removed and is worth making once for a domain,
// while reading both on every run would buy the past over again at a search apiece.
func TestSearchTypes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		requested         []string
		options           []related_config.Option
		expectedTypes     []string
		expectedPurchases int64
	}{
		{
			name: "nothing asked for reads the current records alone",
			// Two terms, one search type: two purchases.
			expectedTypes:     []string{whoisxml.SearchTypeCurrent},
			expectedPurchases: 2,
		},
		{
			name:              "the call decides where it says so",
			requested:         []string{whoisxml.SearchTypeHistoric},
			expectedTypes:     []string{whoisxml.SearchTypeHistoric},
			expectedPurchases: 2,
		},
		{
			name:              "both is both, and costs twice",
			requested:         []string{whoisxml.SearchTypeCurrent, whoisxml.SearchTypeHistoric},
			expectedTypes:     []string{whoisxml.SearchTypeCurrent, whoisxml.SearchTypeHistoric},
			expectedPurchases: 4,
		},
		{
			name:              "a finder configured for one reads that one",
			options:           []related_config.Option{related_config.WithSearchTypes(whoisxml.SearchTypeHistoric)},
			expectedTypes:     []string{whoisxml.SearchTypeHistoric},
			expectedPurchases: 2,
		},
		{
			name:              "and the call still overrides the finder",
			requested:         []string{whoisxml.SearchTypeCurrent},
			options:           []related_config.Option{related_config.WithSearchTypes(whoisxml.SearchTypeHistoric)},
			expectedTypes:     []string{whoisxml.SearchTypeCurrent},
			expectedPurchases: 2,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var (
				purchases atomic.Int64
				seen      sync.Map
			)

			counts := map[string]int{"*@example.com": 1, "*@*.example.com": 1}
			handler := reverseWhoisHandler(t, counts, &purchases)

			finder := whoisXmlFinder(
				t,
				func(writer http.ResponseWriter, request *http.Request) {
					body, err := io.ReadAll(request.Body)
					if err != nil {
						t.Errorf("could not read the request: %v", err)

						return
					}

					var sent whoisXmlTypes.ReverseWhoisRequest
					if err := json.Unmarshal(body, &sent); err != nil {
						t.Errorf("could not unmarshal the request: %v", err)

						return
					}
					seen.Store(sent.SearchType, struct{}{})

					request.Body = io.NopCloser(strings.NewReader(string(body)))
					handler(writer, request)
				},
				testCase.options...,
			)

			domains, err := finder.ReverseWhois(t.Context(), "example.com", testCase.requested)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			asked := make([]string, 0, 2)
			seen.Range(func(key any, _ any) bool {
				asked = append(asked, key.(string))

				return true
			})
			slices.Sort(asked)

			if !slices.Equal(asked, testCase.expectedTypes) {
				t.Errorf("expected %v to be asked for, got %v", testCase.expectedTypes, asked)
			}
			if got := purchases.Load(); got != testCase.expectedPurchases {
				t.Errorf("expected %d purchases, got %d", testCase.expectedPurchases, got)
			}

			// Whichever records were read, the search type is on the reasoning, so a historic match
			// can be told from a current one after the fact.
			for _, domain := range domains {
				for _, item := range domain.Inferences {
					if !slices.ContainsFunc(testCase.expectedTypes, func(searchType string) bool {
						return slices.Contains(item.Via, searchType)
					}) {
						t.Errorf("expected the search type in the reasoning, got %v", item.Via)
					}
				}
			}
		})
	}
}

// TestHistoricIsWorthLessThanCurrent holds the weighting between the two sets of records, and the
// reason they are not separate methods.
func TestHistoricIsWorthLessThanCurrent(t *testing.T) {
	t.Parallel()

	pivots := []*pivot{
		{
			field:      whoisxml.FieldEmail,
			term:       "*@example.com",
			method:     MethodReverseWhois,
			confidence: ReverseWhoisConfidence,
		},
	}

	terms := expand(pivots, []string{whoisxml.SearchTypeCurrent, whoisxml.SearchTypeHistoric})
	if len(terms) != 2 {
		t.Fatalf("expected a term per search type, got %d", len(terms))
	}

	current, historic := terms[0], terms[1]

	// The package claims present ownership, and a registration that has since changed is weaker
	// evidence of it -- by one step, redaction meaning the past is often the only place the
	// evidence survives at all.
	if historic.confidence != current.confidence-1 {
		t.Errorf(
			"expected historic (%d) to be one step below current (%d)",
			historic.confidence,
			current.confidence,
		)
	}

	// The same method, deliberately. Two search types are one search against two copies of the same
	// registry rather than two methods agreeing, and Combined would raise every domain in both if
	// they were separate.
	if historic.method != current.method {
		t.Errorf("expected one method across the search types, got %q and %q", current.method, historic.method)
	}

	both := Merge(
		&Domain{
			Domain:     "example.net",
			Inferences: []*inference.Inference{inference.New(current.method, current.confidence, "current")},
		},
		&Domain{
			Domain:     "example.net",
			Inferences: []*inference.Inference{inference.New(historic.method, historic.confidence, "historic")},
		},
	)
	if len(both) != 1 {
		t.Fatalf("expected one domain, got %d", len(both))
	}
	if got := both[0].Confidence(); got != current.confidence {
		t.Errorf("expected a domain in both records to stand at the current confidence, got %d", got)
	}

	// The weakest a pivot can be weakened to is still on the scale.
	weakest := expand(
		[]*pivot{{method: MethodReverseWhois, confidence: inference.Lowest}},
		[]string{whoisxml.SearchTypeHistoric},
	)
	if !weakest[0].confidence.Valid() {
		t.Errorf("expected a confidence on the scale, got %d", weakest[0].confidence)
	}
}

// TestResults holds the failure policy both searches share. Neither cancels its siblings on the
// first error, so what one input found survives another input failing -- and every input failing
// with nothing to show is the key or the source rather than a domain with no relations.
//
// It is exercised directly as well as through the two searches that use it, the policy being one
// thing rather than two and worth one test that says so.
func TestResults(t *testing.T) {
	t.Parallel()

	found := []*Domain{{Domain: "example.net"}}

	testCases := []struct {
		name            string
		searches        int
		collected       [][]*Domain
		failures        []error
		expectedError   bool
		expectedDomains int
	}{
		{
			name:     "nothing found and nothing failed is an empty answer",
			searches: 2,
		},
		{
			name:            "one search failing does not discard what the other found",
			searches:        2,
			collected:       [][]*Domain{found},
			failures:        []error{errFirstSearch},
			expectedDomains: 1,
		},
		{
			name:          "every search failing with nothing to show is an error",
			searches:      2,
			failures:      []error{errFirstSearch, errSecondSearch},
			expectedError: true,
		},
		{
			name:            "every search failing is not, where one left something behind",
			searches:        2,
			collected:       [][]*Domain{found},
			failures:        []error{errFirstSearch, errSecondSearch},
			expectedDomains: 1,
		},
		{
			name:     "no searches at all is not every search failing",
			searches: 0,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var gathered results
			for _, domains := range testCase.collected {
				gathered.collect(domains)
			}
			for _, err := range testCase.failures {
				gathered.record(err)
			}

			domains, err := gathered.finish(t.Context(), testCase.searches, "searching")

			if testCase.expectedError {
				if err == nil {
					t.Fatal("expected an error")
				}

				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(domains) != testCase.expectedDomains {
				t.Errorf("expected %d domains, got %d", testCase.expectedDomains, len(domains))
			}
		})
	}
}

// TestReverseWhoisMatchLimitIsMeaningful records what the limit is measured in: one response's
// worth, which is as high as the preview counts, so the default answer is whole or unbought.
func TestReverseWhoisMatchLimitIsMeaningful(t *testing.T) {
	t.Parallel()

	if DefaultReverseWhoisMatchLimit != whoisxml.MaximumResponseDomains {
		t.Errorf(
			"expected the default to be one response's worth (%d), got %d",
			whoisxml.MaximumResponseDomains,
			DefaultReverseWhoisMatchLimit,
		)
	}

	// A configured limit overrides the default; an unset one falls back to it.
	if got := NewFinder(related_config.WithReverseWhoisMatchLimit(3)).reverseWhoisMatchLimit(); got != 3 {
		t.Errorf("expected the configured limit, got %d", got)
	}
	if got := NewFinder().reverseWhoisMatchLimit(); got != DefaultReverseWhoisMatchLimit {
		t.Errorf("expected the default limit, got %d", got)
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
