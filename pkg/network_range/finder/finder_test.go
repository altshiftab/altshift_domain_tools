package finder

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/inference"
	"github.com/altshiftab/altshift_domain_tools/pkg/network_range/finder/finder_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/network_range/spf"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripe"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripe/ripe_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

type stubResolver struct {
	records map[string][]string

	lock sync.Mutex
}

func (stub *stubResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	stub.lock.Lock()
	defer stub.lock.Unlock()

	records, ok := stub.records[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}

	return records, nil
}

// newFinder stands the registry up on a test server and gives the walk a stubbed resolver.
func newFinder(t *testing.T, handler http.HandlerFunc, records map[string][]string) *Finder {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("could not parse the server url: %v", err)
	}

	return NewFinder(
		finder_config.WithRipe(ripe.NewClient(
			ripe_config.WithBaseUrl(serverUrl),
			ripe_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
		)),
		finder_config.WithResolver(&stubResolver{records: records}),
	)
}

// registryHandler answers both registry steps: the person search, then the ranges.
func registryHandler(t *testing.T, inetnum string) http.HandlerFunc {
	t.Helper()

	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")

		if strings.Contains(request.URL.Path, "fulltextsearch") {
			body := `{"result":{"numFound":1,"docs":[{"doc":{"strs":[
				{"str":{"name":"nic-hdl","value":"AA1-RIPE"}},
				{"str":{"name":"e-mail","value":"ops@example.com"}}
			]}}]}}`
			if _, err := fmt.Fprint(writer, body); err != nil {
				t.Errorf("could not write: %v", err)
			}

			return
		}

		body := fmt.Sprintf(`{"objects":{"object":[{"attributes":{"attribute":[
			{"name":"inetnum","value":%q},
			{"name":"netname","value":"EXAMPLE-NET"},
			{"name":"status","value":"ASSIGNED PA"}
		]}}]}}`, inetnum)
		if _, err := fmt.Fprint(writer, body); err != nil {
			t.Errorf("could not write: %v", err)
		}
	}
}

func networksOf(ranges []*Range) []string {
	found := make([]string, 0, len(ranges))
	for _, item := range ranges {
		found = append(found, item.Network)
	}

	return found
}

// TestFindMergesBothSources holds why both run: the registry knows what a party was allocated, and
// a mail policy declares what it sends from. Neither is a superset of the other.
func TestFindMergesBothSources(t *testing.T) {
	t.Parallel()

	subdomainFinder := newFinder(
		t,
		registryHandler(t, "192.0.2.0 - 192.0.2.255"),
		map[string][]string{"example.com": {"v=spf1 ip4:198.51.100.0/24 -all"}},
	)

	ranges, err := subdomainFinder.Find(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"192.0.2.0/24", "198.51.100.0/24"}) {
		t.Fatalf("expected both sources, sorted, got %v", networksOf(ranges))
	}

	// The registry's range keeps the registry's detail; the declared one has none to keep.
	if ranges[0].NetName != "EXAMPLE-NET" {
		t.Errorf("expected the registry name kept, got %+v", ranges[0])
	}
	if ranges[0].Confidence() != RipeConfidence {
		t.Errorf("expected the registry confidence, got %d", ranges[0].Confidence())
	}
	if ranges[1].Confidence() != spf.Confidence {
		t.Errorf("expected the declared confidence, got %d", ranges[1].Confidence())
	}
}

// TestFindRaisesConfidenceWhenBothAgree holds the point of carrying inferences rather than a
// boolean: a range two independent sources found is better attributed than one a single weak signal
// produced.
func TestFindRaisesConfidenceWhenBothAgree(t *testing.T) {
	t.Parallel()

	subdomainFinder := newFinder(
		t,
		registryHandler(t, "192.0.2.0 - 192.0.2.255"),
		map[string][]string{"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"}},
	)

	ranges, err := subdomainFinder.Find(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ranges) != 1 {
		t.Fatalf("expected the one range both found, got %d: %v", len(ranges), networksOf(ranges))
	}
	if len(inference.Methods(ranges[0].Inferences)) != 2 {
		t.Errorf("expected both reasons kept, got %+v", ranges[0].Inferences)
	}
	if got := ranges[0].Confidence(); got != RipeConfidence+1 {
		t.Errorf("expected agreement to raise the confidence, got %d", got)
	}
}

// TestFindSurvivesASourceFailing holds that the sources are independent: the registry being down
// must not cost the answers of the mail policy.
func TestFindSurvivesASourceFailing(t *testing.T) {
	t.Parallel()

	subdomainFinder := newFinder(
		t,
		func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
		},
		map[string][]string{"example.com": {"v=spf1 ip4:198.51.100.0/24 -all"}},
	)

	ranges, err := subdomainFinder.Find(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"198.51.100.0/24"}) {
		t.Errorf("expected the working source to survive, got %v", networksOf(ranges))
	}
}

func TestCollapse(t *testing.T) {
	t.Parallel()

	// A registry answer routinely holds a large allocation and several assignments inside it.
	// Reporting all of them would make one allocation look like a dozen.
	collapsed := Collapse([]*Range{
		{Network: "10.0.0.0/16", Inferences: []*inference.Inference{inference.New(MethodRipe, RipeConfidence)}},
		{Network: "10.0.1.0/24", Inferences: []*inference.Inference{inference.New(spf.Method, spf.Confidence)}},
		{Network: "10.0.2.0/24", Inferences: []*inference.Inference{inference.New(spf.Method, spf.Confidence)}},
		{Network: "192.0.2.0/24", Inferences: []*inference.Inference{inference.New(spf.Method, spf.Confidence)}},
		{Network: "not a network"},
		nil,
	})

	if !slices.Equal(networksOf(collapsed), []string{"10.0.0.0/16", "192.0.2.0/24"}) {
		t.Fatalf("expected the contained ranges folded in, got %v", networksOf(collapsed))
	}

	// The narrower range's reasoning is worth keeping: it may have come from a source the wider
	// one did not.
	methods := inference.Methods(collapsed[0].Inferences)
	if len(methods) != 2 {
		t.Errorf("expected the folded reasons kept, got %v", methods)
	}
}

// TestCollapseKeepsOneOfTwoIdentical holds the tie-break. Identical ranges contain each other, so
// without one they would both be dropped.
func TestCollapseKeepsOneOfTwoIdentical(t *testing.T) {
	t.Parallel()

	collapsed := Collapse([]*Range{
		{Network: "10.0.0.0/24", Inferences: []*inference.Inference{inference.New(MethodRipe, RipeConfidence)}},
		{Network: "10.0.0.0/24", Inferences: []*inference.Inference{inference.New(spf.Method, spf.Confidence)}},
	})

	if len(collapsed) != 1 {
		t.Fatalf("expected exactly one to survive, got %d", len(collapsed))
	}
	if len(inference.Methods(collapsed[0].Inferences)) != 2 {
		t.Errorf("expected both reasons kept, got %+v", collapsed[0].Inferences)
	}
}

func TestFindArgumentChecks(t *testing.T) {
	t.Parallel()

	if _, err := NewFinder().Find(t.Context(), ""); err == nil {
		t.Error("expected an empty domain to be an error")
	}

	var nilFinder *Finder
	if _, err := nilFinder.Find(t.Context(), "example.com"); err == nil {
		t.Error("expected a nil finder to be an error")
	}

	var nilRange *Range
	if got := nilRange.Confidence(); got != 0 {
		t.Errorf("expected a nil range to have no confidence, got %d", got)
	}
}
