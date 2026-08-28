package finder_test

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/crtsh"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/crtsh/crtsh_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/hackertarget"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/hackertarget/hackertarget_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/subdomain/finder"
	"github.com/altshiftab/altshift_domain_tools/pkg/subdomain/finder/finder_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

// stubResolver answers yes for the names given, and to the wildcard probe when wildcard is set.
//
// It locks because the brute force calls a resolver from many goroutines at once, which the
// interface requires an implementation to withstand. A stub that did not would race where the real
// resolver does not, and the race would be the test's rather than the code's.
type stubResolver struct {
	exists   map[string]bool
	wildcard bool

	askedLock sync.Mutex
	asked     []string
}

func (stub *stubResolver) DomainExists(_ context.Context, domain string) (bool, error) {
	stub.askedLock.Lock()
	stub.asked = append(stub.asked, domain)
	stub.askedLock.Unlock()

	if stub.wildcard {
		return true, nil
	}

	return stub.exists[domain], nil
}

// askedFor reports whether the resolver was asked about the name.
func (stub *stubResolver) askedFor(domain string) bool {
	stub.askedLock.Lock()
	defer stub.askedLock.Unlock()

	return slices.Contains(stub.asked, domain)
}

// askedCount is how many lookups the resolver was asked for.
func (stub *stubResolver) askedCount() int {
	stub.askedLock.Lock()
	defer stub.askedLock.Unlock()

	return len(stub.asked)
}

// newFinder stands both passive sources up on one server and builds a finder pointed at it. The
// sources take their base URL from their config rather than a package global, so these tests run in
// parallel.
func newFinder(t *testing.T, certNames []string, hostSearch string, options ...finder_config.Option) *finder.Finder {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "hostsearch") {
			if _, err := writer.Write([]byte(hostSearch)); err != nil {
				t.Errorf("could not write: %v", err)
			}

			return
		}

		results := make([]*crtsh.Result, 0, len(certNames))
		for _, name := range certNames {
			results = append(results, &crtsh.Result{NameValue: name})
		}
		data, err := json.Marshal(results)
		if err != nil {
			t.Errorf("could not marshal: %v", err)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if _, err := writer.Write(data); err != nil {
			t.Errorf("could not write: %v", err)
		}
	}))

	t.Cleanup(server.Close)

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("could not parse the server url: %v", err)
	}

	httpClient := fetch_config.WithHttpClient(server.Client())

	return finder.NewFinder(
		slices.Concat(
			[]finder_config.Option{
				finder_config.WithCrtsh(crtsh.NewClient(crtsh_config.WithBaseUrl(serverUrl))),
				finder_config.WithHackerTarget(hackertarget.NewClient(hackertarget_config.WithBaseUrl(serverUrl))),
				finder_config.WithFetchOptions(httpClient),
			},
			options,
		)...,
	)
}

func TestPassive(t *testing.T) {
	t.Parallel()

	subdomainFinder := newFinder(t, []string{"www.example.com", "*.example.com"}, "mail.example.com,192.0.2.1\n")

	names := subdomainFinder.Passive(t.Context(), "example.com")

	if !slices.Equal(names, []string{"mail.example.com", "www.example.com"}) {
		t.Errorf("expected both sources' names, sorted, got %v", names)
	}
}

// TestPassiveSurvivesASourceFailing holds that the sources are independent: one being down or out
// of quota must not cost the answers of the other.
func TestPassiveSurvivesASourceFailing(t *testing.T) {
	t.Parallel()

	subdomainFinder := newFinder(
		t,
		[]string{"www.example.com"},
		"API count exceeded - Increase Quota with Membership",
	)

	names := subdomainFinder.Passive(t.Context(), "example.com")

	if !slices.Equal(names, []string{"www.example.com"}) {
		t.Errorf("expected the working source's answer to survive, got %v", names)
	}
}

func TestFind(t *testing.T) {
	t.Parallel()

	stub := &stubResolver{exists: map[string]bool{"vpn.example.com": true}}

	subdomainFinder := newFinder(
		t,
		[]string{"www.example.com"},
		"mail.example.com,192.0.2.1\n",
		finder_config.WithResolver(stub),
		finder_config.WithConcurrency(4),
	)

	result, err := subdomainFinder.Find(
		t.Context(),
		"example.com",
		slices.Values([]string{"vpn", "nothing"}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Bruted {
		t.Error("expected the active pass to have run")
	}

	// The passive names are kept even though nothing resolves them -- a name the logs know existed
	// once is worth reporting -- and the active pass adds what it found.
	slices.Sort(result.Names)
	expected := []string{"mail.example.com", "vpn.example.com", "www.example.com"}
	if !slices.Equal(result.Names, expected) {
		t.Errorf("expected %v, got %v", expected, result.Names)
	}

	// What the passive sources found is folded into what the active pass asks about.
	if !stub.askedFor("www.example.com") {
		t.Error("expected the passive names to be asked about too")
	}
}

// TestFindSkipsTheActivePassOnAWildcard holds the guard: a domain answering to every name would
// return the whole list as hits, all of them false.
func TestFindSkipsTheActivePassOnAWildcard(t *testing.T) {
	t.Parallel()

	stub := &stubResolver{wildcard: true}

	subdomainFinder := newFinder(
		t,
		[]string{"www.example.com"},
		"",
		finder_config.WithResolver(stub),
		finder_config.WithConcurrency(4),
	)

	result, err := subdomainFinder.Find(
		t.Context(),
		"example.com",
		slices.Values([]string{"vpn", "secret", "internal"}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Bruted {
		t.Error("expected the active pass to be skipped on a wildcard domain")
	}
	if !slices.Equal(result.Names, []string{"www.example.com"}) {
		t.Errorf("expected only the passive names, got %v", result.Names)
	}
	// Only the wildcard probe should have been asked about.
	if got := stub.askedCount(); got != 1 {
		t.Errorf("expected one lookup, the probe, got %d", got)
	}
}

func TestFindWithoutAResolver(t *testing.T) {
	t.Parallel()

	subdomainFinder := newFinder(t, []string{"www.example.com"}, "")

	result, err := subdomainFinder.Find(t.Context(), "example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Bruted {
		t.Error("expected no active pass without a resolver")
	}
	if !slices.Equal(result.Names, []string{"www.example.com"}) {
		t.Errorf("expected the passive names, got %v", result.Names)
	}
}

func TestFindArgumentChecks(t *testing.T) {
	t.Parallel()

	if _, err := finder.NewFinder().Find(t.Context(), "", nil); err == nil {
		t.Error("expected an empty domain to be an error")
	}

	var nilFinder *finder.Finder
	if _, err := nilFinder.Find(t.Context(), "example.com", nil); err == nil {
		t.Error("expected a nil finder to be an error")
	}
	if names := nilFinder.Passive(t.Context(), "example.com"); len(names) != 0 {
		t.Errorf("expected a nil finder to find nothing, got %v", names)
	}
}
