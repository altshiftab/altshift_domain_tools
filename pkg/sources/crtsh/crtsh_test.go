package crtsh

import (
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/crtsh/crtsh_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

// serverClient is a client pointed at the test server, which is what a base URL in the config is
// for: the package no longer holds a mutable global, so these tests can run in parallel.
func serverClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("could not parse the server url: %v", err)
	}

	return NewClient(
		crtsh_config.WithBaseUrl(serverUrl),
		crtsh_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
	)
}

func TestNames(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		results []*Result
		domain  string
		expect  []string
	}{
		{name: "nothing", domain: "example.com", expect: []string{}},
		{
			name:    "the names of a certificate, one per line",
			results: []*Result{{NameValue: "www.example.com\nmail.example.com"}},
			domain:  "example.com",
			expect:  []string{"www.example.com", "mail.example.com"},
		},
		{
			// A host appears on every certificate ever issued for it, so the log answers with far
			// more rows than names.
			name: "the same name on several certificates is one name",
			results: []*Result{
				{NameValue: "www.example.com"},
				{NameValue: "www.example.com"},
			},
			domain: "example.com",
			expect: []string{"www.example.com"},
		},
		{
			// "*.example.com" is not a host that exists.
			name:    "a wildcard is not a host",
			results: []*Result{{NameValue: "*.example.com\nwww.example.com"}},
			domain:  "example.com",
			expect:  []string{"www.example.com"},
		},
		{
			// A log search matches on a pattern, and a pattern can match a name that is not under
			// the domain at all.
			name:    "a name that is not under the domain is left out",
			results: []*Result{{NameValue: "www.example.com.evil.test\nwww.example.com"}},
			domain:  "example.com",
			expect:  []string{"www.example.com"},
		},
		{
			name:    "the domain itself is not one of its own subdomains",
			results: []*Result{{NameValue: "example.com\nwww.example.com"}},
			domain:  "example.com",
			expect:  []string{"www.example.com"},
		},
		{
			name:    "names are lower-cased",
			results: []*Result{{NameValue: "WWW.Example.COM"}},
			domain:  "example.com",
			expect:  []string{"www.example.com"},
		},
		{name: "a nil result is skipped", results: []*Result{nil}, domain: "example.com", expect: []string{}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := Names(testCase.results, testCase.domain)

			slices.Sort(got)
			expected := slices.Clone(testCase.expect)
			slices.Sort(expected)

			if !slices.Equal(got, expected) {
				t.Errorf("%s: expected %v, got %v", testCase.name, expected, got)
			}
		})
	}
}

func TestQuery(t *testing.T) {
	t.Parallel()

	var asked map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		asked = map[string]string{"q": query.Get("q"), "output": query.Get("output")}

		data, err := json.Marshal([]*Result{{NameValue: "www.example.com", CommonName: "www.example.com"}})
		if err != nil {
			t.Errorf("could not marshal: %v", err)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if _, err := writer.Write(data); err != nil {
			t.Errorf("could not write: %v", err)
		}
	}))
	defer server.Close()

	results, err := serverClient(t, server).Query(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	// The leading "%." is the log's wildcard: without it the search returns the domain alone.
	if expected := "%.example.com"; asked["q"] != expected {
		t.Errorf("expected the query %q, got %q", expected, asked["q"])
	}
	if asked["output"] != "json" {
		t.Errorf("expected json output to be asked for, got %q", asked["output"])
	}
}

func TestQueryArgumentChecks(t *testing.T) {
	t.Parallel()

	var nilClient *Client
	if _, err := nilClient.Query(t.Context(), "example.com"); err == nil {
		t.Error("expected a nil client to be an error")
	}

	results, err := NewClient().Query(t.Context(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Errorf("expected an empty domain to search nothing, got %d", len(results))
	}
}

// TestQueryRetries holds that a query crt.sh turns away for being busy is made again once the wait it
// advises is over, and that one it answers for good -- a 404 -- is not.
func TestQueryRetries(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		first         int
		expectErr     bool
		expectedCalls int32
	}{
		{name: "busy, then answered", first: http.StatusTooManyRequests, expectedCalls: 2},
		{name: "a server error, then answered", first: http.StatusBadGateway, expectedCalls: 2},
		{name: "not found is an answer", first: http.StatusNotFound, expectErr: true, expectedCalls: 1},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) == 1 {
					// The shortest wait the header can advise, so the test is not slow.
					writer.Header().Set("Retry-After", "0")
					writer.WriteHeader(testCase.first)

					return
				}

				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(`[]`))
			}))
			t.Cleanup(server.Close)

			_, err := serverClient(t, server).Query(t.Context(), "example.com")
			if (err != nil) != testCase.expectErr {
				t.Fatalf("got error %v, expected an error: %v", err, testCase.expectErr)
			}

			if got := calls.Load(); got != testCase.expectedCalls {
				t.Errorf("got %d requests, expected %d", got, testCase.expectedCalls)
			}
		})
	}
}

// slowServer answers after delay, or not at all if the request is given up on first.
func slowServer(t *testing.T, delay *atomic.Int64, calls *atomic.Int32) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)

		select {
		case <-time.After(time.Duration(delay.Load())):
		case <-request.Context().Done():
			return
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`[]`))
	}))
	t.Cleanup(server.Close)

	return server
}

func clientFor(t *testing.T, server *httptest.Server, httpClient *http.Client, options ...crtsh_config.Option) *Client {
	t.Helper()

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url parse: %v", err)
	}

	return NewClient(append([]crtsh_config.Option{
		crtsh_config.WithBaseUrl(serverUrl),
		crtsh_config.WithFetchOptions(fetch_config.WithHttpClient(httpClient)),
	}, options...)...)
}

// TestQueryTakesItsOwnTimeout holds that a query is bounded by the client's timeout rather than by
// that of a client the caller shares with faster sources: the monitor's thirty seconds cut crt.sh
// off for domains with many certificates.
func TestQueryTakesItsOwnTimeout(t *testing.T) {
	t.Parallel()

	var (
		delay atomic.Int64
		calls atomic.Int32
	)
	delay.Store(int64(200 * time.Millisecond))
	server := slowServer(t, &delay, &calls)

	callerClient := server.Client()
	callerClient.Timeout = 50 * time.Millisecond

	client := clientFor(t, server, callerClient, crtsh_config.WithRequestTimeout(2*time.Second))

	if _, err := client.Query(t.Context(), "example.com"); err != nil {
		t.Fatalf("expected the query to outlast the caller's timeout, got %v", err)
	}
}

// TestQueryCoolsDownAfterATimeout holds the guard on that longer timeout: a timed-out query is not
// retried, the queries that follow are turned away without a request until the cool-down is over,
// and then they are made again.
func TestQueryCoolsDownAfterATimeout(t *testing.T) {
	t.Parallel()

	var (
		delay atomic.Int64
		calls atomic.Int32
	)
	delay.Store(int64(time.Second))
	server := slowServer(t, &delay, &calls)

	client := clientFor(
		t,
		server,
		server.Client(),
		crtsh_config.WithRequestTimeout(100*time.Millisecond),
		crtsh_config.WithTimeoutCooldown(300*time.Millisecond),
	)

	if _, err := client.Query(t.Context(), "example.com"); err == nil {
		t.Fatal("expected the query to time out")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("got %d requests, expected a timed-out query not retried", got)
	}

	if _, err := client.Query(t.Context(), "example.org"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected the next query turned away, got %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("got %d requests, expected none while cooling down", got)
	}

	delay.Store(0)
	time.Sleep(400 * time.Millisecond)

	if _, err := client.Query(t.Context(), "example.net"); err != nil {
		t.Fatalf("expected a query after the cool-down to be made, got %v", err)
	}
}
