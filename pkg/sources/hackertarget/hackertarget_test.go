package hackertarget

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/hackertarget/hackertarget_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

// serverClient is a client pointed at the test server, which is what a base URL in the config is
// for: the package no longer holds mutable globals, so these tests can run in parallel.
func serverClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("could not parse the server url: %v", err)
	}

	return NewClient(
		hackertarget_config.WithBaseUrl(serverUrl),
		hackertarget_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
	)
}

func TestQuery(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != HostSearchPath {
			t.Errorf("expected the host search path, got %q", request.URL.Path)
		}
		if got := request.URL.Query().Get("q"); got != "example.com" {
			t.Errorf("expected the domain to be sent, got %q", got)
		}
		// The counters come from headers rather than the body.
		writer.Header().Set("x-api-quota", "100")
		writer.Header().Set("x-api-count", "7")
		if _, err := writer.Write([]byte("www.example.com,192.0.2.1\nmail.example.com,192.0.2.2\n")); err != nil {
			t.Errorf("could not write: %v", err)
		}
	}))
	defer server.Close()

	response, err := serverClient(t, server).Query(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if response == nil {
		t.Fatal("expected a response, got nil")
	}

	if len(response.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(response.Results))
	}
	if response.Results[0].Domain != "www.example.com" || response.Results[0].IpAddress != "192.0.2.1" {
		t.Errorf("expected the name and the address to be split apart, got %+v", response.Results[0])
	}
	// The free tier is metered, so what is left of the allowance is worth carrying back.
	if response.ApiQuota != 100 || response.ApiCount != 7 {
		t.Errorf("expected the quota counters, got quota=%d count=%d", response.ApiQuota, response.ApiCount)
	}
}

// TestQueryReadsThePlainTextRefusals holds what a status code does not catch: the API reports both
// of these with a 200 and a sentence in the body.
func TestQueryReadsThePlainTextRefusals(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		body   string
		expect error
	}{
		{name: "an invalid host", body: "error invalid host", expect: ErrInvalidHost},
		{
			name:   "an exhausted quota",
			body:   "API count exceeded - Increase Quota with Membership",
			expect: ErrQuotaExceeded,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if _, err := writer.Write([]byte(testCase.body)); err != nil {
					t.Errorf("could not write: %v", err)
				}
			}))
			defer server.Close()

			_, err := serverClient(t, server).Query(t.Context(), "example.com")
			if err == nil {
				t.Fatalf("%s: expected an error, got none", testCase.name)
			}
			if !errors.Is(err, testCase.expect) {
				t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expect, err)
			}
		})
	}
}

func TestNames(t *testing.T) {
	t.Parallel()

	response := &Response{
		Results: []*Result{
			{Domain: "www.example.com"},
			{Domain: "WWW.example.com"},
			// Not under the domain: the search can answer with these.
			{Domain: "other.test"},
			{Domain: ""},
			nil,
		},
	}

	names := Names(response, "example.com")
	if !slices.Equal(names, []string{"www.example.com"}) {
		t.Errorf("expected the one distinct name under the domain, got %v", names)
	}

	if Names(nil, "example.com") != nil {
		t.Error("expected no names from a nil response")
	}
}

func TestQueryReverseIp(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != ReverseIpPath {
			t.Errorf("expected the reverse ip path, got %q", request.URL.Path)
		}
		query := request.URL.Query()
		if got := query.Get("q"); got != "192.0.2.1" {
			t.Errorf("expected the address to be sent, got %q", got)
		}
		if got := query.Get("apikey"); got != "the-key" {
			t.Errorf("expected the api key to be sent, got %q", got)
		}
		if _, err := writer.Write([]byte("example.com\nExample.net\n\n")); err != nil {
			t.Errorf("could not write: %v", err)
		}
	}))
	defer server.Close()

	names, err := serverClient(t, server).QueryReverseIp(t.Context(), net.ParseIP("192.0.2.1"), "the-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(names, []string{"example.com", "example.net"}) {
		t.Errorf("expected the names lower-cased with blanks dropped, got %v", names)
	}
}

// TestQueryReverseIpRejectsIpv6 holds the endpoint's limit: it is IPv4 only, and an IPv6 address is
// a caller mistake rather than a lookup that found nothing.
func TestQueryReverseIpRejectsIpv6(t *testing.T) {
	t.Parallel()

	_, err := NewClient().QueryReverseIp(t.Context(), net.ParseIP("2001:db8::1"), "the-key")
	if err == nil {
		t.Fatal("expected an IPv6 address to be refused, got no error")
	}

	var notIpv4Error *NotIpv4Error
	if !errors.As(err, &notIpv4Error) {
		t.Errorf("expected a NotIpv4Error, got %v", err)
	}
}

func TestArgumentChecks(t *testing.T) {
	t.Parallel()

	var nilClient *Client
	if _, err := nilClient.Query(t.Context(), "example.com"); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if _, err := NewClient().QueryReverseIp(t.Context(), net.ParseIP("192.0.2.1"), ""); err == nil {
		t.Error("expected an empty api key to be an error")
	}

	response, err := NewClient().Query(t.Context(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if response != nil {
		t.Error("expected an empty domain to search nothing")
	}
}
