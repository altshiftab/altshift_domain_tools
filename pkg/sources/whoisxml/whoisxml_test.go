package whoisxml_test

import (
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml"
	whoisXmlTypes "github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml/types"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml/whoisxml_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

// serverClient is a client pointed at the test server, which is what a base URL in the config is
// for: the package no longer holds a mutable global, so these tests can run in parallel.
func serverClient(t *testing.T, server *httptest.Server) *whoisxml.Client {
	t.Helper()

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("could not parse the server url: %v", err)
	}

	return whoisxml.NewClient(
		whoisxml_config.WithBaseUrl(serverUrl),
		whoisxml_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
	)
}

func TestQueryReverseWhois(t *testing.T) {
	t.Parallel()

	var sent whoisXmlTypes.ReverseWhoisRequest
	var method string

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		method = request.Method

		body := make([]byte, request.ContentLength)
		_, _ = request.Body.Read(body)
		if err := json.Unmarshal(body, &sent); err != nil {
			t.Errorf("could not read the request: %v", err)
		}

		data, err := json.Marshal(&whoisXmlTypes.ReverseWhoisResponse{
			DomainsCount: 2,
			DomainsList:  []string{"example.net", "example.org"},
		})
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

	response, err := serverClient(t, server).QueryReverseWhois(
		t.Context(),
		&whoisXmlTypes.ReverseWhoisRequest{
			ApiKey:     "the-key",
			SearchType: whoisxml.SearchTypeCurrent,
			Mode:       whoisxml.ModePreview,
			AdvancedSearchTerms: []*whoisXmlTypes.AdvancedSearchTerms{
				{Field: "Email", Term: "*@example.com"},
			},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if response == nil {
		t.Fatal("expected a response, got nil")
	}

	// The API takes the search as a posted body rather than as query parameters.
	if method != http.MethodPost {
		t.Errorf("expected a POST, got %s", method)
	}
	if sent.ApiKey != "the-key" {
		t.Errorf("expected the api key to be sent in the body, got %q", sent.ApiKey)
	}
	if sent.Mode != whoisxml.ModePreview {
		t.Errorf("expected the mode to be sent, got %q", sent.Mode)
	}
	if len(sent.AdvancedSearchTerms) != 1 || sent.AdvancedSearchTerms[0].Term != "*@example.com" {
		t.Errorf("expected the search term to be sent, got %+v", sent.AdvancedSearchTerms)
	}

	if response.DomainsCount != 2 || len(response.DomainsList) != 2 {
		t.Errorf("expected both domains, got %+v", response)
	}
}

// TestModesAndSearchTypesAreDistinct holds the two pairs the API distinguishes. Preview reports how
// many domains match and purchase returns them, so confusing the two either bills for nothing or
// returns nothing.
func TestModesAndSearchTypesAreDistinct(t *testing.T) {
	t.Parallel()

	if whoisxml.ModePreview == whoisxml.ModePurchase {
		t.Error("expected preview and purchase to be different modes")
	}
	if whoisxml.SearchTypeCurrent == whoisxml.SearchTypeHistoric {
		t.Error("expected current and historic to be different search types")
	}
}

func TestQueryReverseWhoisArgumentChecks(t *testing.T) {
	t.Parallel()

	if _, err := whoisxml.NewClient().QueryReverseWhois(t.Context(), nil); err == nil {
		t.Error("expected nil request data to be an error")
	}

	var nilClient *whoisxml.Client
	if _, err := nilClient.QueryReverseWhois(t.Context(), &whoisXmlTypes.ReverseWhoisRequest{}); err == nil {
		t.Error("expected a nil client to be an error")
	}

	if _, _, err := whoisxml.NewClient().QueryReverseWhoisPages(t.Context(), nil, 1); err == nil {
		t.Error("expected nil request data to be an error")
	}
	if _, _, err := nilClient.QueryReverseWhoisPages(t.Context(), &whoisXmlTypes.ReverseWhoisRequest{}, 1); err == nil {
		t.Error("expected a nil client to be an error")
	}
}

// page is one response the paging server hands out: its domains, and the cursor it says the next
// page is behind.
type page struct {
	domains []string
	cursor  string
}

// pagingServer answers each request with the next page in turn, and records the cursor it was sent.
func pagingServer(t *testing.T, pages []page) (*httptest.Server, *[]string) {
	t.Helper()

	var (
		mutex        sync.Mutex
		searchAfters []string
	)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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

		mutex.Lock()
		index := len(searchAfters)
		searchAfters = append(searchAfters, sent.SearchAfter)
		mutex.Unlock()

		if index >= len(pages) {
			t.Errorf("the client asked for page %d, and only %d were laid out", index+1, len(pages))
			writer.WriteHeader(http.StatusInternalServerError)

			return
		}

		response := &whoisXmlTypes.ReverseWhoisResponse{
			DomainsCount: len(pages[index].domains),
			DomainsList:  pages[index].domains,
		}
		if cursor := pages[index].cursor; cursor != "" {
			response.NextPageSearchAfter = &cursor
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
	}))

	return server, &searchAfters
}

// TestQueryReverseWhoisPages holds what following the cursor is for. A search matching more domains
// than one response holds answers with a cursor rather than the rest, so a caller that reads one
// page and stops cannot tell a truncated answer from a whole one -- and neither can its caller.
func TestQueryReverseWhoisPages(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		pages             []page
		pageLimit         int
		expectedDomains   []string
		expectedTruncated bool
		expectedCursors   []string
	}{
		{
			name:            "a page without a cursor is the whole answer",
			pages:           []page{{domains: []string{"a.example"}}},
			pageLimit:       3,
			expectedDomains: []string{"a.example"},
			expectedCursors: []string{""},
		},
		{
			name: "a cursor is followed, and carried into the next request",
			pages: []page{
				{domains: []string{"a.example"}, cursor: "after-a"},
				{domains: []string{"b.example"}, cursor: "after-b"},
				{domains: []string{"c.example"}},
			},
			pageLimit:       5,
			expectedDomains: []string{"a.example", "b.example", "c.example"},
			expectedCursors: []string{"", "after-a", "after-b"},
		},
		{
			name: "the page limit stops the walk, and the answer says it is short",
			pages: []page{
				{domains: []string{"a.example"}, cursor: "after-a"},
				{domains: []string{"b.example"}, cursor: "after-b"},
			},
			pageLimit:         2,
			expectedDomains:   []string{"a.example", "b.example"},
			expectedTruncated: true,
			expectedCursors:   []string{"", "after-a"},
		},
		{
			name:              "a limit of zero reads the one page an unpaginated call read",
			pages:             []page{{domains: []string{"a.example"}, cursor: "after-a"}},
			pageLimit:         0,
			expectedDomains:   []string{"a.example"},
			expectedTruncated: true,
			expectedCursors:   []string{""},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			server, cursors := pagingServer(t, testCase.pages)
			defer server.Close()

			domains, truncated, err := serverClient(t, server).QueryReverseWhoisPages(
				t.Context(),
				&whoisXmlTypes.ReverseWhoisRequest{ApiKey: "the-key", Mode: whoisxml.ModePurchase},
				testCase.pageLimit,
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !slices.Equal(domains, testCase.expectedDomains) {
				t.Errorf("expected %v, got %v", testCase.expectedDomains, domains)
			}
			if truncated != testCase.expectedTruncated {
				t.Errorf("expected truncated to be %t, got %t", testCase.expectedTruncated, truncated)
			}
			if !slices.Equal(*cursors, testCase.expectedCursors) {
				t.Errorf("expected the cursors %v to be sent, got %v", testCase.expectedCursors, *cursors)
			}
		})
	}
}

// TestQueryReverseWhoisPagesKeepsWhatItBought records that a walk which fails part way through hands
// back the pages it did read. Every page is a purchase, and one already paid for is not worth
// discarding because the page after it failed.
func TestQueryReverseWhoisPagesKeepsWhatItBought(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if requests.Add(1) > 1 {
			writer.WriteHeader(http.StatusInternalServerError)

			return
		}

		cursor := "after-a"
		data, err := json.Marshal(&whoisXmlTypes.ReverseWhoisResponse{
			DomainsCount:        2,
			DomainsList:         []string{"a.example"},
			NextPageSearchAfter: &cursor,
		})
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

	// Without a retry config the failing page would be asked for again, on the back-off a rate limit
	// deserves, which is a long time to spend proving a 500 is still a 500.
	domains, truncated, err := serverClient(t, server).QueryReverseWhoisPages(
		t.Context(),
		&whoisXmlTypes.ReverseWhoisRequest{ApiKey: "the-key", Mode: whoisxml.ModePurchase},
		3,
		fetch_config.WithRetryConfig(nil),
	)
	if err == nil {
		t.Fatal("expected the failing page to be an error")
	}
	if !slices.Equal(domains, []string{"a.example"}) {
		t.Errorf("expected the page that was bought to be kept, got %v", domains)
	}
	if !truncated {
		t.Error("expected a walk that stopped early to report itself short")
	}
}

// TestRateLimitingIsRetried holds why a retry config is the default rather than something a caller
// remembers: the API counts the wildcard searches this client is here for against a limit of ten a
// minute, which an ordinary run reaches, and answers the eleventh with a 429.
func TestRateLimitingIsRetried(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if requests.Add(1) == 1 {
			// Answered with a delay of its own, so the test waits a second rather than the minute
			// the back-off would otherwise spend.
			writer.Header().Set("Retry-After", "0")
			writer.WriteHeader(http.StatusTooManyRequests)

			return
		}

		data, err := json.Marshal(&whoisXmlTypes.ReverseWhoisResponse{DomainsCount: 1, DomainsList: []string{"a.example"}})
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

	response, err := serverClient(t, server).QueryReverseWhois(
		t.Context(),
		&whoisXmlTypes.ReverseWhoisRequest{ApiKey: "the-key", Mode: whoisxml.ModePreview},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if response == nil || response.DomainsCount != 1 {
		t.Fatalf("expected the retried request to answer, got %+v", response)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("expected the rate limit to be waited out and the request repeated, got %d requests", got)
	}
}

// TestCallerRetryConfigWins records the ordering the default depends on: it is passed ahead of the
// client's options and the call's, so a caller with its own -- or with none, passing nil -- decides.
func TestCallerRetryConfigWins(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	_, err := serverClient(t, server).QueryReverseWhois(
		t.Context(),
		&whoisXmlTypes.ReverseWhoisRequest{ApiKey: "the-key"},
		fetch_config.WithRetryConfig(nil),
	)
	if err == nil {
		t.Fatal("expected the rate limit to be an error")
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("expected a caller asking for no retries to get none, got %d requests", got)
	}
}

// TestResponseErrorCarriesWhatTheApiSaid holds why the error body is read rather than thrown away
// with the status. On an API that bills, "non-2xx status code" is indistinguishable from a
// transient fault, and the two failures worth telling apart -- a field the API does not have, and a
// key it will not serve -- both say so in the body and in nothing else.
func TestResponseErrorCarriesWhatTheApiSaid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		statusCode      int
		body            string
		expectedMessage string
		expectedCode    int
		expectedIs      error
	}{
		{
			name:       "a rejected search field says which, under \"message\"",
			statusCode: http.StatusUnprocessableEntity,
			body:       `{"code":422,"message":"Invalid search field: RegistrantName"}`,
			// The name the API rejected is the whole value of the error, and is what a caller has to
			// see to fix the call.
			expectedMessage: "Invalid search field: RegistrantName",
			expectedCode:    422,
			expectedIs:      whoisxml.ErrInvalidRequest,
		},
		{
			name:       "a refused key says why, under \"messages\"",
			statusCode: http.StatusForbidden,
			body:       `{"code":403,"messages":"Access restricted. Reasons: insufficient credits balance"}`,
			// The API uses the plural name for this one and the singular for the other; both are the
			// message.
			expectedMessage: "Access restricted. Reasons: insufficient credits balance",
			expectedCode:    403,
			expectedIs:      whoisxml.ErrAccessRestricted,
		},
		{
			name:            "a body in no known shape is carried as it stands",
			statusCode:      http.StatusBadGateway,
			body:            "<html>upstream is unwell</html>",
			expectedMessage: "<html>upstream is unwell</html>",
		},
		{
			name:       "and an empty one leaves the status to say it",
			statusCode: http.StatusTeapot,
			body:       "",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(testCase.statusCode)
				if _, err := writer.Write([]byte(testCase.body)); err != nil {
					t.Errorf("could not write: %v", err)
				}
			}))
			defer server.Close()

			// Neither status retries, so nothing here waits; the config is off regardless, a test
			// that means to see a failure not being served by seeing it three times.
			_, err := serverClient(t, server).QueryReverseWhois(
				t.Context(),
				&whoisXmlTypes.ReverseWhoisRequest{ApiKey: "the-key"},
				fetch_config.WithRetryConfig(nil),
			)
			if err == nil {
				t.Fatal("expected the failure to be an error")
			}

			responseError, ok := errors.AsType[*whoisxml.ResponseError](err)
			if !ok {
				t.Fatalf("expected a response error, got %v", err)
			}

			if responseError.StatusCode != testCase.statusCode {
				t.Errorf("expected status %d, got %d", testCase.statusCode, responseError.StatusCode)
			}
			if responseError.Code != testCase.expectedCode {
				t.Errorf("expected code %d, got %d", testCase.expectedCode, responseError.Code)
			}
			if responseError.Message != testCase.expectedMessage {
				t.Errorf("expected the message %q, got %q", testCase.expectedMessage, responseError.Message)
			}

			// The message reaches whatever prints the error, which is the whole point.
			if testCase.expectedMessage != "" && !strings.Contains(err.Error(), testCase.expectedMessage) {
				t.Errorf("expected the message in %q", err.Error())
			}

			if testCase.expectedIs != nil && !errors.Is(err, testCase.expectedIs) {
				t.Errorf("expected the error to be %v", testCase.expectedIs)
			}
			// A failure that will not clear is not one that merely might.
			if testCase.expectedIs == nil && errors.Is(err, whoisxml.ErrAccessRestricted) {
				t.Error("expected an unknown status not to be sorted as a refused key")
			}
		})
	}
}

// TestPunycodeIsAskedForExplicitly holds why the field is a pointer. The API defaults punycode to
// true, so a plain bool omitted when zero can ask for what is already the default and can never ask
// for the opposite -- a caller setting it to false would silently get true.
func TestPunycodeIsAskedForExplicitly(t *testing.T) {
	t.Parallel()

	unset, err := json.Marshal(&whoisXmlTypes.ReverseWhoisRequest{ApiKey: "the-key"})
	if err != nil {
		t.Fatalf("could not marshal: %v", err)
	}
	if strings.Contains(string(unset), "punycode") {
		t.Errorf("expected an unset punycode to be left to the API's own default, got %s", unset)
	}

	off := false
	turnedOff, err := json.Marshal(&whoisXmlTypes.ReverseWhoisRequest{ApiKey: "the-key", Punycode: &off})
	if err != nil {
		t.Fatalf("could not marshal: %v", err)
	}
	if !strings.Contains(string(turnedOff), `"punycode":false`) {
		t.Errorf("expected punycode to be turned off, got %s", turnedOff)
	}
}
