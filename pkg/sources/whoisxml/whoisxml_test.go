package whoisxml_test

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
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
}
