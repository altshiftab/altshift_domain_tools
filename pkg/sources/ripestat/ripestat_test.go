package ripestat

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripestat/ripestat_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

func serverClient(t *testing.T, handler http.HandlerFunc, options ...ripestat_config.Option) *Client {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("could not parse the server url: %v", err)
	}

	return NewClient(
		slices.Concat(
			[]ripestat_config.Option{
				ripestat_config.WithBaseUrl(serverUrl),
				ripestat_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
			},
			options,
		)...,
	)
}

func write(t *testing.T, writer http.ResponseWriter, body string) {
	t.Helper()

	writer.Header().Set("Content-Type", "application/json")
	if _, err := fmt.Fprint(writer, body); err != nil {
		t.Errorf("could not write: %v", err)
	}
}

// TestRoas holds what an authorisation is: the address holder signing that the network may
// originate the prefix, which is a statement about whose the addresses are.
func TestRoas(t *testing.T) {
	t.Parallel()

	var asked url.Values

	client := serverClient(t, func(writer http.ResponseWriter, request *http.Request) {
		asked = request.URL.Query()
		write(t, writer, `{"data":{"roas":[
			{"asn":"13335","prefix":"1.1.1.0/24","maxLength":24,"ta":"APNIC RPKI Root"},
			{"asn":"13335","prefix":"2606:4700::/32","maxLength":48,"ta":"ARIN RPKI Root"},
			{"asn":"13335","prefix":"1.1.1.0/24","maxLength":24,"ta":"APNIC RPKI Root"},
			{"asn":"64500","prefix":"192.0.2.0/24","maxLength":24,"ta":"Someone Else"}
		]}}`)
	})

	roas, err := client.Roas(t.Context(), "AS13335")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The one prefix once, and the other network's not at all: the service answers about what was
	// asked for, and a caller reading these alongside another network's should not have to trust it.
	if !slices.Equal(Prefixes(roas), []string{"1.1.1.0/24", "2606:4700::/32"}) {
		t.Fatalf("expected the network's own authorisations, got %v", Prefixes(roas))
	}

	if roas[0].MaxLength != 24 || roas[0].TrustAnchor != "APNIC RPKI Root" {
		t.Errorf("expected the authorisation's own detail kept, got %+v", roas[0])
	}

	// The number is written the one way whatever a caller passed.
	if resource := asked.Get("resource"); resource != "AS13335" {
		t.Errorf("expected the number normalised, got %q", resource)
	}
	// The service asks callers to identify themselves and answers one that does more generously.
	if asked.Get("sourceapp") != DefaultSourceApp {
		t.Errorf("expected the caller identified, got %q", asked.Get("sourceapp"))
	}
}

// TestAnnouncedPrefixes holds the weaker answer. It is an observation of what is being routed, which
// a transit provider's network makes about its customers' space as readily as about its own.
func TestAnnouncedPrefixes(t *testing.T) {
	t.Parallel()

	client := serverClient(t, func(writer http.ResponseWriter, _ *http.Request) {
		write(t, writer, `{"data":{"prefixes":[
			{"prefix":"104.16.0.0/12"},
			{"prefix":"2606:4700::/32"},
			{"prefix":"104.16.0.0/12"},
			{"prefix":"not a prefix"}
		]}}`)
	})

	prefixes, err := client.AnnouncedPrefixes(t.Context(), "13335")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Sorted and deduplicated, and what does not read as a prefix is dropped rather than passed on.
	if !slices.Equal(prefixes, []string{"104.16.0.0/12", "2606:4700::/32"}) {
		t.Errorf("expected the prefixes read, got %v", prefixes)
	}
}

// TestBounds holds why the bound is there: a large network announces tens of thousands of prefixes,
// and a party is not better attributed by the last of them than by the first.
func TestBounds(t *testing.T) {
	t.Parallel()

	client := serverClient(
		t,
		func(writer http.ResponseWriter, request *http.Request) {
			if strings.Contains(request.URL.Path, RoasPath) {
				roas := make([]string, 0, 10)
				for index := range 10 {
					roas = append(
						roas,
						fmt.Sprintf(`{"asn":"13335","prefix":"10.%d.0.0/16","maxLength":16}`, index),
					)
				}
				write(t, writer, `{"data":{"roas":[`+strings.Join(roas, ",")+`]}}`)

				return
			}

			prefixes := make([]string, 0, 10)
			for index := range 10 {
				prefixes = append(prefixes, fmt.Sprintf(`{"prefix":"10.%d.0.0/16"}`, index))
			}
			write(t, writer, `{"data":{"prefixes":[`+strings.Join(prefixes, ",")+`]}}`)
		},
		ripestat_config.WithMaxPrefixes(3),
	)

	roas, err := client.Roas(t.Context(), "AS13335")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roas) != 3 {
		t.Errorf("expected the bound to hold, got %d", len(roas))
	}

	prefixes, err := client.AnnouncedPrefixes(t.Context(), "AS13335")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(prefixes) != 3 {
		t.Errorf("expected the bound to hold, got %d", len(prefixes))
	}
}

func TestEmptyAnswers(t *testing.T) {
	t.Parallel()

	client := serverClient(t, func(writer http.ResponseWriter, _ *http.Request) {
		write(t, writer, `{}`)
	})

	roas, err := client.Roas(t.Context(), "AS13335")
	if err != nil || len(roas) != 0 {
		t.Errorf("expected nothing, got %v and %v", roas, err)
	}

	prefixes, err := client.AnnouncedPrefixes(t.Context(), "AS13335")
	if err != nil || len(prefixes) != 0 {
		t.Errorf("expected nothing, got %v and %v", prefixes, err)
	}
}

func TestArgumentChecks(t *testing.T) {
	t.Parallel()

	var nilClient *Client
	if _, err := nilClient.Roas(t.Context(), "AS13335"); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if _, err := nilClient.AnnouncedPrefixes(t.Context(), "AS13335"); err == nil {
		t.Error("expected a nil client to be an error")
	}

	client := NewClient()
	for _, value := range []string{"", "nonsense", "AS"} {
		if _, err := client.Roas(t.Context(), value); err == nil {
			t.Errorf("expected %q to be an error", value)
		}
		if _, err := client.AnnouncedPrefixes(t.Context(), value); err == nil {
			t.Errorf("expected %q to be an error", value)
		}
	}
}

func TestPrefixes(t *testing.T) {
	t.Parallel()

	if got := Prefixes(nil); len(got) != 0 {
		t.Errorf("expected nothing, got %v", got)
	}

	got := Prefixes([]*Roa{{Prefix: "10.0.0.0/8"}, nil, {Prefix: ""}, {Prefix: "10.0.0.0/8"}})
	if !slices.Equal(got, []string{"10.0.0.0/8"}) {
		t.Errorf("expected the one prefix, got %v", got)
	}
}
