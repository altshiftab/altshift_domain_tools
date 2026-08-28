package ripe_config

import (
	"net/url"
	"testing"

	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

func TestNew(t *testing.T) {
	t.Parallel()

	baseUrl := &url.URL{Scheme: "https", Host: "example.test"}

	// No options is the ordinary call: the client fills in the public database, so the config
	// leaving the base URL nil is what says "unset" rather than "the empty URL".
	empty := New()
	if empty == nil {
		t.Fatal("expected a config, got nil")
	}
	if empty.BaseUrl != nil || empty.MaxPersons != 0 || len(empty.FetchOptions) != 0 {
		t.Errorf("expected everything unset, got %+v", empty)
	}

	// A nil option is skipped rather than panicking, so a caller can pass one conditionally.
	if New(nil) == nil {
		t.Error("expected a nil option to be skipped")
	}

	config := New(
		WithBaseUrl(baseUrl),
		WithMaxPersons(5),
		WithFetchOptions(fetch_config.WithMethod("GET")),
		// Accumulating rather than replacing: two calls are how a caller adds to what an earlier
		// one set, and replacing would silently drop it.
		WithFetchOptions(fetch_config.WithMethod("POST")),
	)

	if config.BaseUrl != baseUrl {
		t.Errorf("expected the base url to be taken, got %v", config.BaseUrl)
	}
	// The bound matters because the two search steps multiply: every handle becomes a query.
	if config.MaxPersons != 5 {
		t.Errorf("expected the bound to be taken, got %d", config.MaxPersons)
	}
	if len(config.FetchOptions) != 2 {
		t.Errorf("expected the fetch options to accumulate, got %d", len(config.FetchOptions))
	}
}
