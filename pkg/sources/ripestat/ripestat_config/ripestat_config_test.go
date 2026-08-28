package ripestat_config

import (
	"net/url"
	"testing"

	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

func TestNew(t *testing.T) {
	t.Parallel()

	baseUrl := &url.URL{Scheme: "https", Host: "example.test"}

	// No options is the ordinary call: the client fills in the public service and its own bounds, so
	// the config leaving them zero is what says "unset".
	empty := New()
	if empty == nil {
		t.Fatal("expected a config, got nil")
	}
	if empty.BaseUrl != nil || empty.SourceApp != "" || empty.MaxPrefixes != 0 ||
		len(empty.FetchOptions) != 0 {
		t.Errorf("expected everything unset, got %+v", empty)
	}

	// A nil option is skipped rather than panicking, so a caller can pass one conditionally.
	if New(nil) == nil {
		t.Error("expected a nil option to be skipped")
	}

	config := New(
		WithBaseUrl(baseUrl),
		WithSourceApp("something"),
		WithMaxPrefixes(9),
		WithFetchOptions(fetch_config.WithMethod("GET")),
		// Accumulating rather than replacing: two calls are how a caller adds to what an earlier
		// one set, and replacing would silently drop it.
		WithFetchOptions(fetch_config.WithMethod("POST")),
	)

	if config.BaseUrl != baseUrl {
		t.Errorf("expected the base url to be taken, got %v", config.BaseUrl)
	}
	// The service asks callers to identify themselves and answers one that does more generously.
	if config.SourceApp != "something" {
		t.Errorf("expected the source app to be taken, got %q", config.SourceApp)
	}
	// The bound matters because a large network announces tens of thousands of prefixes.
	if config.MaxPrefixes != 9 {
		t.Errorf("expected the bound to be taken, got %d", config.MaxPrefixes)
	}
	if len(config.FetchOptions) != 2 {
		t.Errorf("expected the fetch options to accumulate, got %d", len(config.FetchOptions))
	}
}
