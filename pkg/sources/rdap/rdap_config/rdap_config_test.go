package rdap_config

import (
	"net/url"
	"testing"

	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

func TestNew(t *testing.T) {
	t.Parallel()

	baseUrl := &url.URL{Scheme: "https", Host: "example.test"}

	// No options is a client with no server, which is an error rather than a default: RDAP is a
	// protocol several registries answer, and there is none this could sensibly mean.
	empty := New()
	if empty == nil {
		t.Fatal("expected a config, got nil")
	}
	if empty.BaseUrl != nil || empty.NameSuffix != "" || empty.MaxNames != 0 ||
		empty.MaxEntities != 0 || len(empty.FetchOptions) != 0 {
		t.Errorf("expected everything unset, got %+v", empty)
	}

	// A nil option is skipped rather than panicking, so a caller can pass one conditionally.
	if New(nil) == nil {
		t.Error("expected a nil option to be skipped")
	}

	config := New(
		WithBaseUrl(baseUrl),
		WithNameSuffix("*"),
		WithMaxNames(4),
		WithMaxEntities(7),
		WithFetchOptions(fetch_config.WithMethod("GET")),
		// Accumulating rather than replacing: two calls are how a caller adds to what an earlier
		// one set, and replacing would silently drop it.
		WithFetchOptions(fetch_config.WithMethod("POST")),
	)

	if config.BaseUrl != baseUrl {
		t.Errorf("expected the base url to be taken, got %v", config.BaseUrl)
	}
	// The suffix is a setting because the registries do not agree on how a name search matches.
	if config.NameSuffix != "*" {
		t.Errorf("expected the name suffix to be taken, got %q", config.NameSuffix)
	}
	if config.MaxNames != 4 || config.MaxEntities != 7 {
		t.Errorf("expected the bounds to be taken, got %+v", config)
	}
	if len(config.FetchOptions) != 2 {
		t.Errorf("expected the fetch options to accumulate, got %d", len(config.FetchOptions))
	}
}
