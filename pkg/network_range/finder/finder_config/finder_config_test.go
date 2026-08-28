package finder_config

import (
	"context"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripe"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

// stubResolver stands in for a resolver, so the option can be checked without one.
type stubResolver struct{}

func (*stubResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }

func TestNew(t *testing.T) {
	t.Parallel()

	// No options is the ordinary call: the finder builds its own registry client and uses
	// net.DefaultResolver, so the config leaving them nil is what says "unset".
	empty := New()
	if empty == nil {
		t.Fatal("expected a config, got nil")
	}
	if empty.Ripe != nil || empty.Resolver != nil || len(empty.FetchOptions) != 0 {
		t.Errorf("expected everything unset, got %+v", empty)
	}

	// A nil option is skipped rather than panicking, so a caller can pass one conditionally.
	if New(nil) == nil {
		t.Error("expected a nil option to be skipped")
	}

	ripeClient := ripe.NewClient()
	resolver := &stubResolver{}

	config := New(
		WithRipe(ripeClient),
		WithResolver(resolver),
		WithFetchOptions(fetch_config.WithMethod("GET")),
		// Accumulating rather than replacing: two calls are how a caller adds to what an earlier
		// one set, and replacing would silently drop it.
		WithFetchOptions(fetch_config.WithMethod("POST")),
	)

	if config.Ripe != ripeClient {
		t.Error("expected the registry client to be taken")
	}
	if config.Resolver != resolver {
		t.Error("expected the resolver to be taken")
	}
	if len(config.FetchOptions) != 2 {
		t.Errorf("expected the fetch options to accumulate, got %d", len(config.FetchOptions))
	}
}
