package finder_config

import (
	"context"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/crtsh"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/hackertarget"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

// stubResolver stands in for a resolver, so the option can be checked without one.
type stubResolver struct{}

func (*stubResolver) DomainExists(context.Context, string) (bool, error) { return false, nil }

func TestNew(t *testing.T) {
	t.Parallel()

	// No options is the ordinary call: the finder builds its own source clients, so the config
	// leaving them nil is what says "unset" rather than "no source".
	empty := New()
	if empty == nil {
		t.Fatal("expected a config, got nil")
	}
	if empty.Crtsh != nil || empty.HackerTarget != nil || empty.Resolver != nil {
		t.Errorf("expected everything unset, got %+v", empty)
	}
	if empty.Concurrency != 0 || len(empty.FetchOptions) != 0 {
		t.Errorf("expected everything unset, got %+v", empty)
	}

	// A nil option is skipped rather than panicking, so a caller can pass one conditionally.
	if New(nil) == nil {
		t.Error("expected a nil option to be skipped")
	}

	crtshClient := crtsh.NewClient()
	hackerTargetClient := hackertarget.NewClient()
	resolver := &stubResolver{}

	config := New(
		WithCrtsh(crtshClient),
		WithHackerTarget(hackerTargetClient),
		WithResolver(resolver),
		WithConcurrency(7),
		WithFetchOptions(fetch_config.WithMethod("GET")),
		// Accumulating rather than replacing: two calls are how a caller adds to what an earlier
		// one set, and replacing would silently drop it.
		WithFetchOptions(fetch_config.WithMethod("POST")),
	)

	if config.Crtsh != crtshClient {
		t.Error("expected the crtsh client to be taken")
	}
	if config.HackerTarget != hackerTargetClient {
		t.Error("expected the hackertarget client to be taken")
	}
	if config.Resolver != resolver {
		t.Error("expected the resolver to be taken")
	}
	if config.Concurrency != 7 {
		t.Errorf("expected the concurrency to be taken, got %d", config.Concurrency)
	}
	if len(config.FetchOptions) != 2 {
		t.Errorf("expected the fetch options to accumulate, got %d", len(config.FetchOptions))
	}
}
