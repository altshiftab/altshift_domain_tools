package finder_config

import (
	"context"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/inference"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/arin"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/rdap"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripe"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whois"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

// apnic is a method a route is declared under. The finder owns the names; this package only keys by
// them, so any would do.
const apnic inference.Method = "apnic registry"

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
	if empty.Ripe != nil || empty.Arin != nil || empty.Resolver != nil ||
		len(empty.Whois) != 0 || len(empty.Rdap) != 0 || len(empty.FetchOptions) != 0 {
		t.Errorf("expected everything unset, got %+v", empty)
	}

	// A nil option is skipped rather than panicking, so a caller can pass one conditionally.
	if New(nil) == nil {
		t.Error("expected a nil option to be skipped")
	}

	ripeClient := ripe.NewClient()
	arinClient := arin.NewClient()
	whoisClient := whois.NewClient(whois.ApnicHost)
	rdapClient := rdap.NewClient()
	resolver := &stubResolver{}

	config := New(
		WithRipe(ripeClient),
		WithArin(arinClient),
		WithWhois(apnic, whoisClient),
		WithRdap(apnic, rdapClient),
		WithResolver(resolver),
		WithFetchOptions(fetch_config.WithMethod("GET")),
		// Accumulating rather than replacing: two calls are how a caller adds to what an earlier
		// one set, and replacing would silently drop it.
		WithFetchOptions(fetch_config.WithMethod("POST")),
	)

	if config.Ripe != ripeClient || config.Arin != arinClient {
		t.Error("expected the registry clients to be taken")
	}
	// Keyed by the method their ranges are attributed to, so that a caller supplying one route for a
	// registry and both for another gets what it asked for either way.
	if config.Whois[apnic] != whoisClient {
		t.Errorf("expected the whois client under its method, got %+v", config.Whois)
	}
	if config.Rdap[apnic] != rdapClient {
		t.Errorf("expected the rdap client under its method, got %+v", config.Rdap)
	}
	if config.Resolver != resolver {
		t.Error("expected the resolver to be taken")
	}
	if len(config.FetchOptions) != 2 {
		t.Errorf("expected the fetch options to accumulate, got %d", len(config.FetchOptions))
	}
}

// TestRouteMapsAccumulate holds that the two routes are declared one registry at a time: a caller
// naming a second must not lose the first, and the maps are built on the first call rather than
// having to exist already.
func TestRouteMapsAccumulate(t *testing.T) {
	t.Parallel()

	const afrinic inference.Method = "afrinic registry"

	config := New(
		WithWhois(apnic, whois.NewClient(whois.ApnicHost)),
		WithWhois(afrinic, whois.NewClient(whois.AfrinicHost)),
		WithRdap(apnic, rdap.NewClient()),
		WithRdap(afrinic, rdap.NewClient()),
	)

	if len(config.Whois) != 2 || len(config.Rdap) != 2 {
		t.Errorf("expected both registries kept, got %d whois and %d rdap", len(config.Whois), len(config.Rdap))
	}
	if config.Whois[apnic].Host() != whois.ApnicHost || config.Whois[afrinic].Host() != whois.AfrinicHost {
		t.Error("expected each client under its own method")
	}
}
