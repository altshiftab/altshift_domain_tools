package related_config

import (
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/hackertarget"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

func TestNew(t *testing.T) {
	t.Parallel()

	// No options is the ordinary call: the finder builds its own source clients, so the config
	// leaving them nil is what says "unset" rather than "no source".
	empty := New()
	if empty == nil {
		t.Fatal("expected a config, got nil")
	}
	if empty.WhoisXml != nil || empty.HackerTarget != nil {
		t.Errorf("expected the clients unset, got %+v", empty)
	}
	if empty.WhoisXmlApiKey != "" || empty.HackerTargetApiKey != "" {
		t.Errorf("expected the keys unset, got %+v", empty)
	}
	// Zero means the default limit rather than a limit of zero, which would discard every answer.
	if empty.SharedHostingDomainLimit != 0 || len(empty.FetchOptions) != 0 {
		t.Errorf("expected everything unset, got %+v", empty)
	}

	// A nil option is skipped rather than panicking, so a caller can pass one conditionally.
	if New(nil) == nil {
		t.Error("expected a nil option to be skipped")
	}

	whoisXmlClient := whoisxml.NewClient()
	hackerTargetClient := hackertarget.NewClient()

	config := New(
		WithWhoisXml(whoisXmlClient),
		WithHackerTarget(hackerTargetClient),
		WithWhoisXmlApiKey("whoisxml-key"),
		WithHackerTargetApiKey("hackertarget-key"),
		WithSharedHostingDomainLimit(9),
		WithFetchOptions(fetch_config.WithMethod("GET")),
		// Accumulating rather than replacing: two calls are how a caller adds to what an earlier
		// one set, and replacing would silently drop it.
		WithFetchOptions(fetch_config.WithMethod("POST")),
	)

	if config.WhoisXml != whoisXmlClient {
		t.Error("expected the whoisxml client to be taken")
	}
	if config.HackerTarget != hackerTargetClient {
		t.Error("expected the hackertarget client to be taken")
	}
	if config.WhoisXmlApiKey != "whoisxml-key" || config.HackerTargetApiKey != "hackertarget-key" {
		t.Errorf("expected both keys to be taken, got %+v", config)
	}
	if config.SharedHostingDomainLimit != 9 {
		t.Errorf("expected the limit to be taken, got %d", config.SharedHostingDomainLimit)
	}
	if len(config.FetchOptions) != 2 {
		t.Errorf("expected the fetch options to accumulate, got %d", len(config.FetchOptions))
	}
}
