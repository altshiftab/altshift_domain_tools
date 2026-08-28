package hackertarget_config

import (
	"net/url"
	"testing"

	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

func TestNew(t *testing.T) {
	t.Parallel()

	baseUrl := &url.URL{Scheme: "https", Host: "example.test"}

	testCases := []struct {
		name             string
		options          []Option
		expectBaseUrl    *url.URL
		expectFetchCount int
	}{
		// No options is the ordinary call: the client fills in its own default base URL, so the
		// config leaving it nil is what says "unset" rather than "the empty URL".
		{name: "no options leaves everything unset"},
		{
			name:          "a base url is taken",
			options:       []Option{WithBaseUrl(baseUrl)},
			expectBaseUrl: baseUrl,
		},
		{
			name:             "fetch options are taken",
			options:          []Option{WithFetchOptions(fetch_config.WithMethod("GET"))},
			expectFetchCount: 1,
		},
		{
			// Accumulating rather than replacing: two calls are how a caller adds to what an
			// earlier one set, and replacing would silently drop it.
			name: "fetch options accumulate across calls",
			options: []Option{
				WithFetchOptions(fetch_config.WithMethod("GET")),
				WithFetchOptions(fetch_config.WithMethod("POST"), fetch_config.WithMethod("PUT")),
			},
			expectFetchCount: 3,
		},
		// A nil option is skipped rather than panicking, so a caller can pass one conditionally.
		{name: "a nil option is skipped", options: []Option{nil}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			config := New(testCase.options...)
			if config == nil {
				t.Fatalf("%s: expected a config, got nil", testCase.name)
			}

			if config.BaseUrl != testCase.expectBaseUrl {
				t.Errorf("%s: expected the base url %v, got %v", testCase.name, testCase.expectBaseUrl, config.BaseUrl)
			}
			if len(config.FetchOptions) != testCase.expectFetchCount {
				t.Errorf(
					"%s: expected %d fetch options, got %d",
					testCase.name,
					testCase.expectFetchCount,
					len(config.FetchOptions),
				)
			}
		})
	}
}
