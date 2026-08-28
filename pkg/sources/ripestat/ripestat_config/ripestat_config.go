// Package ripestat_config holds the settings of a RIPEstat client.
package ripestat_config

import (
	"net/url"

	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

type Config struct {
	// BaseUrl is the service the queries are sent to. A nil one is the public service.
	BaseUrl *url.URL

	// SourceApp identifies the caller to the service, which asks for it and answers a caller that
	// gives one more generously. An empty one is the default.
	SourceApp string

	// MaxPrefixes bounds how many prefixes one answer contributes. Zero is the default.
	//
	// It matters because a large network announces tens of thousands, and a party is not better
	// attributed by the last of them than by the first.
	MaxPrefixes int

	// FetchOptions are passed to every request the client makes.
	FetchOptions []fetch_config.Option
}

type Option func(*Config)

// New builds a config from the options. A nil option is skipped, so a caller can pass one
// conditionally without guarding the call.
func New(options ...Option) *Config {
	config := &Config{}
	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

func WithBaseUrl(baseUrl *url.URL) Option {
	return func(config *Config) {
		config.BaseUrl = baseUrl
	}
}

func WithSourceApp(sourceApp string) Option {
	return func(config *Config) {
		config.SourceApp = sourceApp
	}
}

func WithMaxPrefixes(maxPrefixes int) Option {
	return func(config *Config) {
		config.MaxPrefixes = maxPrefixes
	}
}

// WithFetchOptions adds to what an earlier call set rather than replacing it.
func WithFetchOptions(fetchOptions ...fetch_config.Option) Option {
	return func(config *Config) {
		config.FetchOptions = append(config.FetchOptions, fetchOptions...)
	}
}
