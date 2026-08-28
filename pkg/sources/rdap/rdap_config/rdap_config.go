// Package rdap_config holds the settings of an RDAP client.
package rdap_config

import (
	"net/url"

	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

type Config struct {
	// BaseUrl is the server the queries are sent to. There is no default: RDAP is a protocol several
	// registries answer, and which of them is being asked is the whole of what distinguishes two
	// clients.
	BaseUrl *url.URL

	// NameSuffix is appended to a name before it is searched for.
	//
	// It is a setting because the registries do not agree on what a name search matches. APNIC
	// matches a name by prefix and finds nothing without a trailing asterisk; AFRINIC matches by
	// token and finds nothing with one. The same search term therefore has to be written two ways.
	NameSuffix string

	// MaxNames bounds how many names are searched for. Zero is the default.
	MaxNames int

	// MaxEntities bounds how many of the parties a name search turns up are read in full. Zero is
	// the default.
	//
	// It matters because a short name matches a great many parties, and the search answers without
	// the ranges, so each one is a request of its own.
	MaxEntities int

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

func WithNameSuffix(nameSuffix string) Option {
	return func(config *Config) {
		config.NameSuffix = nameSuffix
	}
}

func WithMaxNames(maxNames int) Option {
	return func(config *Config) {
		config.MaxNames = maxNames
	}
}

func WithMaxEntities(maxEntities int) Option {
	return func(config *Config) {
		config.MaxEntities = maxEntities
	}
}

// WithFetchOptions adds to what an earlier call set rather than replacing it.
func WithFetchOptions(fetchOptions ...fetch_config.Option) Option {
	return func(config *Config) {
		config.FetchOptions = append(config.FetchOptions, fetchOptions...)
	}
}
