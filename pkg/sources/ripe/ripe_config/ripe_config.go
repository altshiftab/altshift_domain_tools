// Package ripe_config holds the settings of a RIPE database client.
package ripe_config

import (
	"net/url"

	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

type Config struct {
	// BaseUrl is the database the queries are sent to. A nil one is the public REST API.
	BaseUrl *url.URL

	// MaxPersons bounds how many person objects a domain search reads before it stops looking up
	// the ranges behind them. Zero is the default.
	//
	// It matters because the two steps multiply: every handle found becomes a query of its own, so
	// a domain that matches a hundred people is a hundred requests against a database that asks
	// callers to be gentle.
	MaxPersons int

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

func WithMaxPersons(maxPersons int) Option {
	return func(config *Config) {
		config.MaxPersons = maxPersons
	}
}

// WithFetchOptions adds to what an earlier call set rather than replacing it.
func WithFetchOptions(fetchOptions ...fetch_config.Option) Option {
	return func(config *Config) {
		config.FetchOptions = append(config.FetchOptions, fetchOptions...)
	}
}
