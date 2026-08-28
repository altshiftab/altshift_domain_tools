// Package arin_config holds the settings of an ARIN database client.
package arin_config

import (
	"net/url"

	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

type Config struct {
	// BaseUrl is the database the queries are sent to. A nil one is the public REST API.
	BaseUrl *url.URL

	// MaxPersons bounds how many contacts a domain search reads in full. Zero is the default.
	//
	// It matters because the search answers with handles alone, so learning the company a contact
	// belongs to -- which is the only bridge ARIN offers from a domain to an organisation -- is a
	// request per contact.
	MaxPersons int

	// MaxOrganizations bounds how many of the organisations a name search turns up are checked
	// against the contacts. Zero is the default.
	//
	// It matters because a short name matches a great many organisations, and each one is two
	// further requests: the contacts to check it by, and the ranges if it holds.
	MaxOrganizations int

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

func WithMaxOrganizations(maxOrganizations int) Option {
	return func(config *Config) {
		config.MaxOrganizations = maxOrganizations
	}
}

// WithFetchOptions adds to what an earlier call set rather than replacing it.
func WithFetchOptions(fetchOptions ...fetch_config.Option) Option {
	return func(config *Config) {
		config.FetchOptions = append(config.FetchOptions, fetchOptions...)
	}
}
