// Package registration_config holds the settings of a registration checker.
package registration_config

import (
	"net/url"

	"github.com/altshiftab/altshift_domain_tools/pkg/resolver"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

type Config struct {
	// BootstrapUrl is where the registries' RDAP servers are listed. Nil is IANA's.
	BootstrapUrl *url.URL

	// Resolver answers for a top-level domain whose registry runs no RDAP server. Nil is a client for
	// the default public resolver.
	Resolver resolver.Resolver

	// FetchOptions are passed to every request the checker makes.
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

func WithBootstrapUrl(bootstrapUrl *url.URL) Option {
	return func(config *Config) {
		config.BootstrapUrl = bootstrapUrl
	}
}

func WithResolver(domainResolver resolver.Resolver) Option {
	return func(config *Config) {
		config.Resolver = domainResolver
	}
}

func WithFetchOptions(fetchOptions ...fetch_config.Option) Option {
	return func(config *Config) {
		config.FetchOptions = fetchOptions
	}
}
