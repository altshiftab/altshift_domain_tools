// Package finder_config holds the settings of a network range finder.
package finder_config

import (
	"github.com/altshiftab/altshift_domain_tools/pkg/network_range/spf"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripe"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

type Config struct {
	// Ripe is the registry client. A nil one is built with its own defaults.
	Ripe *ripe.Client

	// Resolver is what the SPF walk asks. A nil one is net.DefaultResolver.
	Resolver spf.Resolver

	// FetchOptions are passed to the registry calls, on top of whatever the client was built with.
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

func WithRipe(client *ripe.Client) Option {
	return func(config *Config) {
		config.Ripe = client
	}
}

func WithResolver(resolver spf.Resolver) Option {
	return func(config *Config) {
		config.Resolver = resolver
	}
}

// WithFetchOptions adds to what an earlier call set rather than replacing it.
func WithFetchOptions(fetchOptions ...fetch_config.Option) Option {
	return func(config *Config) {
		config.FetchOptions = append(config.FetchOptions, fetchOptions...)
	}
}
