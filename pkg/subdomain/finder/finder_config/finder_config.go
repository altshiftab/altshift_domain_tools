// Package finder_config holds the settings of a subdomain finder.
package finder_config

import (
	"github.com/altshiftab/altshift_domain_tools/pkg/resolver"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/crtsh"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/hackertarget"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

type Config struct {
	// The source clients. A nil one is built with its own defaults, so a caller who wants the
	// ordinary behaviour passes none; a caller who wants a base URL, a timeout or an authenticated
	// transport builds the client and passes it.
	Crtsh        *crtsh.Client
	HackerTarget *hackertarget.Client

	// Resolver is what the active pass asks. Without one the passive sources run alone.
	Resolver resolver.Resolver

	// Concurrency bounds the active pass. Zero is the brute force's default.
	Concurrency int

	// FetchOptions are passed to every source call this finder makes, on top of whatever the source
	// clients were built with.
	FetchOptions []fetch_config.Option
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{}
	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

func WithCrtsh(client *crtsh.Client) Option {
	return func(config *Config) {
		config.Crtsh = client
	}
}

func WithHackerTarget(client *hackertarget.Client) Option {
	return func(config *Config) {
		config.HackerTarget = client
	}
}

func WithResolver(domainResolver resolver.Resolver) Option {
	return func(config *Config) {
		config.Resolver = domainResolver
	}
}

func WithConcurrency(concurrency int) Option {
	return func(config *Config) {
		config.Concurrency = concurrency
	}
}

func WithFetchOptions(fetchOptions ...fetch_config.Option) Option {
	return func(config *Config) {
		config.FetchOptions = append(config.FetchOptions, fetchOptions...)
	}
}
