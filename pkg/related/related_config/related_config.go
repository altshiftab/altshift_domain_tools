// Package related_config holds the settings of a related-domain finder.
package related_config

import (
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/hackertarget"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

type Config struct {
	// The source clients. A nil one is built with its own defaults.
	WhoisXml     *whoisxml.Client
	HackerTarget *hackertarget.Client

	// The keys the two sources need. Neither is anonymous.
	WhoisXmlApiKey     string
	HackerTargetApiKey string

	// SharedHostingDomainLimit overrides how many domains one address may serve before co-location
	// is taken to say nothing about ownership. Zero is the default.
	SharedHostingDomainLimit int

	// FetchOptions are passed to every source call, on top of whatever the clients were built with.
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

func WithWhoisXml(client *whoisxml.Client) Option {
	return func(config *Config) {
		config.WhoisXml = client
	}
}

func WithHackerTarget(client *hackertarget.Client) Option {
	return func(config *Config) {
		config.HackerTarget = client
	}
}

func WithWhoisXmlApiKey(apiKey string) Option {
	return func(config *Config) {
		config.WhoisXmlApiKey = apiKey
	}
}

func WithHackerTargetApiKey(apiKey string) Option {
	return func(config *Config) {
		config.HackerTargetApiKey = apiKey
	}
}

func WithSharedHostingDomainLimit(limit int) Option {
	return func(config *Config) {
		config.SharedHostingDomainLimit = limit
	}
}

func WithFetchOptions(fetchOptions ...fetch_config.Option) Option {
	return func(config *Config) {
		config.FetchOptions = append(config.FetchOptions, fetchOptions...)
	}
}
