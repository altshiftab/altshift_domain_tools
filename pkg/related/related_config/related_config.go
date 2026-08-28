// Package related_config holds the settings of a related-domain finder.
package related_config

import (
	"github.com/altshiftab/altshift_domain_tools/pkg/resolver"
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

	// ReverseWhoisMatchLimit overrides how many domains a reverse-whois term may match before its
	// results are left unbought. Zero is the default. Raising it past what one response holds is
	// what has a search read more than one page, and pages bill one credit each.
	ReverseWhoisMatchLimit int

	// ReverseWhoisOrganizationMatchLimit overrides the same bound for the organisation pivot, which
	// has its own because a name matches far more loosely than an address does. Zero is the default.
	ReverseWhoisOrganizationMatchLimit int

	// SearchTypes is which registration records a reverse-whois search reads -- the current ones,
	// the historic ones, or both. Empty is the default, which is the current ones alone: the
	// historic sweep is worth making once per domain, and a monitor that repeats should not buy the
	// past again on every run. Each type is a search of its own and bills as one.
	SearchTypes []string

	// AddressResolver reads the addresses the reverse-IP search starts from. A nil one is the
	// standard library's resolver.
	AddressResolver resolver.AddressResolver

	// NameServerResolver reads the nameservers the corroboration check compares. A nil one is the
	// standard library's resolver.
	NameServerResolver resolver.NameServerResolver

	// NameServerClusterSize overrides how many domains must share a set of nameservers before the
	// sharing is taken to mean anything. Zero is the default.
	NameServerClusterSize int

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

func WithReverseWhoisMatchLimit(limit int) Option {
	return func(config *Config) {
		config.ReverseWhoisMatchLimit = limit
	}
}

func WithReverseWhoisOrganizationMatchLimit(limit int) Option {
	return func(config *Config) {
		config.ReverseWhoisOrganizationMatchLimit = limit
	}
}

func WithSearchTypes(searchTypes ...string) Option {
	return func(config *Config) {
		config.SearchTypes = searchTypes
	}
}

func WithAddressResolver(addressResolver resolver.AddressResolver) Option {
	return func(config *Config) {
		config.AddressResolver = addressResolver
	}
}

func WithNameServerResolver(nameServerResolver resolver.NameServerResolver) Option {
	return func(config *Config) {
		config.NameServerResolver = nameServerResolver
	}
}

func WithNameServerClusterSize(size int) Option {
	return func(config *Config) {
		config.NameServerClusterSize = size
	}
}

func WithFetchOptions(fetchOptions ...fetch_config.Option) Option {
	return func(config *Config) {
		config.FetchOptions = append(config.FetchOptions, fetchOptions...)
	}
}
