// Package finder_config holds the settings of a network range finder.
package finder_config

import (
	"github.com/altshiftab/altshift_domain_tools/pkg/inference"
	"github.com/altshiftab/altshift_domain_tools/pkg/network_range/spf"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/arin"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/rdap"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripe"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whois"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

type Config struct {
	// Ripe is the registry client for Europe, the Middle East and Central Asia. A nil one is built
	// with its own defaults.
	Ripe *ripe.Client

	// Arin is the registry client for North America. A nil one is built with its own defaults.
	Arin *arin.Client

	// Whois and Rdap are the clients for the registries that offer no search from a domain, by the
	// method each of them answers for. Both empty is APNIC and AFRINIC, built with the settings
	// their servers need.
	//
	// Supplying either confines the run to what was supplied, so a caller wanting one registry, or
	// one route into it, gets that and nothing else. They are separate maps because the two routes
	// are independent -- an inverse search over port 43, a name search over HTTPS -- and a caller
	// may well want one without the other.
	Whois map[inference.Method]*whois.Client
	Rdap  map[inference.Method]*rdap.Client

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

func WithArin(client *arin.Client) Option {
	return func(config *Config) {
		config.Arin = client
	}
}

// WithWhois adds the port 43 route into one registry, under the method its ranges are attributed to.
func WithWhois(method inference.Method, client *whois.Client) Option {
	return func(config *Config) {
		if config.Whois == nil {
			config.Whois = make(map[inference.Method]*whois.Client)
		}

		config.Whois[method] = client
	}
}

// WithRdap adds the name route into one registry, under the method its ranges are attributed to.
func WithRdap(method inference.Method, client *rdap.Client) Option {
	return func(config *Config) {
		if config.Rdap == nil {
			config.Rdap = make(map[inference.Method]*rdap.Client)
		}

		config.Rdap[method] = client
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
