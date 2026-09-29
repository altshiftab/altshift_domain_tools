package crtsh_config

import (
	"net/url"
	"time"

	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

type Config struct {
	BaseUrl      *url.URL
	FetchOptions []fetch_config.Option

	// RequestTimeout bounds one query, over whatever HTTP client the query is otherwise given. Zero
	// is the client's default.
	RequestTimeout time.Duration
	// TimeoutCooldown is how long queries are turned away after one timed out. Zero is the client's
	// default.
	TimeoutCooldown time.Duration
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

func WithBaseUrl(baseUrl *url.URL) Option {
	return func(config *Config) {
		config.BaseUrl = baseUrl
	}
}

func WithFetchOptions(fetchOptions ...fetch_config.Option) Option {
	return func(config *Config) {
		config.FetchOptions = append(config.FetchOptions, fetchOptions...)
	}
}

func WithRequestTimeout(requestTimeout time.Duration) Option {
	return func(config *Config) {
		config.RequestTimeout = requestTimeout
	}
}

func WithTimeoutCooldown(timeoutCooldown time.Duration) Option {
	return func(config *Config) {
		config.TimeoutCooldown = timeoutCooldown
	}
}
