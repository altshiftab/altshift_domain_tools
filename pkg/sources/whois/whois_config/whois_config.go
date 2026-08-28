// Package whois_config holds the settings of a whois client.
package whois_config

import (
	"context"
	"net"
	"time"
)

type Config struct {
	// Port is the service the queries are sent to. An empty one is the well-known whois port.
	Port string

	// Timeout bounds a single query, dialling included. Zero is the default.
	//
	// It matters more here than over HTTP: the protocol has no status line and no length, so a
	// server that accepts a connection and then says nothing would otherwise hold the query open
	// until the context is done.
	Timeout time.Duration

	// InverseAttributes are the references a range is looked for under. Empty is the default.
	//
	// They are configurable because the registries do not agree on which attributes may be searched
	// in reverse: AFRINIC refuses abuse-c, which APNIC allows.
	InverseAttributes []string

	// MaxContacts bounds how many of the contacts found at a domain are followed to their ranges.
	// Zero is the default.
	MaxContacts int

	// MaxResponseBytes bounds what one answer may be. Zero is the default.
	MaxResponseBytes int

	// Dial opens the connection. A nil one dials TCP.
	//
	// It is here so that a test can answer without a server on a well-known port, and so that a
	// caller behind a proxy can supply its own.
	Dial DialFunc
}

// DialFunc opens a connection to the whois service.
type DialFunc func(ctx context.Context, address string) (net.Conn, error)

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

func WithPort(port string) Option {
	return func(config *Config) {
		config.Port = port
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(config *Config) {
		config.Timeout = timeout
	}
}

// WithInverseAttributes replaces what an earlier call set, a list of attributes being one setting
// rather than something to accumulate.
func WithInverseAttributes(attributes ...string) Option {
	return func(config *Config) {
		config.InverseAttributes = attributes
	}
}

func WithMaxContacts(maxContacts int) Option {
	return func(config *Config) {
		config.MaxContacts = maxContacts
	}
}

func WithMaxResponseBytes(maxResponseBytes int) Option {
	return func(config *Config) {
		config.MaxResponseBytes = maxResponseBytes
	}
}

func WithDial(dial DialFunc) Option {
	return func(config *Config) {
		config.Dial = dial
	}
}
