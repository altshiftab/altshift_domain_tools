// Package resolver answers whether a domain resolves, which is what the subdomain brute force and
// the wildcard check are built on.
//
// Resolver is an interface rather than a concrete client so that a caller already holding one --
// dns_utils' client satisfies it as it stands -- passes that instead. The implementation here is
// for callers who hold none.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/miekg/dns"
)

// Resolver reports whether a domain has any record at all.
//
// An implementation must be safe for concurrent use: the brute force calls it from as many
// goroutines at once as its concurrency allows.
type Resolver interface {
	// DomainExists reports whether the domain resolves. A domain that does not is not an error:
	// that is the answer the brute force is asking for, thousands of times.
	DomainExists(ctx context.Context, domain string) (bool, error)
}

// RefusedError is a server declining to answer. It is worth telling apart from any other failure:
// a resolver that refuses one query will refuse the next thousand, so a caller running a brute
// force should stop rather than work through its list being told no.
type RefusedError struct {
	Domain string
	Rcode  int
}

func (refusedError *RefusedError) Error() string {
	return fmt.Sprintf("the resolver refused the query for %s (rcode %d)", refusedError.Domain, refusedError.Rcode)
}

// IsRefused reports whether the error is a resolver declining to answer.
func IsRefused(err error) bool {
	var refusedError *RefusedError

	return errors.As(err, &refusedError)
}

const (
	// DefaultTimeout bounds one query.
	DefaultTimeout = 5 * time.Second
	// DefaultAddress is the resolver queried when none is given. It is a public one rather than the
	// host's, because the host's is often a forwarder that rate limits long before a brute force is
	// through its list.
	DefaultAddress = "1.1.1.1:53"
)

// Client resolves over DNS.
//
// It is here rather than over net.Resolver because the standard library does not report the
// response code, and telling a refusal from a name that does not exist is the difference between
// stopping a brute force and running it to the end against a resolver that has stopped answering.
type Client struct {
	// Address is the resolver to query, host and port. Empty means DefaultAddress.
	Address string
	// Timeout bounds one query. Zero means DefaultTimeout.
	Timeout time.Duration
}

// New makes a client for the resolver at address. An empty address is the default one.
func New(address string) (*Client, error) {
	if address == "" {
		address = DefaultAddress
	}

	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("net split host port: %w", err), address)
	}

	return &Client{Address: address}, nil
}

func (client *Client) address() string {
	if client.Address == "" {
		return DefaultAddress
	}

	return client.Address
}

func (client *Client) timeout() time.Duration {
	if client.Timeout <= 0 {
		return DefaultTimeout
	}

	return client.Timeout
}

// DomainExists reports whether the domain resolves.
//
// It asks for an A record and reads the response code rather than the answers: a name that exists
// without an address of its own -- one carrying only an MX or a TXT record -- still exists, and the
// server says so by answering NOERROR rather than NXDOMAIN.
func (client *Client) DomainExists(ctx context.Context, domain string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("context err: %w", err)
	}

	if domain == "" {
		return false, altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	message.RecursionDesired = true

	dnsClient := &dns.Client{Timeout: client.timeout()}

	response, _, err := dnsClient.ExchangeContext(ctx, message, client.address())
	if err != nil {
		return false, altshiftErrors.NewWithTrace(fmt.Errorf("dns exchange context: %w", err), domain)
	}
	if response == nil {
		return false, altshiftErrors.NewWithTrace(
			//nolint:err113 // a nil response with no error is the library misbehaving, not a condition to match on.
			errors.New("the resolver returned no response"),
			domain,
		)
	}

	switch response.Rcode {
	case dns.RcodeSuccess:
		return true, nil
	case dns.RcodeNameError:
		// NXDOMAIN: the name does not exist. This is the common answer during a brute force and is
		// not a failure.
		return false, nil
	case dns.RcodeRefused, dns.RcodeServerFailure:
		return false, altshiftErrors.NewWithTrace(
			&RefusedError{Domain: domain, Rcode: response.Rcode},
			domain,
		)
	default:
		return false, altshiftErrors.NewWithTrace(
			//nolint:err113 // the response code is the message; there is nothing to match on.
			errors.New("the resolver answered with an unexpected response code "+strconv.Itoa(response.Rcode)),
			domain,
		)
	}
}
