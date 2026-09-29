// Package crtsh reads subdomain names out of the certificate transparency logs.
//
// Every certificate a public authority issues is logged, and a certificate names the hosts it is
// for. Searching the logs for a domain therefore turns up the names someone asked for a certificate
// for -- including ones never meant to be found, since an internal host with a public certificate
// is in the logs like any other.
//
// It needs no credentials and asks nothing of the target, which is why it is worth running before
// anything that does.
package crtsh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/crtsh/crtsh_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config/retry_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config/retry_config/response_checker"
	altshiftHttpUtils "github.com/altshiftab/utils_go/pkg/http/utils"
)

const Domain = "crt.sh"

var defaultBaseUrl = &url.URL{
	Scheme: "https",
	Host:   Domain,
}

// Result is one certificate the log holds.
type Result struct {
	IssuerCaId int    `json:"issuer_ca_id,omitzero"`
	IssuerName string `json:"issuer_name,omitzero"`
	CommonName string `json:"common_name,omitzero"`
	// NameValue carries every name on the certificate, one per line.
	NameValue      string `json:"name_value,omitzero"`
	Id             int64  `json:"id,omitzero"`
	EntryTimestamp string `json:"entry_timestamp,omitzero"`
	NotBefore      string `json:"not_before,omitzero"`
	NotAfter       string `json:"not_after,omitzero"`
	SerialNumber   string `json:"serial_number,omitzero"`
}

type Client struct {
	cooldownLock     sync.Mutex
	unavailableUntil time.Time

	baseUrl *url.URL
	config  *crtsh_config.Config
}

func NewClient(options ...crtsh_config.Option) *Client {
	config := crtsh_config.New(options...)

	baseUrl := config.BaseUrl
	if baseUrl == nil {
		baseUrl = defaultBaseUrl
	}
	clientUrl := *baseUrl
	clientUrl.Path = "/"

	return &Client{baseUrl: &clientUrl, config: config}
}

// The retries a query gets. crt.sh is a shared public service that answers a busy moment with a 429,
// a 502 or a dropped connection, and a query refused once is usually answered a little later. A
// query that runs out of time is not retried: one that took RequestTimeout will not be quicker a few
// seconds on.
const (
	RetryCount       = 3
	RetryBaseDelay   = 5 * time.Second
	MaximumRetryWait = time.Minute
)

// DefaultRequestTimeout bounds one query. crt.sh takes longer than a general-purpose client allows
// for a domain with many certificates, so the query brings its own bound rather than the caller's.
const DefaultRequestTimeout = 90 * time.Second

// DefaultTimeoutCooldown is how long queries are turned away after one timed out. The domains of an
// entity are queried one after another, and a crt.sh that has stopped answering would otherwise cost
// every one of them the full timeout.
const DefaultTimeoutCooldown = 5 * time.Minute

// ErrUnavailable is a query turned away because a recent one timed out.
var ErrUnavailable = errors.New("crt.sh timed out recently")

// isTimeout reports whether the error is a request running out of time.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	netError, ok := errors.AsType[net.Error](err)

	return ok && netError != nil && netError.Timeout()
}

// defaultRetryConfig retries a 429, a server error and a failed request, but not one that timed out.
func defaultRetryConfig() *retry_config.Config {
	return retry_config.New(
		retry_config.WithCount(RetryCount),
		retry_config.WithBaseDelay(RetryBaseDelay),
		retry_config.WithMaximumWaitTime(MaximumRetryWait),
		retry_config.WithResponseChecker(response_checker.New(
			func(response *http.Response, _ []byte, err error) bool {
				if response != nil {
					return response.StatusCode == http.StatusTooManyRequests ||
						response.StatusCode >= http.StatusInternalServerError
				}

				return err != nil && !isTimeout(err)
			},
		)),
	)
}

func (client *Client) requestTimeout() time.Duration {
	if timeout := client.config.RequestTimeout; timeout > 0 {
		return timeout
	}

	return DefaultRequestTimeout
}

func (client *Client) timeoutCooldown() time.Duration {
	if cooldown := client.config.TimeoutCooldown; cooldown > 0 {
		return cooldown
	}

	return DefaultTimeoutCooldown
}

// withRequestTimeout is the HTTP client the options would use, with the query's own timeout: a copy,
// so the caller's client -- its transport, a proxy, a test server -- is kept and not changed.
func (client *Client) withRequestTimeout(fetchOptions []fetch_config.Option) fetch_config.Option {
	httpClient := *fetch_config.New(fetchOptions...).HttpClient
	httpClient.Timeout = client.requestTimeout()

	return fetch_config.WithHttpClient(&httpClient)
}

func (client *Client) unavailable() bool {
	client.cooldownLock.Lock()
	defer client.cooldownLock.Unlock()

	return time.Now().Before(client.unavailableUntil)
}

func (client *Client) coolDown() {
	client.cooldownLock.Lock()
	defer client.cooldownLock.Unlock()

	client.unavailableUntil = time.Now().Add(client.timeoutCooldown())
}

// Query returns the certificates the logs hold for the domain and its subdomains.
func (client *Client) Query(
	ctx context.Context,
	domain string,
	options ...fetch_config.Option,
) ([]*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if domain == "" {
		return nil, nil
	}

	requestUrl := *client.baseUrl

	// The leading "%." is the log's wildcard: it asks for every name under the domain rather than
	// the domain itself.
	query := requestUrl.Query()
	query.Set("q", "%."+domain)
	query.Set("output", "json")
	requestUrl.RawQuery = query.Encode()

	requestUrlString := requestUrl.String()

	// slices.Concat rather than append: the client's options are shared by every call, and
	// appending into that slice's spare capacity would have concurrent calls overwrite one
	// another's.
	//
	// Retries first, so that a caller's own retry policy replaces them; the query's timeout last, so
	// that it is not replaced by the timeout of a client the caller shares with faster sources.
	fetchOptions := slices.Concat(
		[]fetch_config.Option{fetch_config.WithRetryConfig(defaultRetryConfig())},
		client.config.FetchOptions,
		options,
	)
	fetchOptions = append(fetchOptions, client.withRequestTimeout(fetchOptions))

	if client.unavailable() {
		return nil, altshiftErrors.NewWithTrace(ErrUnavailable, domain)
	}

	_, results, err := altshiftHttpUtils.FetchJson[[]*Result](ctx, requestUrlString, fetchOptions...)
	if err != nil {
		if isTimeout(err) && ctx.Err() == nil {
			client.coolDown()
		}

		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), requestUrlString)
	}

	return results, nil
}

// Names returns the distinct subdomain names the results carry, in no particular order.
//
// A certificate names several hosts and the same host appears on every certificate ever issued for
// it, so the log answers with far more rows than names. Wildcards are left out: "*.example.com" is
// not a host that exists, and the domain itself is not one of its own subdomains.
func Names(results []*Result, domain string) []string {
	suffix := "." + strings.ToLower(domain)
	seen := make(map[string]struct{})
	names := make([]string, 0)

	for _, result := range results {
		if result == nil {
			continue
		}

		for name := range strings.SplitSeq(result.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" || strings.Contains(name, "*") {
				continue
			}

			// A log search matches on a pattern, and a pattern can match a name that is not under
			// the domain at all. Only the ones that are under it are kept.
			if !strings.HasSuffix(name, suffix) {
				continue
			}

			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}

	return names
}
