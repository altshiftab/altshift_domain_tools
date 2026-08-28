// Package hackertarget queries the two HackerTarget lookups this library uses.
//
// The host search answers with the names known under a domain, which finds subdomains. The reverse
// IP lookup answers with the names resolving to an address, which finds domains a party may own by
// where they are hosted. They are one client because they are one API with one quota, and the
// counters below are read the same way for both.
//
// The free tier is metered rather than keyed: the response carries the quota and how much of it the
// caller has spent, which is why those are read and returned rather than discarded.
package hackertarget

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/hackertarget/hackertarget_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	altshiftHttpUtils "github.com/altshiftab/utils_go/pkg/http/utils"
)

const Domain = "api.hackertarget.com"

var defaultBaseUrl = &url.URL{
	Scheme: "https",
	Host:   Domain,
}

// The paths the two lookups are served at.
const (
	HostSearchPath = "/hostsearch/"
	ReverseIpPath  = "/reverseiplookup/"
)

// The API reports these conditions as a plain-text body with a 200, so they are recognised by their
// text rather than by a status code.
var (
	invalidHostBody        = []byte("error invalid host")
	quotaExceededBody      = []byte("API count exceeded - Increase Quota with Membership")
	badSearchParameterBody = []byte("error check your search parameter")
)

var (
	// ErrInvalidHost is the API rejecting the domain it was given.
	ErrInvalidHost = errors.New("invalid host")
	// ErrQuotaExceeded is the free tier's allowance being spent. It is worth telling apart: it will
	// not clear by retrying, and every further query is wasted.
	ErrQuotaExceeded = errors.New("quota exceeded")
	// ErrMalformedLine is a body line that is not the "name,address" the API documents.
	ErrMalformedLine = errors.New("malformed line")
	// ErrBadSearchParameter is the API rejecting what it was asked to look up.
	ErrBadSearchParameter = errors.New("bad search parameter")
)

// NotIpv4Error is an address the reverse IP lookup cannot take. The endpoint is IPv4 only, and an
// IPv6 address is a caller mistake rather than a lookup that found nothing.
type NotIpv4Error struct {
	IpAddress net.IP
}

func (notIpv4Error *NotIpv4Error) Error() string {
	return fmt.Sprintf("the address %s is not IPv4, which the reverse IP lookup requires", notIpv4Error.IpAddress)
}

// Result is one name the search knows under the domain.
type Result struct {
	Domain    string `json:"domain"`
	IpAddress string `json:"ip_address"`
}

// Response is a host search, with what the API said about the caller's remaining allowance.
type Response struct {
	// ApiQuota is the allowance, ApiCount what has been spent of it, and ApiBoost whatever the API
	// adds for a paying caller. They come from response headers rather than the body.
	ApiQuota int       `json:"api_quota,omitzero"`
	ApiCount int       `json:"api_count,omitzero"`
	ApiBoost int       `json:"api_boost,omitzero"`
	Results  []*Result `json:"results,omitzero"`
}

type Client struct {
	baseUrl *url.URL
	config  *hackertarget_config.Config
}

func NewClient(options ...hackertarget_config.Option) *Client {
	config := hackertarget_config.New(options...)

	baseUrl := config.BaseUrl
	if baseUrl == nil {
		baseUrl = defaultBaseUrl
	}
	clientUrl := *baseUrl

	return &Client{baseUrl: &clientUrl, config: config}
}

// fetchOptions is the client's options with the call's appended.
//
// slices.Concat rather than append: the client's options are shared by every call, and appending
// into that slice's spare capacity would have concurrent calls overwrite one another's.
func (client *Client) fetchOptions(
	options []fetch_config.Option,
	extra ...fetch_config.Option,
) []fetch_config.Option {
	return slices.Concat(client.config.FetchOptions, options, extra)
}

// requestUrl builds a URL for one of the lookups.
func (client *Client) requestUrl(path string, query url.Values) string {
	requestUrl := *client.baseUrl
	requestUrl.Path = path
	requestUrl.RawQuery = query.Encode()

	return requestUrl.String()
}

// counters reads the metering the API reports in response headers.
func counters(header http.Header, response *Response) error {
	for _, counter := range []struct {
		name  string
		value *int
	}{
		{name: "x-api-quota", value: &response.ApiQuota},
		{name: "x-api-count", value: &response.ApiCount},
		{name: "x-api-boost", value: &response.ApiBoost},
	} {
		raw := header.Get(counter.name)
		if raw == "" {
			continue
		}

		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return altshiftErrors.NewWithTrace(fmt.Errorf("strconv atoi (%s): %w", counter.name, err), raw)
		}
		*counter.value = parsed
	}

	return nil
}

// Query returns the names the host search knows under the domain.
func (client *Client) Query(
	ctx context.Context,
	domain string,
	options ...fetch_config.Option,
) (*Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if domain == "" {
		return nil, nil
	}

	requestUrlString := client.requestUrl(HostSearchPath, url.Values{"q": []string{domain}})

	httpResponse, responseBody, err := altshiftHttpUtils.Fetch(
		ctx,
		requestUrlString,
		client.fetchOptions(options, fetch_config.WithMethod(http.MethodGet))...,
	)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("fetch: %w", err), requestUrlString)
	}
	if httpResponse == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("http response"), requestUrlString)
	}

	trimmed := bytes.TrimSpace(responseBody)
	if bytes.Equal(trimmed, invalidHostBody) {
		return nil, altshiftErrors.NewWithTrace(ErrInvalidHost, domain)
	}
	if bytes.Equal(trimmed, quotaExceededBody) {
		return nil, altshiftErrors.NewWithTrace(ErrQuotaExceeded, domain)
	}

	header := httpResponse.Header
	if header == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("http response header"), requestUrlString)
	}

	response := &Response{}
	if err := counters(header, response); err != nil {
		return nil, fmt.Errorf("counters: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(responseBody))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		name, ipAddress, ok := strings.Cut(line, ",")
		if !ok {
			return nil, altshiftErrors.NewWithTrace(ErrMalformedLine, line)
		}

		response.Results = append(
			response.Results,
			&Result{Domain: strings.TrimSpace(name), IpAddress: strings.TrimSpace(ipAddress)},
		)
	}
	if err := scanner.Err(); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("scanner err: %w", err))
	}

	return response, nil
}

// QueryReverseIp returns the names HackerTarget associates with the address.
//
// The endpoint is IPv4 only, and takes an API key rather than being metered anonymously the way the
// host search is.
func (client *Client) QueryReverseIp(
	ctx context.Context,
	ipAddress net.IP,
	apiKey string,
	options ...fetch_config.Option,
) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if len(ipAddress) == 0 {
		return nil, nil
	}

	if apiKey == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("api key"))
	}

	ipv4 := ipAddress.To4()
	if ipv4 == nil {
		return nil, altshiftErrors.NewWithTrace(&NotIpv4Error{IpAddress: ipAddress})
	}

	requestUrlString := client.requestUrl(
		ReverseIpPath,
		url.Values{"q": []string{ipv4.String()}, "apikey": []string{apiKey}},
	)

	_, responseBody, err := altshiftHttpUtils.Fetch(
		ctx,
		requestUrlString,
		client.fetchOptions(options, fetch_config.WithMethod(http.MethodGet))...,
	)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("fetch: %w", err), requestUrlString, ipv4)
	}

	trimmed := bytes.TrimSpace(responseBody)
	switch {
	case bytes.Equal(trimmed, quotaExceededBody):
		return nil, altshiftErrors.NewWithTrace(ErrQuotaExceeded)
	case bytes.Equal(trimmed, badSearchParameterBody):
		return nil, altshiftErrors.NewWithTrace(ErrBadSearchParameter, ipv4)
	}

	names := make([]string, 0)
	for line := range strings.SplitSeq(string(responseBody), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, strings.ToLower(line))
		}
	}

	return names, nil
}

// Names returns the distinct names the response carries that are under the domain.
func Names(response *Response, domain string) []string {
	if response == nil {
		return nil
	}

	suffix := "." + strings.ToLower(domain)
	seen := make(map[string]struct{})
	names := make([]string, 0, len(response.Results))

	for _, result := range response.Results {
		if result == nil {
			continue
		}

		name := strings.ToLower(strings.TrimSpace(result.Domain))
		if name == "" || !strings.HasSuffix(name, suffix) {
			continue
		}

		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}

	return names
}
