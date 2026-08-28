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
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/crtsh/crtsh_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
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
	fetchOptions := slices.Concat(client.config.FetchOptions, options)

	_, results, err := altshiftHttpUtils.FetchJson[[]*Result](ctx, requestUrlString, fetchOptions...)
	if err != nil {
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
