// Package whoisxml queries WhoisXML's reverse-whois API, which finds domains whose registration
// records match a search term.
package whoisxml

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml/types"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml/whoisxml_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	altshiftHttpUtils "github.com/altshiftab/utils_go/pkg/http/utils"
)

const Domain = "reverse-whois.whoisxmlapi.com"

var defaultBaseUrl = &url.URL{
	Scheme: "https",
	Host:   Domain,
}

// The API bills a search in two steps: a preview reports how many domains match, and a purchase
// returns them.
const (
	ModePreview  = "preview"
	ModePurchase = "purchase"
)

// The two search types the API distinguishes: registrations as they stand now, and registrations as
// they once were.
const (
	SearchTypeCurrent  = "current"
	SearchTypeHistoric = "historic"
)

type Client struct {
	baseUrl *url.URL
	config  *whoisxml_config.Config
}

func NewClient(options ...whoisxml_config.Option) *Client {
	config := whoisxml_config.New(options...)

	baseUrl := config.BaseUrl
	if baseUrl == nil {
		baseUrl = defaultBaseUrl
	}
	clientUrl := *baseUrl
	clientUrl.Path = "/api/v2"

	return &Client{baseUrl: &clientUrl, config: config}
}

// QueryReverseWhois runs one reverse-whois search.
func (client *Client) QueryReverseWhois(
	ctx context.Context,
	request *types.ReverseWhoisRequest,
	options ...fetch_config.Option,
) (*types.ReverseWhoisResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if request == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("request"))
	}

	requestUrlString := client.baseUrl.String()

	// slices.Concat rather than append: a reverse-whois run issues these queries concurrently from
	// one shared option slice, and appending into that slice's spare capacity would have the
	// queries overwrite one another's options.
	fetchOptions := slices.Concat(
		client.config.FetchOptions,
		options,
		[]fetch_config.Option{fetch_config.WithMethod(http.MethodPost)},
	)

	_, response, err := altshiftHttpUtils.FetchJsonWithBody[*types.ReverseWhoisResponse](
		ctx,
		requestUrlString,
		request,
		fetchOptions...,
	)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("fetch json with body: %w", err), requestUrlString)
	}

	return response, nil
}
