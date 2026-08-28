// Package ripestat asks what an autonomous system holds and announces.
//
// It is the half of the walk the registries cannot answer. A registry says which allocations a party
// was given; this says which prefixes that party's network authorises and originates, which is a
// different set: space routed under someone else's allocation appears here and in no registry
// record, and space a party holds but does not route appears in the registry and not here.
//
// Two answers, worth different things. A route origin authorisation is the address holder signing,
// under RPKI, that a given network may originate a given prefix -- a statement by the party itself,
// which is as good as a registry record and rather harder to fake. An announcement is an
// observation: this prefix is being routed by that network right now, which is evidence the two
// belong together and no more. A transit provider originates its customers' space, so an
// announcement alone attributes a customer's addresses to its provider, and the two are kept apart
// here so that a consumer can weigh them differently.
//
// The service is global and answers about every registry's space, which is what makes this the one
// route into the region no registry search reaches.
package ripestat

import (
	"context"
	"fmt"
	"net/url"
	"slices"

	"github.com/altshiftab/altshift_domain_tools/pkg/asn"
	"github.com/altshiftab/altshift_domain_tools/pkg/cidr"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripestat/ripestat_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	altshiftHttpUtils "github.com/altshiftab/utils_go/pkg/http/utils"
)

// Domain is the public RIPEstat data API.
const Domain = "stat.ripe.net"

var defaultBaseUrl = &url.URL{Scheme: "https", Host: Domain}

// The paths the two answers are served at.
const (
	AnnouncedPrefixesPath = "/data/announced-prefixes/data.json"
	RoasPath              = "/data/rpki-roas/data.json"
)

// DefaultSourceApp identifies the caller. The service asks for one and answers a caller that gives
// one more generously, so it is given rather than left out.
const DefaultSourceApp = "altshift_domain_tools"

// DefaultMaxPrefixes bounds how many prefixes one answer contributes.
//
// A large network announces tens of thousands, and a party is not better attributed by the last of
// them than by the first. It is generous because a network's prefixes are the network's, so unlike
// the bounds on a search there is nothing here that a wider answer would attribute wrongly.
const DefaultMaxPrefixes = 5000

// Roa is one route origin authorisation: the address holder signing that the network may originate
// the prefix.
type Roa struct {
	// Prefix is the authorised prefix.
	Prefix string `json:"prefix,omitzero"`
	// MaxLength is how far the authorisation may be deaggregated, which is what lets one
	// authorisation cover the smaller prefixes actually announced.
	MaxLength int `json:"max_length,omitzero"`
	// TrustAnchor is the root the authorisation is signed under, which is the registry saying whose
	// space it is.
	TrustAnchor string `json:"trust_anchor,omitzero"`
}

// The shapes the service answers with.
type (
	announcedPrefixesResponse struct {
		Data *announcedPrefixesData `json:"data,omitzero"`
	}

	announcedPrefixesData struct {
		Prefixes []*announcedPrefix `json:"prefixes,omitzero"`
	}

	announcedPrefix struct {
		Prefix string `json:"prefix,omitzero"`
	}

	roasResponse struct {
		Data *roasData `json:"data,omitzero"`
	}

	roasData struct {
		Roas []*roa `json:"roas,omitzero"`
	}

	roa struct {
		Asn       string `json:"asn,omitzero"`
		Prefix    string `json:"prefix,omitzero"`
		MaxLength int    `json:"maxLength,omitzero"`
		Ta        string `json:"ta,omitzero"`
	}
)

type Client struct {
	baseUrl *url.URL
	config  *ripestat_config.Config
}

// NewClient builds a client. Without a base URL it talks to the public service.
func NewClient(options ...ripestat_config.Option) *Client {
	config := ripestat_config.New(options...)

	baseUrl := config.BaseUrl
	if baseUrl == nil {
		baseUrl = defaultBaseUrl
	}
	clientUrl := *baseUrl

	return &Client{baseUrl: &clientUrl, config: config}
}

func (client *Client) sourceApp() string {
	if sourceApp := client.config.SourceApp; sourceApp != "" {
		return sourceApp
	}

	return DefaultSourceApp
}

func (client *Client) maxPrefixes() int {
	if maxPrefixes := client.config.MaxPrefixes; maxPrefixes > 0 {
		return maxPrefixes
	}

	return DefaultMaxPrefixes
}

// fetchOptions is the client's options with the call's appended.
//
// slices.Concat rather than append: the client's options are shared by every call, and appending
// into that slice's spare capacity would have concurrent calls overwrite one another's.
func (client *Client) fetchOptions(options []fetch_config.Option) []fetch_config.Option {
	return slices.Concat(client.config.FetchOptions, options)
}

// requestUrl builds the URL of one data call about one network.
func (client *Client) requestUrl(path string, number string) string {
	requestUrl := *client.baseUrl
	requestUrl.Path += path
	requestUrl.RawQuery = url.Values{
		"resource":            []string{number},
		"sourceapp":           []string{client.sourceApp()},
		"data_overload_limit": []string{"ignore"},
	}.Encode()

	return requestUrl.String()
}

// AnnouncedPrefixes returns the prefixes the network is originating.
//
// It is an observation rather than a claim, and the weaker of the two answers for it: a transit
// provider originates its customers' space, so this attributes a customer's addresses to its
// provider as readily as a party's own to itself.
func (client *Client) AnnouncedPrefixes(
	ctx context.Context,
	number string,
	options ...fetch_config.Option,
) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	normalized := asn.Normalize(number)
	if normalized == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("number"))
	}

	requestUrlString := client.requestUrl(AnnouncedPrefixesPath, normalized)

	_, response, err := altshiftHttpUtils.FetchJson[*announcedPrefixesResponse](
		ctx,
		requestUrlString,
		client.fetchOptions(options)...,
	)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), requestUrlString)
	}

	if response == nil || response.Data == nil {
		return []string{}, nil
	}

	prefixes := make([]string, 0, min(len(response.Data.Prefixes), client.maxPrefixes()))

	for _, announced := range response.Data.Prefixes {
		if announced == nil || announced.Prefix == "" {
			continue
		}

		if len(prefixes) >= client.maxPrefixes() {
			break
		}

		// Read rather than taken as written, so that what a consumer holds is a prefix rather than
		// whatever the service put in the field.
		networks, err := cidr.Prefixes(announced.Prefix)
		if err != nil {
			continue
		}

		prefixes = append(prefixes, networks...)
	}

	slices.Sort(prefixes)

	return slices.Compact(prefixes), nil
}

// Roas returns the route origin authorisations naming the network.
//
// This is the party signing, under RPKI, that the network may originate the prefix -- so unlike an
// announcement it is a statement about who the addresses belong to rather than about what is being
// routed today.
func (client *Client) Roas(
	ctx context.Context,
	number string,
	options ...fetch_config.Option,
) ([]*Roa, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	normalized := asn.Normalize(number)
	if normalized == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("number"))
	}

	requestUrlString := client.requestUrl(RoasPath, normalized)

	_, response, err := altshiftHttpUtils.FetchJson[*roasResponse](
		ctx,
		requestUrlString,
		client.fetchOptions(options)...,
	)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), requestUrlString)
	}

	if response == nil || response.Data == nil {
		return []*Roa{}, nil
	}

	found := make([]*Roa, 0, min(len(response.Data.Roas), client.maxPrefixes()))
	seen := make(map[string]struct{})

	for _, item := range response.Data.Roas {
		if item == nil || item.Prefix == "" {
			continue
		}

		// The service answers about the resource asked for, but an authorisation names one network
		// and a caller reading these alongside another network's should not have to trust that.
		if asn.Normalize(item.Asn) != normalized {
			continue
		}

		if len(found) >= client.maxPrefixes() {
			break
		}

		networks, err := cidr.Prefixes(item.Prefix)
		if err != nil || len(networks) == 0 {
			continue
		}

		if _, ok := seen[networks[0]]; ok {
			continue
		}
		seen[networks[0]] = struct{}{}

		found = append(
			found,
			&Roa{Prefix: networks[0], MaxLength: item.MaxLength, TrustAnchor: item.Ta},
		)
	}

	return found, nil
}

// Prefixes is the prefixes of the authorisations, which is what a caller wanting only the addresses
// asks for.
func Prefixes(roas []*Roa) []string {
	prefixes := make([]string, 0, len(roas))
	for _, item := range roas {
		if item != nil && item.Prefix != "" {
			prefixes = append(prefixes, item.Prefix)
		}
	}

	slices.Sort(prefixes)

	return slices.Compact(prefixes)
}
