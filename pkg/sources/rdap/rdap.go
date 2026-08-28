// Package rdap queries a registry's RDAP service for the address space a party holds.
//
// RDAP is the protocol every registry answers, which makes it the one way into the databases that
// offer nothing else. What it does not offer is a way in from a domain: RFC 9082 defines exactly two
// searchable properties for a party, its name and its handle, and no registry adds a third. An
// inverse search on an e-mail address, which is what a walk from a domain wants, does not exist
// here and is refused where it does exist.
//
// So the name is the bridge, as it is at ARIN, and the check is the same one: a party found by name
// is kept only where the contact card on it carries an address at the domain. The name can be
// guessed from the domain's own label, or handed over from a registry that does search by domain --
// the company a RIPE or ARIN contact gave is exactly the term wanted here.
//
// The registries disagree about how a name search matches, which is what NameSuffix is for: APNIC
// matches a prefix and finds nothing without a trailing asterisk, AFRINIC matches a token and finds
// nothing with one.
package rdap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/altshiftab/altshift_domain_tools/pkg/asn"
	"github.com/altshiftab/altshift_domain_tools/pkg/cidr"
	"github.com/altshiftab/altshift_domain_tools/pkg/email"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/rdap/rdap_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftHttpErrors "github.com/altshiftab/utils_go/pkg/http/errors"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	altshiftHttpUtils "github.com/altshiftab/utils_go/pkg/http/utils"
)

// The servers this is known to work against, and the suffix each of them needs on a name.
var (
	ApnicBaseUrl   = &url.URL{Scheme: "https", Host: "rdap.apnic.net"}
	AfrinicBaseUrl = &url.URL{Scheme: "https", Host: "rdap.afrinic.net", Path: "/rdap"}
)

// ApnicNameSuffix is the asterisk APNIC needs to match a name by prefix. AFRINIC needs none, so its
// suffix is the empty string and has no constant.
const ApnicNameSuffix = "*"

// The paths a party is searched for and read at.
const (
	EntitySearchPath = "/entities"
	EntityPath       = "/entity"
)

// ContentType is what an RDAP server answers with. It is asked for by name because a server is
// entitled to refuse a request that does not, and one of them does.
const ContentType = "application/rdap+json"

// DefaultMaxNames bounds how many names are searched for.
const DefaultMaxNames = 8

// DefaultMaxEntities bounds how many parties a name search turns up are read in full.
//
// A short name matches a great many, and the search answers without the ranges, so each one is a
// request of its own against a database that asks callers to be gentle.
const DefaultMaxEntities = 25

// KindOrganization is what a party's contact card says it is where the party is an organisation
// rather than a person. Only organisations hold allocations here; a person or a role is a contact
// on one.
const KindOrganization = "org"

// Entity is a registered party.
type Entity struct {
	Handle string `json:"handle,omitzero"`
	Name   string `json:"name,omitzero"`
	// Kind is what the contact card says the party is -- an organisation, an individual, a group.
	Kind string `json:"kind,omitzero"`
	// Email is the address on the party's contact card, and is what says whether the party is the
	// domain's or a stranger the name search happened to reach.
	Email string `json:"email,omitzero"`
	// Ranges are the allocations registered to it. A search answers without them; reading the party
	// itself is what fills them in.
	Ranges []*Range `json:"ranges,omitzero"`
	// AutNums are the autonomous system numbers registered to it, which lead to the prefixes the
	// networks authorise and announce -- a set the allocations do not cover.
	AutNums []string `json:"aut_nums,omitzero"`
}

// Range is one registered allocation.
type Range struct {
	Handle  string `json:"handle,omitzero"`
	NetName string `json:"net_name,omitzero"`
	// StartAddress and EndAddress are the range as the server writes it.
	StartAddress string `json:"start_address,omitzero"`
	EndAddress   string `json:"end_address,omitzero"`
	Country      string `json:"country,omitzero"`
	// Entity is the party it was reached through.
	Entity *Entity `json:"entity,omitzero"`
	// Networks is the range expressed as CIDR.
	Networks []string `json:"networks,omitzero"`
}

// The shapes an RDAP server answers with.
type (
	entitySearchResponse struct {
		EntitySearchResults []*entity `json:"entitySearchResults,omitzero"`
	}

	entity struct {
		Handle string `json:"handle,omitzero"`
		// VcardArray is the contact card, in the two levels of array jCard wraps it in.
		VcardArray []any      `json:"vcardArray,omitzero"`
		Networks   []*network `json:"networks,omitzero"`
		Autnums    []*autnum  `json:"autnums,omitzero"`
	}

	autnum struct {
		Handle      string `json:"handle,omitzero"`
		StartAutnum uint32 `json:"startAutnum,omitzero"`
		EndAutnum   uint32 `json:"endAutnum,omitzero"`
	}

	network struct {
		Handle       string `json:"handle,omitzero"`
		Name         string `json:"name,omitzero"`
		StartAddress string `json:"startAddress,omitzero"`
		EndAddress   string `json:"endAddress,omitzero"`
		Country      string `json:"country,omitzero"`
		// Cidr0Cidrs is the range already expressed as prefixes, by the cidr0 extension every
		// registry here carries. It is preferred to the two addresses because it is the server's own
		// answer rather than one worked out from them.
		Cidr0Cidrs []*cidr0 `json:"cidr0_cidrs,omitzero"`
	}

	cidr0 struct {
		V4Prefix string `json:"v4prefix,omitzero"`
		V6Prefix string `json:"v6prefix,omitzero"`
		Length   int    `json:"length,omitzero"`
	}
)

type Client struct {
	baseUrl *url.URL
	config  *rdap_config.Config
}

// NewClient builds a client for one registry's server. A client without a base URL answers every
// call with an error, there being no server it could sensibly mean.
func NewClient(options ...rdap_config.Option) *Client {
	config := rdap_config.New(options...)

	var baseUrl *url.URL
	if config.BaseUrl != nil {
		clientUrl := *config.BaseUrl
		baseUrl = &clientUrl
	}

	return &Client{baseUrl: baseUrl, config: config}
}

func (client *Client) maxNames() int {
	if maxNames := client.config.MaxNames; maxNames > 0 {
		return maxNames
	}

	return DefaultMaxNames
}

func (client *Client) maxEntities() int {
	if maxEntities := client.config.MaxEntities; maxEntities > 0 {
		return maxEntities
	}

	return DefaultMaxEntities
}

// fetchOptions is the RDAP content type, then the client's options, then the call's.
//
// In that order so that either can override it: the content type is a default this package sets
// rather than a rule it imposes.
func (client *Client) fetchOptions(options []fetch_config.Option) []fetch_config.Option {
	return slices.Concat(
		[]fetch_config.Option{fetch_config.WithHeaders(map[string]string{"Accept": ContentType})},
		client.config.FetchOptions,
		options,
	)
}

// notFound reports whether the failure is the server saying there is nothing.
//
// A search that matched nothing is answered with a 404 by some of these servers and with an empty
// result by others, so both have to be read as the same answer.
func notFound(err error) bool {
	statusError, ok := errors.AsType[*altshiftHttpErrors.Non2xxStatusCodeError](err)

	return ok && statusError != nil && statusError.StatusCode == http.StatusNotFound
}

// vcardProperty is the first value written for a property on a contact card.
//
// RDAP renders a card as jCard (RFC 7095): an array whose first element is the string "vcard" and
// whose second is the properties, each of them an array of four -- the name, its parameters, its
// type and its value. A property whose value is not a string is skipped rather than read, an address
// being written as an array of its lines.
func vcardProperty(card []any, name string) string {
	if len(card) < 2 {
		return ""
	}

	properties, ok := card[1].([]any)
	if !ok {
		return ""
	}

	for _, item := range properties {
		property, ok := item.([]any)
		if !ok || len(property) < 4 {
			continue
		}

		propertyName, ok := property[0].(string)
		if !ok || !strings.EqualFold(propertyName, name) {
			continue
		}

		if value, ok := property[3].(string); ok && value != "" {
			return value
		}
	}

	return ""
}

// networks expresses the allocation as CIDR.
func (item *network) networks() ([]string, error) {
	if item == nil {
		return nil, nil
	}

	found := make([]string, 0, len(item.Cidr0Cidrs))

	for _, written := range item.Cidr0Cidrs {
		if written == nil {
			continue
		}

		prefix := written.V4Prefix
		if prefix == "" {
			prefix = written.V6Prefix
		}
		if prefix == "" {
			continue
		}

		networks, err := cidr.Prefixes(fmt.Sprintf("%s/%d", prefix, written.Length))
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("prefixes: %w", err), prefix, written.Length)
		}

		found = append(found, networks...)
	}

	if len(found) != 0 {
		return found, nil
	}

	// A server that does not carry the extension still writes the two addresses, and an arbitrary
	// range of addresses is not one prefix.
	if item.StartAddress == "" || item.EndAddress == "" {
		return nil, nil
	}

	networks, err := cidr.CoverText(item.StartAddress, item.EndAddress)
	if err != nil {
		return nil, altshiftErrors.New(
			fmt.Errorf("cover text: %w", err),
			item.StartAddress,
			item.EndAddress,
		)
	}

	return networks, nil
}

// convert reads a server's party into the shape a caller holds.
func convert(found *entity) (*Entity, error) {
	if found == nil {
		return nil, nil
	}

	converted := &Entity{
		Handle:  found.Handle,
		Name:    vcardProperty(found.VcardArray, "fn"),
		Kind:    strings.ToLower(vcardProperty(found.VcardArray, "kind")),
		Email:   vcardProperty(found.VcardArray, "email"),
		Ranges:  make([]*Range, 0, len(found.Networks)),
		AutNums: autNums(found.Autnums),
	}

	for _, item := range found.Networks {
		if item == nil {
			continue
		}

		networks, err := item.networks()
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("networks: %w", err), item.Handle)
		}

		if len(networks) == 0 {
			continue
		}

		converted.Ranges = append(
			converted.Ranges,
			&Range{
				Handle:       item.Handle,
				NetName:      item.Name,
				StartAddress: item.StartAddress,
				EndAddress:   item.EndAddress,
				Country:      item.Country,
				Entity:       converted,
				Networks:     networks,
			},
		)
	}

	return converted, nil
}

func (client *Client) requestUrl(path string, segments ...string) (string, error) {
	if client.baseUrl == nil {
		return "", altshiftErrors.NewWithTrace(nil_error.New("base url"))
	}

	requestUrl := *client.baseUrl
	requestUrl.Path += path

	requestUrlString := requestUrl.String()
	for _, segment := range segments {
		requestUrlString += "/" + url.PathEscape(segment)
	}

	return requestUrlString, nil
}

// Entities returns the parties whose name matches the term.
//
// How it matches is the server's business and not the same at each of them, which is what the name
// suffix settles. The parties come back without their ranges, so a caller wanting those reads each
// party in turn.
func (client *Client) Entities(
	ctx context.Context,
	name string,
	options ...fetch_config.Option,
) ([]*Entity, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if name == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("name"))
	}

	searchUrl, err := client.requestUrl(EntitySearchPath)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("request url: %w", err))
	}

	requestUrl, err := url.Parse(searchUrl)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("url parse: %w", err), searchUrl)
	}
	requestUrl.RawQuery = url.Values{"fn": []string{name + client.config.NameSuffix}}.Encode()

	requestUrlString := requestUrl.String()

	_, response, err := altshiftHttpUtils.FetchJson[*entitySearchResponse](
		ctx,
		requestUrlString,
		client.fetchOptions(options)...,
	)
	if err != nil {
		if notFound(err) {
			return []*Entity{}, nil
		}

		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), requestUrlString)
	}

	if response == nil {
		return []*Entity{}, nil
	}

	entities := make([]*Entity, 0, len(response.EntitySearchResults))

	for _, found := range response.EntitySearchResults {
		if found == nil || found.Handle == "" {
			continue
		}

		converted, err := convert(found)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("convert: %w", err), found.Handle)
		}

		entities = append(entities, converted)
	}

	return entities, nil
}

// Entity returns one party in full, ranges included, or nil where there is no such party.
func (client *Client) Entity(
	ctx context.Context,
	handle string,
	options ...fetch_config.Option,
) (*Entity, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if handle == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("handle"))
	}

	requestUrlString, err := client.requestUrl(EntityPath, handle)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("request url: %w", err), handle)
	}

	_, response, err := altshiftHttpUtils.FetchJson[*entity](
		ctx,
		requestUrlString,
		client.fetchOptions(options)...,
	)
	if err != nil {
		if notFound(err) {
			return nil, nil
		}

		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), requestUrlString)
	}

	if response == nil {
		return nil, nil
	}

	converted, err := convert(response)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("convert: %w", err), handle)
	}

	return converted, nil
}

// autNums reads the networks registered to a party.
//
// A block of them is written as a range of numbers, and only a block of one is a network somebody
// holds -- a wider one is a registry's own reservation, which belongs to nobody in particular.
func autNums(found []*autnum) []string {
	numbers := make([]string, 0, len(found))

	for _, item := range found {
		if item == nil {
			continue
		}

		number := asn.Normalize(item.Handle)
		if number == "" && item.StartAutnum != 0 && item.StartAutnum == item.EndAutnum {
			number = asn.FromNumber(item.StartAutnum)
		}

		if number != "" {
			numbers = append(numbers, number)
		}
	}

	slices.Sort(numbers)

	return slices.Compact(numbers)
}

// organizationFirst sorts organisations before everything else.
func organizationFirst(found *Entity) int {
	if found != nil && found.Kind == KindOrganization {
		return 0
	}

	return 1
}

// Ranges returns the address space registered to the parties the names reach and the domain claims.
//
// The names are a guess and the contact card is the check, which is the whole shape of this: a name
// that reaches a stranger costs a request, and a name that reaches nobody costs one too. Only a
// party whose card carries an address at the domain has its space attributed.
func (client *Client) Ranges(
	ctx context.Context,
	domain string,
	names []string,
	options ...fetch_config.Option,
) ([]*Range, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if domain == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	ranges := make([]*Range, 0)
	considered := make(map[string]struct{})

	for index, name := range names {
		if index >= client.maxNames() {
			break
		}

		if name == "" {
			continue
		}

		entities, err := client.Entities(ctx, name, options...)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("entities: %w", err), name)
		}

		// Organisations first, because they are the only parties that hold allocations: a person or
		// a role is a contact on one. A name matching a party of any size answers with its people
		// as readily as with itself, and without this the bound below would routinely be spent on
		// contacts before it reached the organisation that had the ranges.
		entities = slices.SortedStableFunc(slices.Values(entities), func(a *Entity, b *Entity) int {
			return organizationFirst(a) - organizationFirst(b)
		})

		for _, found := range entities {
			if found == nil || found.Handle == "" {
				continue
			}

			if _, ok := considered[found.Handle]; ok {
				continue
			}

			// A card on the search result is enough to drop a stranger before it costs a request.
			// Some servers carry one there and some do not, so its absence decides nothing.
			if found.Email != "" && !email.AtDomain(found.Email, domain) {
				continue
			}

			if len(considered) >= client.maxEntities() {
				break
			}
			considered[found.Handle] = struct{}{}

			read, err := client.Entity(ctx, found.Handle, options...)
			if err != nil {
				return nil, altshiftErrors.New(fmt.Errorf("entity: %w", err), found.Handle)
			}

			// The name found it; the address on the card is what says it is the domain's.
			if read == nil || !email.AtDomain(read.Email, domain) {
				continue
			}

			ranges = append(ranges, read.Ranges...)
		}
	}

	return ranges, nil
}
