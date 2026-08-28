// Package ripe queries the RIPE database for the address space a party holds.
//
// It answers in two steps, which is what makes it worth having. A full-text search finds the objects
// registered at a domain, and an inverse search finds the ranges those objects are referenced by.
// Starting from the domain rather than from an address is the point: it finds space the party holds
// but is not currently using, which nothing that begins with a hostname can see.
//
// Both steps are wider than the obvious version of them, and each way they are wider was a party's
// space going unfound. The search reads roles and organisations as well as people, because a range
// is as often registered to "Example NOC" as to somebody, and because an inetnum's org is the party
// that holds it where its contacts may be a provider's staff. It asks for more than the ten hits
// the database answers with by default. The inverse search reads the abuse contact as well as the
// administrative and technical ones, and asks for inet6num as well as inetnum -- a filter naming
// only the latter excludes the former rather than covering it, so a party holding v6 space looked
// as though it held none.
//
// RIPE covers Europe, the Middle East and Central Asia. A party whose space is registered with
// ARIN, APNIC, AFRINIC or LACNIC will not be found here, and an empty answer is therefore not
// evidence that a party holds nothing.
package ripe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/altshiftab/altshift_domain_tools/pkg/asn"
	"github.com/altshiftab/altshift_domain_tools/pkg/cidr"
	"github.com/altshiftab/altshift_domain_tools/pkg/email"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripe/ripe_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftHttpErrors "github.com/altshiftab/utils_go/pkg/http/errors"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	altshiftHttpUtils "github.com/altshiftab/utils_go/pkg/http/utils"
)

// Domain is the public RIPE REST API.
const Domain = "rest.db.ripe.net"

var defaultBaseUrl = &url.URL{Scheme: "https", Host: Domain}

// The paths the two searches are served at.
const (
	FullTextSearchPath = "/fulltextsearch/select.json"
	SearchPath         = "/search.json"
)

// DefaultMaxPersons bounds how many person objects a domain search reads.
//
// The two steps multiply: every handle found becomes a query of its own. A domain matching a
// hundred people would be a hundred requests against a database that asks callers to be gentle,
// and the ranges behind the hundredth match are not better evidence than those behind the first.
const DefaultMaxPersons = 25

// DefaultMaxOrganizations bounds how many organisation objects a domain search reads, for the same
// reason: every handle found becomes a query of its own.
const DefaultMaxOrganizations = 25

// ErrMalformedRange is an inetnum that is not the "start - end" the database documents.
//
// It is the conversion's own error rather than one of this package's, so that a caller checking for
// it catches both the inetnum that is not a range and the pair of addresses that is not one.
var ErrMalformedRange = cidr.ErrMalformedRange

// ObjectTypes are the objects a domain search reads.
//
// A role as well as a person, because a range is as often registered to "Example NOC" as to
// somebody; and an organisation, because an inetnum's org is the party that holds it, where its
// contacts may be a provider's staff.
var ObjectTypes = []string{"person", "role", "organisation"}

// The attributes a range is looked for under.
var (
	// PersonInverseAttributes are the ways a range points at a contact. Abuse as well as
	// administrative and technical, because a party is sometimes only the abuse contact on space it
	// holds.
	PersonInverseAttributes = []string{"admin-c", "tech-c", "abuse-c"}
	// OrganizationInverseAttributes are the ways a range points at an organisation.
	OrganizationInverseAttributes = []string{"org"}
)

// The other object types read here: the one a network is, and the two a declared origin is.
const (
	TypeAutNum = "aut-num"
	TypeRoute  = "route"
	TypeRoute6 = "route6"
	// TypeDomain is a delegation, which for a reverse zone is the registry recording who the space
	// it names was handed to.
	TypeDomain = "domain"
)

// TypeFilters are the object types a range is written as. Both, because a filter naming only
// inetnum excludes inet6num rather than covering it, and a party holding v6 space would look as
// though it held none.
var TypeFilters = []string{"inetnum", "inet6num"}

// DefaultSearchRows is how many hits a domain search reads.
//
// The database answers with ten unless asked otherwise, which for a party of any size is the first
// ten of something rather than what it holds.
const DefaultSearchRows = 100

// Person is a registered contact -- a person or a role, which the database distinguishes and a walk
// from a domain does not.
type Person struct {
	// NicHandle is the database's identifier for the contact, which is what the ranges reference.
	NicHandle string `json:"nic_handle,omitzero"`
	Name      string `json:"name,omitzero"`
	Email     string `json:"email,omitzero"`
}

// Organization is a registered party.
type Organization struct {
	// Handle is the database's identifier for it, which is what the ranges reference.
	Handle string `json:"handle,omitzero"`
	Name   string `json:"name,omitzero"`
	Email  string `json:"email,omitzero"`
}

// Registrants is what a domain search finds, by what a range would have to reference to be reached
// through it.
type Registrants struct {
	Persons       []*Person       `json:"persons,omitzero"`
	Organizations []*Organization `json:"organizations,omitzero"`
}

// Range is one registered allocation.
type Range struct {
	// Inetnum is the range as the database writes it, "start - end".
	Inetnum string `json:"inetnum,omitzero"`
	NetName string `json:"netname,omitzero"`
	Status  string `json:"status,omitzero"`
	Country string `json:"country,omitzero"`
	// Networks is the range expressed as CIDR. An arbitrary range is not one prefix, so this is
	// often several.
	Networks []string `json:"networks,omitzero"`
}

// The shapes the two searches answer with. They are unexported because they are the database's
// rendering rather than anything a caller should hold: attributes arrive as name/value pairs, which
// is convenient for RIPE and for nobody else.
type (
	fullTextResponse struct {
		Result *fullTextResult `json:"result,omitzero"`
	}

	fullTextResult struct {
		NumFound int            `json:"numFound,omitzero"`
		Docs     []*fullTextDoc `json:"docs,omitzero"`
	}

	fullTextDoc struct {
		Doc *fullTextInner `json:"doc,omitzero"`
	}

	fullTextInner struct {
		Strs []*fullTextStr `json:"strs,omitzero"`
	}

	fullTextStr struct {
		Str *nameValue `json:"str,omitzero"`
	}

	nameValue struct {
		Name  string `json:"name,omitzero"`
		Value string `json:"value,omitzero"`
	}

	searchResponse struct {
		Objects *searchObjects `json:"objects,omitzero"`
	}

	searchObjects struct {
		Object []*searchObject `json:"object,omitzero"`
	}

	searchObject struct {
		Attributes *searchAttributes `json:"attributes,omitzero"`
	}

	searchAttributes struct {
		Attribute []*nameValue `json:"attribute,omitzero"`
	}
)

type Client struct {
	baseUrl *url.URL
	config  *ripe_config.Config
}

// NewClient builds a client. Without a base URL it talks to the public database.
func NewClient(options ...ripe_config.Option) *Client {
	config := ripe_config.New(options...)

	baseUrl := config.BaseUrl
	if baseUrl == nil {
		baseUrl = defaultBaseUrl
	}
	clientUrl := *baseUrl

	return &Client{baseUrl: &clientUrl, config: config}
}

func (client *Client) maxPersons() int {
	if maxPersons := client.config.MaxPersons; maxPersons > 0 {
		return maxPersons
	}

	return DefaultMaxPersons
}

func (client *Client) maxOrganizations() int {
	if maxOrganizations := client.config.MaxOrganizations; maxOrganizations > 0 {
		return maxOrganizations
	}

	return DefaultMaxOrganizations
}

func (client *Client) searchRows() int {
	if searchRows := client.config.SearchRows; searchRows > 0 {
		return searchRows
	}

	return DefaultSearchRows
}

// fetchOptions is the client's options with the call's appended.
//
// slices.Concat rather than append: the client's options are shared by every call, and appending
// into that slice's spare capacity would have concurrent calls overwrite one another's.
func (client *Client) fetchOptions(options []fetch_config.Option) []fetch_config.Option {
	return slices.Concat(client.config.FetchOptions, options)
}

// values reads a doc's attributes into a map, which is how the database's name/value pairs become
// something addressable.
func values(pairs []*nameValue) map[string]string {
	found := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		if pair == nil || pair.Name == "" {
			continue
		}

		// The first wins. An object can repeat an attribute -- several e-mail lines, several
		// admin-c -- and for the fields read here the first is the one meant.
		if _, ok := found[pair.Name]; !ok {
			found[pair.Name] = pair.Value
		}
	}

	return found
}

// Registrants returns everything registered at the domain that a range can be reached through.
//
// One search rather than three, the database being willing to answer for several object types at
// once and every request against it being one a caller should think twice about.
func (client *Client) Registrants(
	ctx context.Context,
	domain string,
	options ...fetch_config.Option,
) (*Registrants, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if domain == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	types := make([]string, 0, len(ObjectTypes))
	for _, objectType := range ObjectTypes {
		types = append(types, "object-type:"+objectType)
	}

	requestUrl := *client.baseUrl
	requestUrl.Path += FullTextSearchPath
	requestUrl.RawQuery = url.Values{
		"q":  []string{fmt.Sprintf("(%s) AND (%s)", domain, strings.Join(types, " OR "))},
		"wt": []string{"json"},
		// Without this the search answers with ten hits whatever it found, which for a party of any
		// size is the first ten of something rather than what it holds.
		"rows": []string{strconv.Itoa(client.searchRows())},
	}.Encode()

	requestUrlString := requestUrl.String()

	_, response, err := altshiftHttpUtils.FetchJson[*fullTextResponse](
		ctx,
		requestUrlString,
		client.fetchOptions(options)...,
	)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), requestUrlString)
	}

	registrants := &Registrants{Persons: []*Person{}, Organizations: []*Organization{}}

	if response == nil || response.Result == nil {
		return registrants, nil
	}

	seen := make(map[string]struct{})

	for _, doc := range response.Result.Docs {
		if doc == nil || doc.Doc == nil {
			continue
		}

		pairs := make([]*nameValue, 0, len(doc.Doc.Strs))
		for _, str := range doc.Doc.Strs {
			if str != nil && str.Str != nil {
				pairs = append(pairs, str.Str)
			}
		}

		attributes := values(pairs)

		address := attributes["e-mail"]

		// The search matched the domain somewhere in the object; only an address at the domain says
		// the object belongs to it. Attributing a stranger's address space to a customer on a postal
		// address or a remark that happens to mention the domain would be a serious error.
		if !email.AtDomain(address, domain) {
			continue
		}

		// What the object is, is what it opens with. A contact -- a person or a role alike -- is
		// named by its nic-hdl and referenced by the ranges it is a contact on; an organisation is
		// named by its own attribute and referenced by their org.
		switch {
		case attributes["nic-hdl"] != "":
			handle := attributes["nic-hdl"]
			if _, ok := seen[handle]; ok || len(registrants.Persons) >= client.maxPersons() {
				continue
			}
			seen[handle] = struct{}{}

			// A role has no person attribute, being a job rather than somebody.
			name := attributes["person"]
			if name == "" {
				name = attributes["role"]
			}

			registrants.Persons = append(
				registrants.Persons,
				&Person{NicHandle: handle, Name: name, Email: address},
			)
		case attributes["organisation"] != "":
			handle := attributes["organisation"]
			if _, ok := seen[handle]; ok || len(registrants.Organizations) >= client.maxOrganizations() {
				continue
			}
			seen[handle] = struct{}{}

			registrants.Organizations = append(
				registrants.Organizations,
				&Organization{Handle: handle, Name: attributes["org-name"], Email: address},
			)
		}
	}

	return registrants, nil
}

// Persons returns the contacts registered with an address at the domain.
func (client *Client) Persons(
	ctx context.Context,
	domain string,
	options ...fetch_config.Option,
) ([]*Person, error) {
	registrants, err := client.Registrants(ctx, domain, options...)
	if err != nil {
		return nil, fmt.Errorf("registrants: %w", err)
	}

	return registrants.Persons, nil
}

// Organizations returns the organisations registered with an address at the domain.
func (client *Client) Organizations(
	ctx context.Context,
	domain string,
	options ...fetch_config.Option,
) ([]*Organization, error) {
	registrants, err := client.Registrants(ctx, domain, options...)
	if err != nil {
		return nil, fmt.Errorf("registrants: %w", err)
	}

	return registrants.Organizations, nil
}

// Ranges returns the allocations the contact administers.
func (client *Client) Ranges(
	ctx context.Context,
	nicHandle string,
	options ...fetch_config.Option,
) ([]*Range, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if nicHandle == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("nic handle"))
	}

	ranges, err := client.inverseRanges(ctx, nicHandle, PersonInverseAttributes, options)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("inverse ranges: %w", err), nicHandle)
	}

	return ranges, nil
}

// OrganizationRanges returns the allocations registered to the organisation.
//
// It is the other half of what a domain search finds, and the better half: an inetnum's org is the
// party that holds it, where its administrative and technical contacts may be a provider's staff.
func (client *Client) OrganizationRanges(
	ctx context.Context,
	handle string,
	options ...fetch_config.Option,
) ([]*Range, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if handle == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("handle"))
	}

	ranges, err := client.inverseRanges(ctx, handle, OrganizationInverseAttributes, options)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("inverse ranges: %w", err), handle)
	}

	return ranges, nil
}

// AutNums returns the autonomous system numbers registered to the contact or the organisation.
//
// It is the same inverse search the allocations use, asked for a different kind of object. What the
// number is worth is that it leads somewhere the registry does not: to the prefixes the network
// authorises and announces, which are not the same set as the allocations.
func (client *Client) AutNums(
	ctx context.Context,
	handle string,
	options ...fetch_config.Option,
) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if handle == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("handle"))
	}

	// The organisation as well as the contacts, an aut-num naming both.
	attributes := slices.Concat(PersonInverseAttributes, OrganizationInverseAttributes)

	objects, err := client.inverse(ctx, handle, attributes, []string{TypeAutNum}, options)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("inverse: %w", err), handle)
	}

	numbers := make([]string, 0, len(objects))

	for _, object := range objects {
		if number := asn.Normalize(object["aut-num"]); number != "" {
			numbers = append(numbers, number)
		}
	}

	slices.Sort(numbers)

	return slices.Compact(numbers), nil
}

// RoutePrefixes returns the prefixes declared as originating from the network.
//
// A route object is the maintainer of the address space authorising a network to announce it, which
// makes it a claim about whose the addresses are rather than an observation of what is routed.
func (client *Client) RoutePrefixes(
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

	objects, err := client.inverse(
		ctx,
		normalized,
		[]string{"origin"},
		[]string{TypeRoute, TypeRoute6},
		options,
	)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("inverse: %w", err), normalized)
	}

	prefixes := make([]string, 0, len(objects))

	for _, object := range objects {
		// The object is about a prefix, and only ever a prefix -- unlike an allocation, which is
		// written as two addresses.
		written := object[TypeRoute]
		if written == "" {
			written = object[TypeRoute6]
		}

		networks, err := cidr.Prefixes(written)
		if err != nil {
			continue
		}

		prefixes = append(prefixes, networks...)
	}

	slices.Sort(prefixes)

	return slices.Compact(prefixes), nil
}

// ReverseZones returns the prefixes whose reverse DNS is delegated to the contact or organisation.
//
// A registry delegates a reverse zone only to the holder of the address space, and records the
// delegation as an object of its own -- so an object naming the party is the registry stating that
// the party holds the block the zone is the zone for. The zone name carries the prefix: a zone has
// one label per octet, so 8.8.8.in-addr.arpa is 8.8.8.0/24 and nothing else.
func (client *Client) ReverseZones(
	ctx context.Context,
	handle string,
	options ...fetch_config.Option,
) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if handle == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("handle"))
	}

	attributes := slices.Concat(PersonInverseAttributes, OrganizationInverseAttributes)

	objects, err := client.inverse(ctx, handle, attributes, []string{TypeDomain}, options)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("inverse: %w", err), handle)
	}

	prefixes := make([]string, 0, len(objects))

	for _, object := range objects {
		// A forward zone is an object of the same type and names no prefix; a classless delegation
		// names a range of addresses rather than a block. Both fail to read and are dropped.
		prefix, err := cidr.FromReverseZone(object[TypeDomain])
		if err != nil {
			continue
		}

		prefixes = append(prefixes, prefix)
	}

	slices.Sort(prefixes)

	return slices.Compact(prefixes), nil
}

// inverse returns the attributes of the objects referencing the handle.
func (client *Client) inverse(
	ctx context.Context,
	handle string,
	attributes []string,
	types []string,
	options []fetch_config.Option,
) ([]map[string]string, error) {
	requestUrl := *client.baseUrl
	requestUrl.Path += SearchPath
	requestUrl.RawQuery = url.Values{
		"query-string":      []string{handle},
		"inverse-attribute": attributes,
		"type-filter":       types,
		"flags":             []string{"no-referenced"},
	}.Encode()

	requestUrlString := requestUrl.String()

	_, response, err := altshiftHttpUtils.FetchJson[*searchResponse](
		ctx,
		requestUrlString,
		client.fetchOptions(options)...,
	)
	if err != nil {
		// A handle with nothing behind it is answered with a 404 rather than an empty result, which
		// is an answer rather than a failure.
		if statusError, ok := errors.AsType[*altshiftHttpErrors.Non2xxStatusCodeError](err); ok &&
			statusError != nil && statusError.StatusCode == http.StatusNotFound {
			return []map[string]string{}, nil
		}

		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), requestUrlString)
	}

	if response == nil || response.Objects == nil {
		return []map[string]string{}, nil
	}

	found := make([]map[string]string, 0, len(response.Objects.Object))

	for _, object := range response.Objects.Object {
		if object == nil || object.Attributes == nil {
			continue
		}

		found = append(found, values(object.Attributes.Attribute))
	}

	return found, nil
}

// inverseRanges returns the allocations referencing the handle in one of the attributes.
func (client *Client) inverseRanges(
	ctx context.Context,
	handle string,
	attributes []string,
	options []fetch_config.Option,
) ([]*Range, error) {
	requestUrl := *client.baseUrl
	requestUrl.Path += SearchPath
	requestUrl.RawQuery = url.Values{
		"query-string":      []string{handle},
		"inverse-attribute": attributes,
		// Both families. A filter naming only inetnum excludes inet6num rather than covering it,
		// and a party holding v6 space would look as though it held none.
		"type-filter": TypeFilters,
		// Without this the database returns every object referenced by each match, which is a great
		// deal of data none of it needs.
		"flags": []string{"no-referenced"},
	}.Encode()

	requestUrlString := requestUrl.String()

	_, response, err := altshiftHttpUtils.FetchJson[*searchResponse](
		ctx,
		requestUrlString,
		client.fetchOptions(options)...,
	)
	if err != nil {
		// A handle with no ranges is answered with a 404 rather than an empty result, which is an
		// answer rather than a failure.
		if statusError, ok := errors.AsType[*altshiftHttpErrors.Non2xxStatusCodeError](err); ok &&
			statusError != nil && statusError.StatusCode == http.StatusNotFound {
			return []*Range{}, nil
		}

		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), requestUrlString)
	}

	if response == nil || response.Objects == nil {
		return []*Range{}, nil
	}

	ranges := make([]*Range, 0, len(response.Objects.Object))

	for _, object := range response.Objects.Object {
		if object == nil || object.Attributes == nil {
			continue
		}

		attributes := values(object.Attributes.Attribute)

		inetnum := attributes["inetnum"]
		if inetnum == "" {
			inetnum = attributes["inet6num"]
		}
		if inetnum == "" {
			continue
		}

		networks, err := Networks(inetnum)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("networks: %w", err), inetnum)
		}

		ranges = append(
			ranges,
			&Range{
				Inetnum:  inetnum,
				NetName:  attributes["netname"],
				Status:   attributes["status"],
				Country:  attributes["country"],
				Networks: networks,
			},
		)
	}

	return ranges, nil
}

// Networks expresses an inetnum as CIDR.
//
// The database writes an allocation as a first and last address, and an arbitrary range of
// addresses is not one prefix, so this is however many prefixes it takes to cover the range exactly
// rather than the one that would have to be too large.
func Networks(inetnum string) ([]string, error) {
	first, last, found := strings.Cut(inetnum, "-")
	if !found {
		// A single address, or already a prefix. An inet6num is written this way.
		networks, err := cidr.Prefixes(inetnum)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("prefixes: %w", err), inetnum)
		}

		return networks, nil
	}

	networks, err := cidr.CoverText(first, last)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("cover text: %w", err), inetnum)
	}

	return networks, nil
}
