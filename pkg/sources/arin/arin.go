// Package arin queries the ARIN database for the address space a party holds.
//
// It answers the same question the RIPE package does, and starting from the domain rather than from
// an address is the point in the same way: it finds space the party holds but is not currently
// using, which nothing that begins with a hostname can see.
//
// The route there is longer, because ARIN's searches are different ones. It offers a search from a
// domain to a contact -- a real search over the contacts' e-mail addresses, rather than the
// full-text guess RIPE answers with -- but no search from a contact to the space they administer.
// Only an organisation holds ranges, and an organisation is reachable by name. So the name is the
// bridge: it is read off the contacts the domain search found, and the organisations it turns up
// are then checked back against those same contacts before anything is attributed. A name that
// matched the wrong organisation costs a request rather than a wrong answer.
//
// ARIN covers North America. A party whose space is registered with RIPE, APNIC, AFRINIC or LACNIC
// will not be found here, and an empty answer is therefore not evidence that a party holds nothing.
// A search is answered with at most 256 results, so a very large party is reported in part.
package arin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/altshiftab/altshift_domain_tools/pkg/cidr"
	"github.com/altshiftab/altshift_domain_tools/pkg/email"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/arin/arin_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftHttpErrors "github.com/altshiftab/utils_go/pkg/http/errors"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	altshiftHttpUtils "github.com/altshiftab/utils_go/pkg/http/utils"
	"github.com/altshiftab/utils_go/pkg/net/types/domain_parts"
)

// Domain is the public ARIN Whois-RWS API.
const Domain = "whois.arin.net"

var defaultBaseUrl = &url.URL{Scheme: "https", Host: Domain}

// The paths the searches and the objects are served at.
const (
	PersonSearchPath       = "/rest/pocs"
	PersonPath             = "/rest/poc"
	OrganizationSearchPath = "/rest/orgs"
	OrganizationPath       = "/rest/org"
)

// DefaultMaxPersons bounds how many contacts a domain search reads in full.
//
// The steps multiply: the search answers with handles alone, so the company a contact belongs to --
// the only bridge ARIN offers from a domain to an organisation -- is a request per contact. The
// twenty-sixth contact of a domain is not better evidence than the first.
const DefaultMaxPersons = 25

// DefaultMaxOrganizations bounds how many organisations a name search's results are checked.
//
// A short name matches a great many organisations, and each one is two further requests against a
// database that asks callers to be gentle.
const DefaultMaxOrganizations = 25

// Person is a registered point of contact.
type Person struct {
	// Handle is the database's identifier for the contact, which is what an organisation references.
	Handle string `json:"handle,omitzero"`
	Name   string `json:"name,omitzero"`
	// Company is the organisation the contact says they belong to. It is what the organisation
	// search is given, ARIN offering no search from a contact to the organisations naming them.
	Company string `json:"company,omitzero"`
	Email   string `json:"email,omitzero"`
}

// Organization is a registered party.
type Organization struct {
	Handle string `json:"handle,omitzero"`
	Name   string `json:"name,omitzero"`
}

// Range is one registered allocation.
type Range struct {
	Handle string `json:"handle,omitzero"`
	// NetName is what the registry called the allocation.
	NetName string `json:"net_name,omitzero"`
	// StartAddress and EndAddress are the range as the database writes it.
	StartAddress string `json:"start_address,omitzero"`
	EndAddress   string `json:"end_address,omitzero"`
	// Organization is the party it is registered to.
	Organization *Organization `json:"organization,omitzero"`
	// Networks is the range expressed as CIDR. An arbitrary range is not one prefix, so this is
	// often several.
	Networks []string `json:"networks,omitzero"`
}

// The shapes the database answers with. They are unexported because they are ARIN's rendering
// rather than anything a caller should hold: the JSON is mapped from XML by the BadgerFish
// convention, so an element's text arrives under "$" and its attributes under names beginning with
// "@", which is convenient for a mechanical translation and for nobody else.
type (
	// text is an element with nothing in it but its own content.
	text struct {
		Value string `json:"$,omitzero"`
	}

	// reference is a search hit: a link to an object, with enough of the object on it to decide
	// whether to follow the link.
	reference struct {
		Handle string `json:"@handle,omitzero"`
		Name   string `json:"@name,omitzero"`
	}

	personSearchResponse struct {
		Pocs *personRefs `json:"pocs,omitzero"`
	}

	personRefs struct {
		PocRef list[reference] `json:"pocRef,omitzero"`
	}

	personResponse struct {
		Poc *person `json:"poc,omitzero"`
	}

	person struct {
		Handle      *text   `json:"handle,omitzero"`
		CompanyName *text   `json:"companyName,omitzero"`
		FirstName   *text   `json:"firstName,omitzero"`
		LastName    *text   `json:"lastName,omitzero"`
		Emails      *emails `json:"emails,omitzero"`
	}

	emails struct {
		Email list[text] `json:"email,omitzero"`
	}

	organizationSearchResponse struct {
		Orgs *organizationRefs `json:"orgs,omitzero"`
	}

	organizationRefs struct {
		OrgRef list[reference] `json:"orgRef,omitzero"`
	}

	organizationPersonsResponse struct {
		Pocs *personLinkRefs `json:"pocs,omitzero"`
	}

	personLinkRefs struct {
		PocLinkRef list[personLink] `json:"pocLinkRef,omitzero"`
	}

	// personLink is a contact on an organisation, with the role they hold there.
	personLink struct {
		Handle   string `json:"@handle,omitzero"`
		Function string `json:"@function,omitzero"`
	}

	networksResponse struct {
		Nets *networkRefs `json:"nets,omitzero"`
	}

	networkRefs struct {
		NetRef list[networkRef] `json:"netRef,omitzero"`
	}

	networkRef struct {
		Handle       string `json:"@handle,omitzero"`
		Name         string `json:"@name,omitzero"`
		StartAddress string `json:"@startAddress,omitzero"`
		EndAddress   string `json:"@endAddress,omitzero"`
	}
)

// list is a field the database writes as an object when there is one of something and as an array
// when there are several.
//
// That is what the mapping from XML costs: a document with one <pocRef> child and a document with
// several are the same document to a reader that walks elements, and the difference only appears
// once it has been rendered as JSON. A plain slice would decode the several and fail on the one,
// which is the case a search narrow enough to match exactly what was asked for produces.
type list[T any] []*T

func (items *list[T]) UnmarshalJSON(data []byte) error {
	if items == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("items"))
	}

	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}

	if data[0] == '[' {
		var several []*T
		if err := json.Unmarshal(data, &several); err != nil {
			return altshiftErrors.NewWithTrace(fmt.Errorf("json unmarshal (several): %w", err))
		}

		*items = several

		return nil
	}

	var one T
	if err := json.Unmarshal(data, &one); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("json unmarshal (one): %w", err))
	}

	*items = []*T{&one}

	return nil
}

// value is the content of an element that may not be there at all.
func (element *text) value() string {
	if element == nil {
		return ""
	}

	return element.Value
}

type Client struct {
	baseUrl *url.URL
	config  *arin_config.Config
}

// NewClient builds a client. Without a base URL it talks to the public database.
func NewClient(options ...arin_config.Option) *Client {
	config := arin_config.New(options...)

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

// fetchOptions is the client's options with the call's appended.
//
// slices.Concat rather than append: the client's options are shared by every call, and appending
// into that slice's spare capacity would have concurrent calls overwrite one another's.
func (client *Client) fetchOptions(options []fetch_config.Option) []fetch_config.Option {
	return slices.Concat(client.config.FetchOptions, options)
}

// searchUrl builds a search URL.
//
// ARIN takes a search term as a matrix parameter -- a name and a value on the path segment itself,
// after a semicolon -- rather than as a query string, so the URL is built rather than assembled
// with url.Values. The value is escaped as a path segment, which is what keeps a term holding a
// slash or a semicolon from becoming part of the path.
func (client *Client) searchUrl(path string, name string, value string) string {
	requestUrl := *client.baseUrl
	requestUrl.Path += path

	return requestUrl.String() + ";" + name + "=" + url.PathEscape(value)
}

// objectUrl builds the URL of an object, or of something hanging off one.
func (client *Client) objectUrl(path string, segments ...string) string {
	requestUrl := *client.baseUrl
	requestUrl.Path += path

	requestUrlString := requestUrl.String()
	for _, segment := range segments {
		requestUrlString += "/" + url.PathEscape(segment)
	}

	return requestUrlString
}

// notFound reports whether the failure is the database saying there is nothing.
//
// It answers a search that matched nothing with a 404 rather than with an empty result, which is an
// answer rather than a failure.
func notFound(err error) bool {
	statusError, ok := errors.AsType[*altshiftHttpErrors.Non2xxStatusCodeError](err)

	return ok && statusError != nil && statusError.StatusCode == http.StatusNotFound
}

// Persons returns the contacts registered with an address at the domain.
//
// The search answers with handles and display names alone, so each hit is read in full: the company
// and the e-mail address are on the object rather than on the search result, and both are needed --
// the company to search organisations by, the address to confirm the hit belongs to the domain.
func (client *Client) Persons(
	ctx context.Context,
	domain string,
	options ...fetch_config.Option,
) ([]*Person, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if domain == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	requestUrlString := client.searchUrl(PersonSearchPath, "domain", domain)

	_, response, err := altshiftHttpUtils.FetchJson[*personSearchResponse](
		ctx,
		requestUrlString,
		client.fetchOptions(options)...,
	)
	if err != nil {
		if notFound(err) {
			return []*Person{}, nil
		}

		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), requestUrlString)
	}

	if response == nil || response.Pocs == nil {
		return []*Person{}, nil
	}

	persons := make([]*Person, 0, min(len(response.Pocs.PocRef), client.maxPersons()))
	seen := make(map[string]struct{})
	read := 0

	for _, hit := range response.Pocs.PocRef {
		if hit == nil || hit.Handle == "" {
			continue
		}

		if _, ok := seen[hit.Handle]; ok {
			continue
		}
		seen[hit.Handle] = struct{}{}

		// The bound is on the hits read rather than on the contacts kept, because reading is what
		// costs: a search answers with as many as 256 hits, and a bound counting only what survives
		// the check below would read all of them whenever few do.
		if read >= client.maxPersons() {
			break
		}
		read++

		found, err := client.Person(ctx, hit.Handle, options...)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("person: %w", err), hit.Handle)
		}

		// A contact the search matched but the object does not confirm is left where it was found.
		if found == nil || !email.AtDomain(found.Email, domain) {
			continue
		}

		persons = append(persons, found)
	}

	return persons, nil
}

// Person returns one contact, or nil where there is no such contact.
func (client *Client) Person(
	ctx context.Context,
	handle string,
	options ...fetch_config.Option,
) (*Person, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if handle == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("handle"))
	}

	requestUrlString := client.objectUrl(PersonPath, handle)

	_, response, err := altshiftHttpUtils.FetchJson[*personResponse](
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

	if response == nil || response.Poc == nil {
		return nil, nil
	}

	email := ""
	if response.Poc.Emails != nil && len(response.Poc.Emails.Email) != 0 {
		// The first wins. A contact can hold several addresses, and the object lists the one meant
		// first.
		email = response.Poc.Emails.Email[0].value()
	}

	// The handle on the object rather than the one asked for, an object being free to answer for
	// another.
	found := &Person{
		Handle:  response.Poc.Handle.value(),
		Name:    strings.TrimSpace(response.Poc.FirstName.value() + " " + response.Poc.LastName.value()),
		Company: response.Poc.CompanyName.value(),
		Email:   email,
	}

	if found.Handle == "" {
		found.Handle = handle
	}

	return found, nil
}

// Organizations returns the organisations whose name begins with the term.
//
// The search is a prefix search: ARIN answers an exact name with nothing at all unless the name is
// the whole of the organisation's, and a party is registered under "Example, Inc." as readily as
// under "Example". So the term is the beginning of a name rather than a name.
func (client *Client) Organizations(
	ctx context.Context,
	name string,
	options ...fetch_config.Option,
) ([]*Organization, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if name == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("name"))
	}

	requestUrlString := client.searchUrl(OrganizationSearchPath, "name", name+"*")

	_, response, err := altshiftHttpUtils.FetchJson[*organizationSearchResponse](
		ctx,
		requestUrlString,
		client.fetchOptions(options)...,
	)
	if err != nil {
		if notFound(err) {
			return []*Organization{}, nil
		}

		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), requestUrlString)
	}

	if response == nil || response.Orgs == nil {
		return []*Organization{}, nil
	}

	organizations := make([]*Organization, 0, len(response.Orgs.OrgRef))

	for _, hit := range response.Orgs.OrgRef {
		if hit == nil || hit.Handle == "" {
			continue
		}

		organizations = append(organizations, &Organization{Handle: hit.Handle, Name: hit.Name})
	}

	return organizations, nil
}

// OrganizationPersons returns the handles of the contacts registered on the organisation.
//
// It is what an organisation found by name is checked with: an organisation whose contacts include
// one registered at the domain is the domain's, and one whose contacts do not is a stranger that
// happens to share the beginning of a name.
func (client *Client) OrganizationPersons(
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

	requestUrlString := client.objectUrl(OrganizationPath, handle, "pocs")

	_, response, err := altshiftHttpUtils.FetchJson[*organizationPersonsResponse](
		ctx,
		requestUrlString,
		client.fetchOptions(options)...,
	)
	if err != nil {
		if notFound(err) {
			return []string{}, nil
		}

		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), requestUrlString)
	}

	if response == nil || response.Pocs == nil {
		return []string{}, nil
	}

	handles := make([]string, 0, len(response.Pocs.PocLinkRef))

	for _, link := range response.Pocs.PocLinkRef {
		if link == nil || link.Handle == "" {
			continue
		}

		handles = append(handles, link.Handle)
	}

	// The same contact holds several roles on an organisation, and is listed once for each.
	slices.Sort(handles)

	return slices.Compact(handles), nil
}

// OrganizationRanges returns the allocations registered to the organisation.
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

	requestUrlString := client.objectUrl(OrganizationPath, handle, "nets")

	_, response, err := altshiftHttpUtils.FetchJson[*networksResponse](
		ctx,
		requestUrlString,
		client.fetchOptions(options)...,
	)
	if err != nil {
		// An organisation holding no space is answered with a 404 rather than an empty result.
		if notFound(err) {
			return []*Range{}, nil
		}

		return nil, altshiftErrors.New(fmt.Errorf("fetch json: %w", err), requestUrlString)
	}

	if response == nil || response.Nets == nil {
		return []*Range{}, nil
	}

	ranges := make([]*Range, 0, len(response.Nets.NetRef))

	for _, hit := range response.Nets.NetRef {
		if hit == nil || hit.StartAddress == "" || hit.EndAddress == "" {
			continue
		}

		networks, err := cidr.CoverText(hit.StartAddress, hit.EndAddress)
		if err != nil {
			return nil, altshiftErrors.New(
				fmt.Errorf("cover text: %w", err),
				hit.StartAddress,
				hit.EndAddress,
			)
		}

		ranges = append(
			ranges,
			&Range{
				Handle:       hit.Handle,
				NetName:      hit.Name,
				StartAddress: hit.StartAddress,
				EndAddress:   hit.EndAddress,
				Networks:     networks,
			},
		)
	}

	return ranges, nil
}

// SearchNames returns the names to search organisations by, most specific first.
//
// They are the companies given, trimmed at the first comma so that "Example, Inc." also reaches the
// organisation registered as "Example, Inc" or as "Example"; and the domain's own label, for the
// party whose contacts left the company out or gave a person's name instead. A name that matches
// nothing costs a request, and a name that matches the wrong organisation costs another, because
// what the search finds is checked before it is used.
//
// It takes the companies rather than the contacts holding them because the same terms are what the
// registries that only search by name are given, and there the names come from somewhere else.
func SearchNames(domain string, companies []string) []string {
	names := make([]string, 0, len(companies)+1)
	seen := make(map[string]struct{})

	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}

		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}

		names = append(names, name)
	}

	trimmed := make([]string, 0, len(companies))
	for _, company := range companies {
		name, _, _ := strings.Cut(company, ",")
		if name = strings.TrimSpace(name); name != "" {
			trimmed = append(trimmed, name)
		}
	}

	// Sorted, so that the bound on how many organisations are checked falls in the same place on
	// every run rather than wherever the search happened to order its hits.
	slices.Sort(trimmed)
	for _, company := range trimmed {
		add(company)
	}

	add(label(domain))

	return names
}

// label is the domain's own name, without what it is registered under.
func label(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))

	registered := domain
	if parts := domain_parts.New(domain); parts != nil && parts.RegisteredDomain != "" {
		registered = parts.RegisteredDomain
	}

	first, _, _ := strings.Cut(registered, ".")

	return first
}

// Ranges returns the address space registered to the parties the domain's contacts belong to.
//
// It is the whole walk, four steps of it, because the third is a check rather than a lookup: the
// organisations a name turns up are kept only where their own contacts include one the domain
// search found. Without it the name would be doing the attributing, and a name is a poor thing to
// attribute address space on.
func (client *Client) Ranges(
	ctx context.Context,
	domain string,
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

	persons, err := client.Persons(ctx, domain, options...)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("persons: %w", err), domain)
	}

	if len(persons) == 0 {
		return []*Range{}, nil
	}

	registered := make(map[string]struct{}, len(persons))
	for _, person := range persons {
		if person != nil && person.Handle != "" {
			registered[person.Handle] = struct{}{}
		}
	}

	companies := make([]string, 0, len(persons))
	for _, person := range persons {
		if person != nil && person.Company != "" {
			companies = append(companies, person.Company)
		}
	}

	found := make([]*Range, 0)
	considered := make(map[string]struct{})

	for _, name := range SearchNames(domain, companies) {
		if len(considered) >= client.maxOrganizations() {
			break
		}

		organizations, err := client.Organizations(ctx, name, options...)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("organizations: %w", err), name)
		}

		for _, organization := range organizations {
			if organization == nil || organization.Handle == "" {
				continue
			}

			if _, ok := considered[organization.Handle]; ok {
				continue
			}

			if len(considered) >= client.maxOrganizations() {
				break
			}
			considered[organization.Handle] = struct{}{}

			contacts, err := client.OrganizationPersons(ctx, organization.Handle, options...)
			if err != nil {
				return nil, altshiftErrors.New(
					fmt.Errorf("organization persons: %w", err),
					organization.Handle,
				)
			}

			// The name found it; the contacts are what say it is the domain's.
			if !slices.ContainsFunc(contacts, func(handle string) bool {
				_, ok := registered[handle]

				return ok
			}) {
				continue
			}

			ranges, err := client.OrganizationRanges(ctx, organization.Handle, options...)
			if err != nil {
				return nil, altshiftErrors.New(
					fmt.Errorf("organization ranges: %w", err),
					organization.Handle,
				)
			}

			for _, item := range ranges {
				if item == nil {
					continue
				}

				item.Organization = organization
				found = append(found, item)
			}
		}
	}

	return found, nil
}
