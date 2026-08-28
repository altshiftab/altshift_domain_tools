// Package whoisxml queries WhoisXML's reverse-whois API, which finds domains whose registration
// records match a search term.
package whoisxml

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml/types"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml/whoisxml_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config/retry_config"
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

// The registration fields an advanced search can match on.
//
// They are named here rather than written at the call sites because the API rejects an unknown one
// outright, and because its own documentation gets three of them wrong: it lists RegistrantName,
// AdministrativeContact.* and TechnicalContact.*, and the service answers all three with
// "422 Invalid search field". Every name below was checked against the live API instead.
//
// FieldEmail is the one to reach for over FieldRegistrantEmail: it matches an address anywhere in
// the record -- registrant, admin or tech -- rather than in the registrant contact alone.
const (
	FieldEmail                  = "Email"
	FieldDomainName             = "DomainName"
	FieldNameServers            = "NameServers"
	FieldRegistrantEmail        = "RegistrantContact.Email"
	FieldRegistrantName         = "RegistrantContact.Name"
	FieldRegistrantOrganization = "RegistrantContact.Organization"
	FieldAdminOrganization      = "AdminContact.Organization"
	FieldTechOrganization       = "TechContact.Organization"
)

// MaximumResponseDomains is the most domains one response holds. A search matching more hands back
// a cursor rather than the rest, and is read a page at a time.
const MaximumResponseDomains = 10000

// ContentType is what the API takes and answers with.
const ContentType = "application/json"

// MaximumErrorMessageBytes bounds how much of an unreadable error body is carried into the error.
// Enough to see what happened, not so much that a stray HTML page becomes the message.
const MaximumErrorMessageBytes = 512

var (
	// ErrAccessRestricted is the API refusing the key. It is worth telling apart because it will
	// not clear by retrying: the credits are spent, or the key is wrong, or the address the request
	// came from is not one the account allows. The API declines to say which, so neither does this.
	ErrAccessRestricted = errors.New("access restricted")
	// ErrInvalidRequest is the API rejecting the search rather than the caller -- a field name it
	// does not have, most often. It is a mistake in the program, and no amount of asking again
	// fixes it.
	ErrInvalidRequest = errors.New("invalid request")
)

// ResponseError is the API's own account of what went wrong.
//
// It exists because a status code alone does not say enough on an API that bills. A 422 naming the
// field it does not have, and a 403 saying the credits are spent, are different problems needing
// different answers, and "non-2xx status code" -- which is all a caller saw before this -- is
// neither of them and is indistinguishable from a transient fault.
type ResponseError struct {
	StatusCode int
	Code       int
	Message    string
}

func (responseError *ResponseError) Error() string {
	if responseError.Message == "" {
		return fmt.Sprintf("the api answered %d", responseError.StatusCode)
	}

	return fmt.Sprintf("the api answered %d: %s", responseError.StatusCode, responseError.Message)
}

// Unwrap sorts the failure into the two that are worth acting on differently. A status this does
// not know is wrapped by nothing, and is the error it already is.
func (responseError *ResponseError) Unwrap() error {
	switch responseError.StatusCode {
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden:
		return ErrAccessRestricted
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return ErrInvalidRequest
	}

	return nil
}

// newResponseError reads what the API said about a failure, falling back to the body itself where
// it said it in a shape this does not know.
func newResponseError(statusCode int, body []byte) *ResponseError {
	responseError := &ResponseError{StatusCode: statusCode}

	var reported types.ErrorResponse
	if err := json.Unmarshal(body, &reported); err == nil {
		responseError.Code = reported.Code
		responseError.Message = reported.Text()
	}

	if responseError.Message == "" {
		message := strings.TrimSpace(string(body))
		if len(message) > MaximumErrorMessageBytes {
			message = message[:MaximumErrorMessageBytes]
		}
		responseError.Message = message
	}

	return responseError
}

// defaultRetryConfig is what a call retries with where its caller asked for nothing else.
//
// The API answers a caller going too fast with 429, and counts wildcard searches -- which the
// searches this package is here for are -- against a limit of ten a minute, low enough that an
// ordinary run over a handful of domains reaches it. Waiting and asking again is therefore what a
// call does by default rather than something every caller has to remember, and the waits are
// measured against that per-minute window rather than against the half second the shared default
// retries with.
//
// A retried request may be a purchase, which bills. The 429 this is mostly for is not billed; a
// 5xx that billed before it failed would bill twice, which is accepted, because the alternative is
// losing a run to one bad response.
var defaultRetryConfig = retry_config.New(
	retry_config.WithCount(3),
	retry_config.WithBaseDelay(5*time.Second),
	retry_config.WithMaximumWaitTime(time.Minute),
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

	// The key travels in the body because that is where this API takes it, so a marshalled request
	// carries it and there is no arrangement of this code that does not. Worth knowing rather than
	// worth silencing: the body is what the fetch attaches to an error's context and what a
	// debug-level handler would print, so a run with debug logging on writes the key to the log.
	requestBody, err := json.Marshal(request) //nolint:gosec // G117: the API takes its key in the body.
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (request): %w", err))
	}

	// slices.Concat rather than append: a reverse-whois run issues these queries concurrently from
	// one shared option slice, and appending into that slice's spare capacity would have the
	// queries overwrite one another's options.
	//
	// The retry config and the headers go first, ahead of the client's options and the call's, so
	// that a caller with its own -- or with no retries at all, passing a nil config -- overrides
	// them: the later option is the one that takes. What the client must control to do its job
	// goes last.
	fetchOptions := slices.Concat(
		[]fetch_config.Option{
			fetch_config.WithRetryConfig(defaultRetryConfig),
			fetch_config.WithHeaders(map[string]string{"Content-Type": ContentType, "Accept": ContentType}),
		},
		client.config.FetchOptions,
		options,
		[]fetch_config.Option{
			fetch_config.WithMethod(http.MethodPost),
			fetch_config.WithBody(requestBody),
			// The status is judged here rather than by the fetch, so that the body carrying the
			// API's own account of the failure is read instead of thrown away with it. Retries are
			// unaffected: the checker reads the status off the response rather than off the error.
			fetch_config.WithSkipErrorOnStatus(true),
		},
	)

	httpResponse, responseBody, err := altshiftHttpUtils.Fetch(ctx, requestUrlString, fetchOptions...)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("fetch: %w", err), requestUrlString)
	}
	if httpResponse == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("http response"), requestUrlString)
	}

	if httpResponse.StatusCode < http.StatusOK || httpResponse.StatusCode >= http.StatusMultipleChoices {
		return nil, altshiftErrors.NewWithTrace(
			newResponseError(httpResponse.StatusCode, responseBody),
			requestUrlString,
		)
	}

	if len(responseBody) == 0 {
		return nil, nil
	}

	var response types.ReverseWhoisResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("json unmarshal (response body): %w", err),
			responseBody,
		)
	}

	return &response, nil
}

// QueryReverseWhoisPages runs one search and follows its pagination, returning every domain it
// matched.
//
// A response holds at most MaximumResponseDomains domains and says so by handing back a cursor to
// the next page. Without following that cursor a truncated answer cannot be told from a whole one,
// which is the failure this is here to prevent: a search matching eleven thousand domains answers
// with ten thousand and no complaint.
//
// Every page is a request of its own, and a purchase bills per request rather than per domain, so
// pageLimit is what bounds the credits one call may spend. A limit of zero or less reads a single
// page, which is what an unpaginated call already did.
//
// The bool reports pages left unread, so a caller can say its answer is partial rather than let it
// pass for whole. The pages that were read are returned alongside an error as well: a purchase
// that failed on its third page still bought the first two, and those are worth more than throwing
// them away for tidiness.
func (client *Client) QueryReverseWhoisPages(
	ctx context.Context,
	request *types.ReverseWhoisRequest,
	pageLimit int,
	options ...fetch_config.Option,
) ([]string, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, fmt.Errorf("context err: %w", err)
	}

	if client == nil {
		return nil, false, altshiftErrors.NewWithTrace(nil_error.New("client"))
	}

	if request == nil {
		return nil, false, altshiftErrors.NewWithTrace(nil_error.New("request"))
	}

	// The cursor is written to a copy: the caller's request is the caller's, and one handed to this
	// twice should mean the same search both times rather than resume where the last call stopped.
	pageRequest := *request

	var domains []string

	for page := range max(pageLimit, 1) {
		response, err := client.QueryReverseWhois(ctx, &pageRequest, options...)
		if err != nil {
			return domains, true, altshiftErrors.New(fmt.Errorf("query reverse whois: %w", err), page)
		}
		if response == nil {
			return domains, true, altshiftErrors.NewWithTrace(nil_error.New("reverse whois response"), page)
		}

		domains = append(domains, response.DomainsList...)

		// A preview reports a count and no domains, and so no cursor either, which stops this after
		// the one request a preview is.
		if response.NextPageSearchAfter == nil || *response.NextPageSearchAfter == "" {
			return domains, false, nil
		}

		pageRequest.SearchAfter = *response.NextPageSearchAfter
	}

	return domains, true, nil
}
