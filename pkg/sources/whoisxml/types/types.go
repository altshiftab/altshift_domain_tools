// Package types holds the WhoisXML reverse-whois wire format.
package types

type AdvancedSearchTerms struct {
	Field      string `json:"field,omitzero"`
	Term       string `json:"term,omitzero"`
	Exclude    bool   `json:"exclude,omitzero"`
	ExactMatch bool   `json:"exactMatch,omitzero"`
}

type BasicSearchTerms struct {
	Include []string `json:"include,omitzero"`
	Exclude []string `json:"exclude,omitzero"`
}

type ReverseWhoisRequest struct {
	ApiKey              string                 `json:"apiKey"`
	BasicSearchTerms    []*BasicSearchTerms    `json:"basicSearchTerms,omitzero"`
	AdvancedSearchTerms []*AdvancedSearchTerms `json:"advancedSearchTerms,omitzero"`
	SearchType          string                 `json:"searchType,omitzero"`
	Mode                string                 `json:"mode,omitzero"`
	// Punycode is a pointer because the API defaults it to true rather than to false: a plain bool
	// omitted when zero could ask for it but never turn it off, and a caller setting it to false
	// would silently get the opposite of what it asked for.
	Punycode          *bool  `json:"punycode,omitzero"`
	IncludeAuditDates bool   `json:"includeAuditDates,omitzero"`
	ResponseFormat    string `json:"responseFormat,omitzero"`
	CreatedDateFrom   string `json:"createdDateFrom,omitzero"`
	CreatedDateTo     string `json:"createdDateTo,omitzero"`
	UpdatedDateFrom   string `json:"updatedDateFrom,omitzero"`
	UpdatedDateTo     string `json:"updatedDateTo,omitzero"`
	ExpiredDateFrom   string `json:"expiredDateFrom,omitzero"`
	ExpiredDateTo     string `json:"expiredDateTo,omitzero"`
	SearchAfter       string `json:"searchAfter,omitzero"`
}

// ErrorResponse is how the API reports a failure.
//
// Two message fields because the API uses two names for the one thing: a rejected search field
// answers with "message", and a refused key answers with "messages". Whichever arrives is the
// message; a body carrying neither is handled by the caller, which keeps the body itself.
type ErrorResponse struct {
	Code     int    `json:"code,omitzero"`
	Message  string `json:"message,omitzero"`
	Messages string `json:"messages,omitzero"`
}

// Text is whichever of the two message fields the API filled in.
func (errorResponse *ErrorResponse) Text() string {
	if errorResponse.Message != "" {
		return errorResponse.Message
	}

	return errorResponse.Messages
}

// ReverseWhoisResponse is the shape returned when IncludeAuditDates is not set.
// With audit dates requested, DomainsList becomes a list of objects instead of
// a list of names; nothing here asks for them.
type ReverseWhoisResponse struct {
	NextPageSearchAfter *string  `json:"nextPageSearchAfter,omitzero"`
	DomainsCount        int      `json:"domainsCount,omitzero"`
	DomainsList         []string `json:"domainsList,omitzero"`
}
