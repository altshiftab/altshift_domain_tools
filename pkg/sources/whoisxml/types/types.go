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
	Punycode            bool                   `json:"punycode,omitzero"`
	IncludeAuditDates   bool                   `json:"includeAuditDates,omitzero"`
	ResponseFormat      string                 `json:"responseFormat,omitzero"`
	CreatedDateFrom     string                 `json:"createdDateFrom,omitzero"`
	CreatedDateTo       string                 `json:"createdDateTo,omitzero"`
	UpdatedDateFrom     string                 `json:"updatedDateFrom,omitzero"`
	UpdatedDateTo       string                 `json:"updatedDateTo,omitzero"`
	ExpiredDateFrom     string                 `json:"expiredDateFrom,omitzero"`
	ExpiredDateTo       string                 `json:"expiredDateTo,omitzero"`
	SearchAfter         string                 `json:"searchAfter,omitzero"`
}

// ReverseWhoisResponse is the shape returned when IncludeAuditDates is not set.
// With audit dates requested, DomainsList becomes a list of objects instead of
// a list of names; nothing here asks for them.
type ReverseWhoisResponse struct {
	NextPageSearchAfter *string  `json:"nextPageSearchAfter,omitzero"`
	DomainsCount        int      `json:"domainsCount,omitzero"`
	DomainsList         []string `json:"domainsList,omitzero"`
}
