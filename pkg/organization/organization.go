// Package organization decides whether a party's name is worth searching a registry on.
//
// A name is a poor thing to attribute anything on, and a bad name is worse than no name at all. An
// organisation search matches a substring, so a term of two characters, or of nothing but the words
// every company shares -- "Group", "Holding", "AB" -- answers with whoever happens to contain it,
// and answers at the same price as a good term. This is what stands between such a term and the
// query that would bill for it.
//
// Two gates catch two different things, and only the first of them is here. What a name cannot
// possibly discriminate on is caught before anything is spent: a name of one letter, or of nothing
// but company-form words. What a name merely turns out not to discriminate on is caught by how many
// domains its search previews as matching -- which no amount of reading the name can tell you, and
// which the search is free to ask. So the length gate below is deliberately permissive, admitting
// the three-letter names real companies have, and leaves the rest to the count.
package organization

import (
	"errors"
	"strings"
	"unicode"

	"github.com/altshiftab/utils_go/pkg/net/types/domain_parts"
)

// MinimumLength is the shortest distinctive name worth searching on, counted in letters and digits.
//
// Three rather than four, because three-letter names are real -- SEB, SAS, IBM -- and rejecting
// them outright would lose the companies most likely to be searched for. A three-letter substring
// does match a great deal that has nothing to do with the party, but that shows up as a match count
// no portfolio could have, which is where it is caught.
const MinimumLength = 3

// legalForms are the company-form words a name carries that say nothing about which company it is.
// They are stripped before anything is judged, so that "Kivra AB" is searched for as "Kivra" --
// which matches the record either way, the search being a substring one, and matches the records
// that spell the form differently as well.
// The keys are what key() reduces a word to -- lower case, letters and digits only -- so "S.A." is
// looked up as "sa" and "sp. z o.o." as "spzoo".
//
// Deliberately absent is "sas", which is a company form in France and an airline in Scandinavia.
// Stripping it would leave that airline with no name at all, and this library is likelier to be
// pointed at the airline.
var legalForms = map[string]struct{}{
	"ab": {}, "aktiebolag": {}, "ag": {}, "aps": {}, "as": {}, "asa": {}, "bhd": {}, "bv": {},
	"co": {}, "company": {}, "corp": {}, "corporation": {}, "gk": {}, "gmbh": {}, "inc": {},
	"incorporated": {}, "kb": {}, "kft": {}, "kg": {}, "kk": {}, "limited": {}, "llc": {},
	"llp": {}, "ltd": {}, "ltda": {}, "nv": {}, "oy": {}, "oyj": {}, "plc": {}, "pte": {},
	"pty": {}, "sa": {}, "sarl": {}, "sdn": {}, "se": {}, "spa": {}, "spzoo": {}, "srl": {},
	"ug": {},
}

// genericWords are the words a great many companies share. A name is not rejected for containing
// one -- most names do -- but one made of nothing else identifies no party, and the words are
// dropped from the term either way, a shorter substring matching strictly more.
var genericWords = map[string]struct{}{
	"agency": {}, "capital": {}, "cloud": {}, "consulting": {}, "data": {}, "digital": {},
	"enterprises": {}, "global": {}, "group": {}, "holding": {}, "holdings": {}, "industries": {},
	"international": {}, "internet": {}, "invest": {}, "investments": {}, "labs": {},
	"marketing": {}, "media": {}, "net": {}, "online": {}, "partners": {}, "security": {},
	"service": {}, "services": {}, "software": {}, "solution": {}, "solutions": {}, "studio": {},
	"studios": {}, "system": {}, "systems": {}, "tech": {}, "technologies": {}, "technology": {},
	"trading": {}, "ventures": {}, "web": {}, "works": {}, "worldwide": {},
}

var (
	// ErrTooShort is a name with too little to it to identify anyone.
	ErrTooShort = errors.New("the name is too short to identify a party")
	// ErrTooGeneric is a name of nothing but the words every company carries.
	ErrTooGeneric = errors.New("the name is too generic to identify a party")
)

// separator reports the runes a name's words are divided by. The full stop is not among them: it
// belongs to the forms written with one, and "S.A." is one word rather than two.
func separator(value rune) bool {
	return unicode.IsSpace(value) || value == ',' || value == ';'
}

// key is a word reduced to what it is looked up by, so that "Inc.", "inc" and "INC" are one word
// and "S.A." is "sa".
func key(word string) string {
	return strings.Map(
		func(value rune) rune {
			if unicode.IsLetter(value) || unicode.IsDigit(value) {
				return unicode.ToLower(value)
			}

			return -1
		},
		word,
	)
}

// significant counts the letters and digits in a name, which is what its length is measured in: the
// spaces and hyphens between words are not what a search matches on.
func significant(name string) int {
	count := 0
	for _, value := range name {
		if unicode.IsLetter(value) || unicode.IsDigit(value) {
			count++
		}
	}

	return count
}

// Distinctive is the part of a name that says which party it is.
//
// It is the name with its company form and its shared words removed -- "Nordic Snipe Group AB"
// becomes "Nordic Snipe" -- which is both a better search term and a fairer thing to judge. Better,
// because the search matches a substring and the shorter term matches every record the longer one
// does and the records that spell the rest differently besides. Fairer, because what is left is
// what the name actually contributes.
func Distinctive(name string) string {
	words := strings.FieldsFunc(name, separator)

	kept := make([]string, 0, len(words))
	for _, word := range words {
		lookup := key(word)
		if lookup == "" {
			continue
		}

		if _, ok := legalForms[lookup]; ok {
			continue
		}
		if _, ok := genericWords[lookup]; ok {
			continue
		}

		// Trimmed of the punctuation a word ends on, the term being matched against a record rather
		// than read.
		kept = append(kept, strings.Trim(word, ".,;:"))
	}

	return strings.Join(kept, " ")
}

// Check reports whether the name is worth searching on, and says why where it is not.
//
// An empty name is the caller's business rather than this one's, and is not judged here.
func Check(name string) error {
	distinctive := Distinctive(name)

	if distinctive == "" {
		return ErrTooGeneric
	}

	if significant(distinctive) < MinimumLength {
		return ErrTooShort
	}

	return nil
}

// Label is the domain's own name, without what it is registered under: kivra.com is Kivra.
//
// It is the name a party is guessed to be called where nothing better was handed over, and it
// carries most of them -- a party is usually registered under the name it puts in its domain. It is
// still a guess, which is what Check is for.
func Label(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))

	registered := domain
	if parts := domain_parts.New(domain); parts != nil && parts.RegisteredDomain != "" {
		registered = parts.RegisteredDomain
	}

	first, _, _ := strings.Cut(registered, ".")

	return first
}
