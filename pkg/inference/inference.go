// Package inference records how something was found and how much that is worth.
//
// Everything this library discovers is inferred rather than known. A domain found in a registration
// record, a subdomain found in a certificate log, a network range named by an SPF directive -- each
// is a different kind of evidence, and they are not worth the same. A consumer that treated them
// alike would attribute half the internet to whoever shares a web host.
//
// So a discovered thing carries the inferences that produced it rather than a bare boolean, and the
// consumer decides what to do with them.
package inference

import "slices"

// Method names how something was found.
//
// It is a defined type so that the methods a package can produce are declared once, near the code
// that produces them, rather than written as a bare string at each call site where a typo would
// quietly invent a new one. This package deliberately does not enumerate them: a source knows its
// own methods, and adding one should not mean editing this file.
type Method string

// Confidence is how much a method is worth, on a fixed scale.
//
// The scale is small on purpose. The distinctions that matter are "this is barely evidence" against
// "this is a registration record naming the same party"; a finer scale would invite precision the
// evidence does not support.
type Confidence int

const (
	// ConfidenceWeak is co-location and the like: true of the thing, and true of a great many
	// things that have nothing to do with it.
	ConfidenceWeak Confidence = 1
	// ConfidenceModest is a signal an owner controls but does not think of as a claim, such as a
	// range named in an SPF record.
	ConfidenceModest Confidence = 2
	// ConfidenceFair is a published association that someone had to arrange.
	ConfidenceFair Confidence = 3
	// ConfidenceStrong is a registry record naming the same party.
	ConfidenceStrong Confidence = 4
	// ConfidenceCertain is direct observation of the thing itself.
	ConfidenceCertain Confidence = 5
)

// Lowest and Highest bound the scale.
const (
	Lowest  = ConfidenceWeak
	Highest = ConfidenceCertain
)

// Valid reports whether the confidence is on the scale. A value off it is a caller's mistake rather
// than a grade, and is worth catching before it reaches a consumer that ranks by it.
func (confidence Confidence) Valid() bool {
	return confidence >= Lowest && confidence <= Highest
}

// Inference is one reason something was attributed.
type Inference struct {
	// Method is how it was found.
	Method Method `json:"method"`
	// Confidence is what that method is worth.
	Confidence Confidence `json:"confidence"`
	// Via are the steps behind it -- the search term that matched, the address it was co-located
	// on, the domain whose SPF record named it. It is what lets an operator check the reasoning
	// rather than take the confidence on faith.
	Via []string `json:"via,omitzero"`
}

// New builds an inference.
func New(method Method, confidence Confidence, via ...string) *Inference {
	return &Inference{Method: method, Confidence: confidence, Via: via}
}

// Methods returns the distinct methods behind the inferences, sorted.
func Methods(inferences []*Inference) []Method {
	methods := make([]Method, 0, len(inferences))

	for _, item := range inferences {
		if item == nil || item.Method == "" {
			continue
		}

		methods = append(methods, item.Method)
	}

	slices.Sort(methods)

	return slices.Compact(methods)
}

// Combined is what the inferences are worth together.
//
// It is the strongest of them, raised by one where two or more distinct methods agree, and capped
// at the top of the scale. That rule is deliberately conservative, and the reason is independence:
// five reverse-IP hits are one piece of evidence seen five times, because they all come from the
// same shared host, and summing them would make co-location look like proof. Two different methods
// agreeing is genuinely more than either alone, so it is worth exactly one step.
//
// No inferences is no confidence, which is not the same as a weak one.
func Combined(inferences []*Inference) Confidence {
	var strongest Confidence

	for _, item := range inferences {
		if item == nil {
			continue
		}

		if item.Confidence > strongest {
			strongest = item.Confidence
		}
	}

	if strongest == 0 {
		return 0
	}

	if len(Methods(inferences)) > 1 {
		strongest++
	}

	return min(strongest, Highest)
}

// Merge collapses inferences that say the same thing, keeping the order they were given in.
//
// The same method reached through the same steps is one reason, however many times a run turned it
// up: a domain named by two certificates is not better attributed than one named by a single
// certificate.
func Merge(inferences []*Inference) []*Inference {
	type key struct {
		method     Method
		confidence Confidence
		via        string
	}

	seen := make(map[key]struct{}, len(inferences))
	merged := make([]*Inference, 0, len(inferences))

	for _, item := range inferences {
		if item == nil {
			continue
		}

		itemKey := key{
			method:     item.Method,
			confidence: item.Confidence,
			// The steps joined with a separator no step contains, so two different chains cannot
			// collide into one.
			via: joinVia(item.Via),
		}

		if _, ok := seen[itemKey]; ok {
			continue
		}
		seen[itemKey] = struct{}{}

		merged = append(merged, item)
	}

	return merged
}

// joinVia renders the steps as one string for comparison.
func joinVia(via []string) string {
	joined := ""
	for index, step := range via {
		if index != 0 {
			joined += "\x00"
		}
		joined += step
	}

	return joined
}
