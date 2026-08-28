package inference

import (
	"slices"
	"testing"
)

const (
	methodA Method = "a"
	methodB Method = "b"
)

func TestCombined(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		inferences []*Inference
		expect     Confidence
	}{
		// No inferences is no confidence, which is not the same as a weak one: nothing was found
		// rather than something was found badly.
		{name: "nothing at all", expect: 0},
		{
			name:       "one method stands at its own worth",
			inferences: []*Inference{New(methodA, ConfidenceWeak)},
			expect:     ConfidenceWeak,
		},
		{
			// The rule that matters. Five reverse-IP hits are one piece of evidence seen five
			// times -- they all come from the same shared host -- so repeating a method must not
			// make co-location look like proof.
			name: "the same method repeated adds nothing",
			inferences: []*Inference{
				New(methodA, ConfidenceWeak, "one"),
				New(methodA, ConfidenceWeak, "two"),
				New(methodA, ConfidenceWeak, "three"),
			},
			expect: ConfidenceWeak,
		},
		{
			// Two different methods agreeing is genuinely more than either alone, and worth
			// exactly one step.
			name: "two distinct methods raise it by one",
			inferences: []*Inference{
				New(methodA, ConfidenceWeak),
				New(methodB, ConfidenceWeak),
			},
			expect: ConfidenceWeak + 1,
		},
		{
			name: "the strongest is the floor",
			inferences: []*Inference{
				New(methodA, ConfidenceWeak),
				New(methodB, ConfidenceStrong),
			},
			expect: ConfidenceStrong + 1,
		},
		{
			// The scale has a top, and agreement cannot push past it.
			name: "agreement cannot exceed the scale",
			inferences: []*Inference{
				New(methodA, ConfidenceCertain),
				New(methodB, ConfidenceCertain),
			},
			expect: ConfidenceCertain,
		},
		{name: "a nil inference is skipped", inferences: []*Inference{nil}, expect: 0},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := Combined(testCase.inferences); got != testCase.expect {
				t.Errorf("%s: expected %d, got %d", testCase.name, testCase.expect, got)
			}
		})
	}
}

func TestMerge(t *testing.T) {
	t.Parallel()

	// The same method reached the same way is one reason however many times a run turned it up.
	merged := Merge([]*Inference{
		New(methodA, ConfidenceWeak, "x"),
		New(methodA, ConfidenceWeak, "x"),
		New(methodA, ConfidenceWeak, "y"),
		New(methodB, ConfidenceWeak, "x"),
		nil,
	})

	if len(merged) != 3 {
		t.Fatalf("expected the duplicate to be dropped, got %d: %+v", len(merged), merged)
	}
	// The order it was given in is kept, so the first reason found reads first.
	if merged[0].Via[0] != "x" || merged[1].Via[0] != "y" || merged[2].Method != methodB {
		t.Errorf("expected the given order to be kept, got %+v", merged)
	}
}

// TestMergeDistinguishesChains holds that two different chains cannot collide into one, which a
// naive join on a character a step might contain would allow.
func TestMergeDistinguishesChains(t *testing.T) {
	t.Parallel()

	merged := Merge([]*Inference{
		New(methodA, ConfidenceWeak, "a", "b"),
		New(methodA, ConfidenceWeak, "a b"),
	})

	if len(merged) != 2 {
		t.Errorf("expected two distinct chains to stay distinct, got %d", len(merged))
	}
}

func TestMethods(t *testing.T) {
	t.Parallel()

	got := Methods([]*Inference{
		New(methodB, ConfidenceWeak),
		New(methodA, ConfidenceWeak),
		New(methodA, ConfidenceStrong),
		{Method: "", Confidence: ConfidenceWeak},
		nil,
	})

	if !slices.Equal(got, []Method{methodA, methodB}) {
		t.Errorf("expected the distinct methods, sorted, got %v", got)
	}
}

func TestConfidenceValid(t *testing.T) {
	t.Parallel()

	for _, confidence := range []Confidence{ConfidenceWeak, ConfidenceModest, ConfidenceFair, ConfidenceStrong, ConfidenceCertain} {
		if !confidence.Valid() {
			t.Errorf("expected %d to be on the scale", confidence)
		}
	}
	// A value off the scale is a caller's mistake rather than a grade, and worth catching before it
	// reaches something that ranks by it.
	for _, confidence := range []Confidence{0, -1, Highest + 1} {
		if confidence.Valid() {
			t.Errorf("expected %d to be off the scale", confidence)
		}
	}
}
