package handmove

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nimbfire/ssh-handshake/internal/testutil"
	"github.com/nimbfire/ssh-handshake/internal/validator"
)

func seq(idx ...int) []string {
	out := make([]string, len(idx))
	for i, x := range idx {
		out[i] = Movements[x]
	}
	return out
}

var answer = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 0}

func TestEnrollAndChallenge(t *testing.T) {
	v := Validator{}
	a := &testutil.Answerer{Want: append(seq(answer...), seq(answer...)...)}
	params, secret, err := v.Enroll(a, nil, validator.EnrollOptions{})
	if err != nil {
		t.Fatalf("enroll: %v\n%s", err, a.Out.String())
	}
	if len(secret) != DefaultLength {
		t.Fatalf("secret len %d", len(secret))
	}
	for i, b := range secret {
		if int(b) != answer[i] {
			t.Fatalf("secret[%d]=%d want %d", i, b, answer[i])
		}
	}

	// Same movements give the same secret, even though digits differ.
	c := &testutil.Answerer{Want: seq(answer...)}
	got, err := v.Challenge(c, nil, params)
	if err != nil || string(got) != string(secret) {
		t.Fatalf("challenge = %v, %v", got, err)
	}
	// No per-step feedback in the transcript.
	if strings.Contains(strings.ToLower(c.Out.String()), "errad") {
		t.Fatal("challenge leaks per-step correctness")
	}
}

func TestEnrollMismatch(t *testing.T) {
	other := append([]int(nil), answer...)
	other[3] = 8
	a := &testutil.Answerer{Want: append(seq(answer...), seq(other...)...)}
	_, _, err := Validator{}.Enroll(a, nil, validator.EnrollOptions{})
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("err = %v, want ErrMismatch", err)
	}
}

func TestEnrollRejectsWeak(t *testing.T) {
	weak := []int{1, 1, 1, 1, 2, 2, 2, 2, 1, 1}
	a := &testutil.Answerer{Want: append(seq(weak...), seq(weak...)...)}
	_, _, err := Validator{}.Enroll(a, nil, validator.EnrollOptions{})
	if !errors.Is(err, ErrWeak) {
		t.Fatalf("err = %v, want ErrWeak", err)
	}
}

func TestInvalidInput(t *testing.T) {
	params, _ := json.Marshal(Params{Cues: make([]int, MinLength)})
	a := &testutil.Answerer{Raw: []string{"0", "10", "abc"}}
	_, err := Validator{}.Challenge(a, nil, params)
	if !errors.Is(err, ErrTooManyInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestParamsValidate(t *testing.T) {
	for _, p := range []Params{
		{Cues: make([]int, MinLength-1)},
		{Cues: make([]int, MaxLength+1)},
		{Cues: []int{0, 0, 0, 0, 0, 0, 0, 9}},
		{Cues: []int{0, 0, 0, 0, 0, 0, 0, -1}},
	} {
		if p.Validate() == nil {
			t.Errorf("accepted %v", p.Cues)
		}
	}
}

func TestShuffleIsPermutation(t *testing.T) {
	for i := 0; i < 100; i++ {
		p, err := shuffle(nil, 9)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[int]bool{}
		for _, x := range p {
			seen[x] = true
		}
		if len(seen) != 9 {
			t.Fatalf("not a permutation: %v", p)
		}
	}
}
