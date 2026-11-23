package handseq

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nimbfire/ssh-handshake/internal/terminal"
	"github.com/nimbfire/ssh-handshake/internal/validator"
	"github.com/nimbfire/ssh-handshake/internal/validator/handmove"
)

// typer answers each ReadLine by finding, in the options it was just shown,
// the digits of the wanted movements.
type typer struct {
	want    [][]int
	out     strings.Builder
	pending strings.Builder
	digit   map[string]string
}

func (a *typer) Printf(f string, args ...any) {
	s := fmt.Sprintf(f, args...)
	a.out.WriteString(s)
	a.pending.WriteString(s)
}

func (a *typer) ReadLine(string) (string, error) {
	if len(a.want) == 0 {
		return "", errors.New("no more answers")
	}
	if a.digit == nil || strings.Contains(a.pending.String(), "Opções:") {
		a.digit = map[string]string{}
	}
	digit := a.digit
	for _, line := range strings.Split(a.pending.String(), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, ") "); i == 1 {
			name := line[i+2:]
			if j := strings.Index(name, "  "); j >= 0 {
				name = name[j+2:]
			}
			digit[name] = line[:1]
		}
	}
	a.pending.Reset()
	var sb strings.Builder
	for _, m := range a.want[0] {
		sb.WriteString(digit[handmove.Movements[m]])
	}
	a.want = a.want[1:]
	return sb.String(), nil
}

func TestEnrollAndChallenge(t *testing.T) {
	v := Validator{}
	secret := []int{3, 0, 3, 8, 1}
	params, got, err := v.Enroll(&typer{want: [][]int{secret, secret}}, nil, validator.EnrollOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(params) != "{}" || len(got) != len(secret) {
		t.Fatalf("params %s secret %v", params, got)
	}
	ch, err := v.Challenge(&typer{want: [][]int{secret}}, nil, json.RawMessage(params))
	if err != nil || string(ch) != string(got) {
		t.Fatalf("challenge %v %v, want %v", ch, err, got)
	}
}

func TestMinLength(t *testing.T) {
	v := Validator{}
	_, got, err := v.Enroll(&typer{want: [][]int{{1, 2}, {1, 2, 3}, {1, 2, 3}}}, nil, validator.EnrollOptions{MinLength: 3})
	if err != nil || len(got) != 3 {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestEnrollErrors(t *testing.T) {
	v := Validator{}
	if _, _, err := v.Enroll(&typer{want: [][]int{{1, 2}, {2, 1}}}, nil, validator.EnrollOptions{}); !errors.Is(err, ErrMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	if _, _, err := v.Enroll(&typer{want: [][]int{{4, 4, 4}}}, nil, validator.EnrollOptions{}); !errors.Is(err, ErrWeak) {
		t.Fatalf("weak: %v", err)
	}
	bad := &terminal.Scripted{Lines: []string{"12a", "0", "x"}}
	if _, err := v.Challenge(bad, nil, json.RawMessage("{}")); !errors.Is(err, ErrTooManyInvalid) {
		t.Fatalf("invalid: %v", err)
	}
}

func TestFixedOrder(t *testing.T) {
	FixedOrder = true
	defer func() { FixedOrder = false }()
	got, err := Validator{}.Challenge(&terminal.Scripted{Lines: []string{"1 9 3"}}, nil, json.RawMessage("{}"))
	if err != nil || string(got) != string([]byte{0, 8, 2}) {
		t.Fatalf("got %v %v", got, err)
	}
}
