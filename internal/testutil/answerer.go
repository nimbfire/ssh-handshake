// Package testutil has helpers shared by tests.
package testutil

import (
	"fmt"
	"io"
	"strings"
)

// Answerer is a terminal.Terminal that answers handmove questions by
// movement name: it reads the shuffled option list it was just shown and
// types the digit of the next wanted movement.
type Answerer struct {
	Want    []string // movement names, consumed in order
	Raw     []string // if non-empty, returned verbatim before using Want
	Out     strings.Builder
	pending strings.Builder
}

func (a *Answerer) Printf(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	a.Out.WriteString(s)
	a.pending.WriteString(s)
}

func (a *Answerer) ReadLine(prompt string) (string, error) {
	a.Out.WriteString(prompt)
	if len(a.Raw) > 0 {
		r := a.Raw[0]
		a.Raw = a.Raw[1:]
		return r, nil
	}
	if len(a.Want) == 0 {
		return "", io.EOF
	}
	want := a.Want[0]
	a.Want = a.Want[1:]
	shown := a.pending.String()
	a.pending.Reset()
	for _, line := range strings.Split(shown, "\n") {
		var n int
		var name string
		line = strings.TrimSpace(line)
		if i := strings.Index(line, ") "); i > 0 {
			if _, err := fmt.Sscanf(line[:i], "%d", &n); err == nil {
				name = line[i+2:]
			}
		}
		// Ignore an emoji prefix ("👍  Polegar para cima").
		if i := strings.Index(name, "  "); i >= 0 {
			name = name[i+2:]
		}
		if name == want {
			return fmt.Sprint(n), nil
		}
	}
	return "", fmt.Errorf("answerer: %q not among shown options", want)
}
