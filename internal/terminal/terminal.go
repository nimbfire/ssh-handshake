// Package terminal is the small I/O surface validators use to talk to the
// SSH client. Prompts go to stderr so they never pollute the stdout of a
// non-interactive command (`ssh host cmd`).
package terminal

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Terminal is what a validator can use to interact with the user.
type Terminal interface {
	// Printf writes text to the user.
	Printf(format string, a ...any)
	// ReadLine shows prompt and reads one line. On a TTY the input is not
	// echoed.
	ReadLine(prompt string) (string, error)
}

// ErrLineTooLong is returned when the user sends an absurdly long line.
var ErrLineTooLong = errors.New("terminal: input line too long")

// Std is a Terminal backed by stdin and stderr.
type Std struct {
	in  *bufio.Reader
	out io.Writer
	fd  int
	tty bool
}

// NewStd returns a Terminal on the process stdin/stderr.
func NewStd() *Std {
	fd := int(os.Stdin.Fd())
	return &Std{
		in:  bufio.NewReaderSize(os.Stdin, 256),
		out: os.Stderr,
		fd:  fd,
		tty: term.IsTerminal(fd),
	}
}

// IsTTY reports whether stdin is a terminal.
func (s *Std) IsTTY() bool { return s.tty }

func (s *Std) Printf(format string, a ...any) { fmt.Fprintf(s.out, format, a...) }

func (s *Std) ReadLine(prompt string) (string, error) {
	fmt.Fprint(s.out, prompt)
	if s.tty {
		b, err := term.ReadPassword(s.fd)
		fmt.Fprintln(s.out)
		if err != nil {
			return "", err
		}
		if len(b) > 256 {
			return "", ErrLineTooLong
		}
		return strings.TrimSpace(string(b)), nil
	}
	return readLine(s.in)
}

func readLine(r *bufio.Reader) (string, error) {
	b, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", ErrLineTooLong
	}
	if err != nil && !(errors.Is(err, io.EOF) && len(b) > 0) {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Scripted is a Terminal for tests: it answers from a fixed list of lines
// and records everything printed.
type Scripted struct {
	Lines []string
	Out   strings.Builder
}

func (s *Scripted) Printf(format string, a ...any) { fmt.Fprintf(&s.Out, format, a...) }

func (s *Scripted) ReadLine(prompt string) (string, error) {
	s.Out.WriteString(prompt)
	if len(s.Lines) == 0 {
		return "", io.EOF
	}
	l := s.Lines[0]
	s.Lines = s.Lines[1:]
	return l, nil
}
