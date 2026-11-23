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
	"sync/atomic"

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

// KeyReader is implemented by terminals that can read a single keypress
// without waiting for Enter. Validators use it when KeyMode reports true and
// fall back to ReadLine otherwise.
type KeyReader interface {
	KeyMode() bool
	// ReadKey shows prompt and returns the first key in accept, without
	// echo. Other keys are ignored. Ctrl+C returns ErrInterrupted, Ctrl+D
	// io.EOF.
	ReadKey(prompt, accept string) (byte, error)
}

// ErrInterrupted is returned when the user presses Ctrl+C in key mode (raw
// mode turns it into a byte instead of SIGINT).
var ErrInterrupted = errors.New("terminal: interrupted")

// restore undoes raw mode; used by Restore before an abrupt exit.
var restore atomic.Pointer[func()]

// Restore puts the terminal back in its normal mode if a read left it raw.
// Call it before os.Exit from another goroutine (e.g. a timeout).
func Restore() {
	if f := restore.Swap(nil); f != nil {
		(*f)()
	}
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

func (s *Std) KeyMode() bool { return s.tty }

func (s *Std) ReadKey(prompt, accept string) (byte, error) {
	fmt.Fprint(s.out, prompt)
	old, err := term.MakeRaw(s.fd)
	if err != nil {
		return 0, err
	}
	f := func() { _ = term.Restore(s.fd, old) }
	restore.Store(&f)
	defer Restore()
	// Read straight from the fd, one byte at a time, so keys typed ahead stay
	// in the kernel buffer for the next question.
	var b [1]byte
	for {
		n, err := os.Stdin.Read(b[:])
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue
		}
		switch c := b[0]; {
		case c == 0x03:
			return 0, ErrInterrupted
		case c == 0x04:
			return 0, io.EOF
		case strings.IndexByte(accept, c) >= 0:
			return c, nil
		}
	}
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
