// Package handseq implements the "hand sequence" handshake: the user types a
// sequence of hand movements of any length (within limits) and presses Enter.
//
// The nine movements are listed with a digit each. By default the digits are
// shuffled once per pass (so they stay put while typing and change on the next
// login); with FixedOrder the catalog order is always used. What is hashed is
// the sequence of movement identities, never the digits.
//
// There is no per-step feedback: the whole sequence is hashed and compared at
// the end by the caller. The length is not stored anywhere in clear text.
package handseq

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/nimbfire/ssh-handshake/internal/terminal"
	"github.com/nimbfire/ssh-handshake/internal/validator"
	"github.com/nimbfire/ssh-handshake/internal/validator/handmove"
)

// Name is the identifier stored in handshake files.
const Name = "handseq"

const (
	// MinLength is the smallest sequence accepted at enrollment. Admins can
	// require more with EnrollOptions.MinLength (--min-length).
	MinLength = 2
	// MaxLength bounds the input.
	MaxLength = 64
	// minDistinct rejects sequences that repeat a single movement.
	minDistinct = 2
	// maxInvalid is how many unparsable lines are tolerated without a TTY.
	maxInvalid = 3
)

// FixedOrder makes the digit of each movement always the catalog order
// (1 = first movement, ...), on every login, instead of shuffling.
var FixedOrder = false

// Errors returned by the validator.
var (
	ErrTooManyInvalid = errors.New("handseq: too many invalid answers")
	ErrMismatch       = errors.New("handseq: confirmation does not match")
	ErrWeak           = fmt.Errorf("handseq: use at least %d different movements", minDistinct)
)

// Params is the public part of a handseq handshake. It is empty: the length
// and the movements are secret.
type Params struct{}

// Validator is the handseq validator.
type Validator struct{}

func init() { validator.Register(Validator{}) }

func (Validator) Name() string { return Name }

func (Validator) Description() string {
	return "sequência de mãos: digite os números das mãos e Enter (tamanho livre)"
}

func (Validator) Enroll(t terminal.Terminal, rnd io.Reader, opts validator.EnrollOptions) (json.RawMessage, []byte, error) {
	min := opts.MinLength
	if min < MinLength {
		min = MinLength
	}
	if min > MaxLength {
		return nil, nil, fmt.Errorf("handseq: minimum length %d above maximum %d", min, MaxLength)
	}
	first, err := ask(t, rnd, fmt.Sprintf("== Criando novo handshake ==\n"+
		"Digite a sequência de mãos que será o seu handshake (mínimo %d).\n"+
		"Memorize a sequência: ela não pode ser recuperada, só redefinida.\n", min), min)
	if err != nil {
		return nil, nil, err
	}
	if distinct(first) < minDistinct {
		return nil, nil, ErrWeak
	}
	second, err := ask(t, rnd, "== Confirme o handshake ==\n", 1)
	if err != nil {
		return nil, nil, err
	}
	if string(first) != string(second) {
		return nil, nil, ErrMismatch
	}
	raw, err := json.Marshal(Params{})
	if err != nil {
		return nil, nil, err
	}
	return raw, first, nil
}

func (Validator) Challenge(t terminal.Terminal, rnd io.Reader, raw json.RawMessage) ([]byte, error) {
	var p Params
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("handseq: bad params: %w", err)
	}
	return ask(t, rnd, "== ssh-handshake ==\n", 1)
}

// ask reads one full sequence.
func ask(t terminal.Terminal, rnd io.Reader, header string, min int) ([]byte, error) {
	perm, err := order(rnd)
	if err != nil {
		return nil, err
	}
	if k, ok := t.(terminal.KeyReader); ok && k.KeyMode() {
		return askKeys(t, k, perm, header, min)
	}
	return askLine(t, perm, header, min)
}

func printOptions(t terminal.Terminal, perm []int) {
	t.Printf("\nOpções:\n")
	for j, m := range perm {
		t.Printf("  %d) %s\n", j+1, handmove.Label(m))
	}
}

// askKeys reads one key at a time and redraws the screen with the sequence
// typed so far. Enter finishes, Backspace removes the last movement.
func askKeys(t terminal.Terminal, k terminal.KeyReader, perm []int, header string, min int) ([]byte, error) {
	var out []byte
	msg := ""
	for {
		t.Printf("\033[H\033[2J%s", header)
		printOptions(t, perm)
		t.Printf("\nDigite os números das mãos. Enter termina, Backspace apaga.\n")
		t.Printf("\nSeu handshake (%d): %s\n", len(out), Sequence(out))
		if msg != "" {
			t.Printf("%s\n", msg)
			msg = ""
		}
		c, err := k.ReadKey("", "123456789\r\n\x7f\x08")
		if err != nil {
			return nil, err
		}
		switch c {
		case '\r', '\n':
			if len(out) >= min {
				return out, nil
			}
			msg = fmt.Sprintf("Digite pelo menos %d mãos.", min)
		case 0x7f, 0x08:
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			if len(out) >= MaxLength {
				msg = fmt.Sprintf("Máximo de %d mãos.", MaxLength)
				continue
			}
			out = append(out, byte(perm[c-'1']))
		}
	}
}

// askLine is used without a TTY: the whole sequence comes as one line of
// digits (spaces ignored).
func askLine(t terminal.Terminal, perm []int, header string, min int) ([]byte, error) {
	t.Printf("\n%s", header)
	printOptions(t, perm)
	for attempt := 0; attempt < maxInvalid; attempt++ {
		line, err := t.ReadLine("\nDigite os números das mãos e Enter: ")
		if err != nil {
			return nil, err
		}
		out, ok := parse(line, perm)
		switch {
		case !ok:
			t.Printf("Entrada inválida: use só dígitos de 1 a 9 (até %d).\n", MaxLength)
		case len(out) < min:
			t.Printf("Digite pelo menos %d mãos.\n", min)
		default:
			return out, nil
		}
	}
	return nil, ErrTooManyInvalid
}

func parse(line string, perm []int) ([]byte, bool) {
	var out []byte
	for _, r := range line {
		switch {
		case r == ' ' || r == '\t':
		case r >= '1' && r <= '9':
			out = append(out, byte(perm[r-'1']))
		default:
			return nil, false
		}
	}
	return out, len(out) <= MaxLength
}

// Sequence renders movements typed so far.
func Sequence(seq []byte) string {
	parts := make([]string, len(seq))
	for i, m := range seq {
		if handmove.ShowEmoji {
			parts[i] = handmove.Emojis[m]
		} else {
			parts[i] = handmove.Movements[m]
		}
	}
	if handmove.ShowEmoji {
		return strings.Join(parts, " ")
	}
	return strings.Join(parts, " · ")
}

// order returns the digit → movement mapping for one pass.
func order(rnd io.Reader) ([]int, error) {
	n := len(handmove.Movements)
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	if FixedOrder {
		return p, nil
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	for i := n - 1; i > 0; i-- {
		v, err := rand.Int(rnd, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, fmt.Errorf("handseq: random: %w", err)
		}
		j := int(v.Int64())
		p[i], p[j] = p[j], p[i]
	}
	return p, nil
}

func distinct(b []byte) int {
	seen := map[byte]bool{}
	for _, x := range b {
		seen[x] = true
	}
	return len(seen)
}
