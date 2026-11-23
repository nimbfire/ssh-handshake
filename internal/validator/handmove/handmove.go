// Package handmove implements the question-and-answer "hand movement"
// handshake.
//
// At enrollment a fixed sequence of server movements (cues) is drawn at
// random and the user picks, for each cue, which movement they answer with.
// At login the server shows the same cues in order; for each one it lists
// the nine possible answers in a freshly shuffled order and the user types
// 1-9. What is hashed is the identity of the chosen movement, not the digit,
// so the digits typed change every login and are useless to a keylogger or a
// shoulder surfer on their own.
//
// All nine options are always shown, so watching many logins never narrows
// the candidate set.
package handmove

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"

	"github.com/nimbfire/ssh-handshake/internal/terminal"
	"github.com/nimbfire/ssh-handshake/internal/validator"
)

// Name is the identifier stored in handshake files.
const Name = "handmove"

const (
	// MinLength gives 9^8 ≈ 4.3e7 combinations; together with Argon2id
	// that is the minimum accepted.
	MinLength = 8
	// DefaultLength gives 9^10 ≈ 3.5e9 combinations.
	DefaultLength = 10
	MaxLength     = 32
	// minDistinct rejects degenerate sequences such as "always the fist".
	minDistinct = 3
	// maxInvalid is how many unparsable inputs are tolerated per question.
	maxInvalid = 3
)

// Movements is the catalog. Its order is part of the on-disk format: the
// secret stores indexes into it, so never reorder or remove entries.
var Movements = [9]string{
	"Mão aberta (palma para frente)",
	"Punho fechado",
	"Polegar para cima",
	"Polegar para baixo",
	"Sinal de V (paz)",
	"Indicador apontando",
	"Sinal de OK",
	"Chifres (indicador e mindinho)",
	"Mão em concha",
}

// Emojis shows each movement as an emoji, same order as Movements.
var Emojis = [9]string{"✋", "✊", "👍", "👎", "✌️", "👉", "👌", "🤘", "🤲"}

// ShowEmoji controls whether emojis are printed next to movement names.
// Terminals without emoji fonts (e.g. old Windows conhost) can turn it off
// with --no-emoji. Names are always printed too.
var ShowEmoji = true

// Label is how a movement is shown to the user.
func Label(i int) string {
	if ShowEmoji {
		return Emojis[i] + "  " + Movements[i]
	}
	return Movements[i]
}

// Errors returned by the validator.
var (
	ErrTooManyInvalid = errors.New("handmove: too many invalid answers")
	ErrMismatch       = errors.New("handmove: confirmation does not match")
	ErrWeak           = fmt.Errorf("handmove: use at least %d different answers", minDistinct)
)

// Params is the public, stored part of a handmove handshake.
type Params struct {
	// Cues are the server movements, as indexes into Movements.
	Cues []int `json:"cues"`
}

// Validate checks p is well formed.
func (p Params) Validate() error {
	if len(p.Cues) < MinLength || len(p.Cues) > MaxLength {
		return fmt.Errorf("handmove: length %d out of range [%d,%d]", len(p.Cues), MinLength, MaxLength)
	}
	for _, c := range p.Cues {
		if c < 0 || c >= len(Movements) {
			return fmt.Errorf("handmove: invalid cue %d", c)
		}
	}
	return nil
}

// Validator is the handmove validator.
type Validator struct{}

func init() { validator.Register(Validator{}) }

func (Validator) Name() string { return Name }

func (Validator) Description() string {
	return "perguntas e respostas: o servidor mostra um movimento de mão e você responde com o seu (1-9)"
}

func (v Validator) Enroll(t terminal.Terminal, rnd io.Reader, opts validator.EnrollOptions) (json.RawMessage, []byte, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	n := opts.Length
	if n == 0 {
		n = DefaultLength
	}
	p := Params{Cues: make([]int, n)}
	for i := range p.Cues {
		c, err := randInt(rnd, len(Movements))
		if err != nil {
			return nil, nil, err
		}
		p.Cues[i] = c
	}
	if err := p.Validate(); err != nil {
		return nil, nil, err
	}

	first, err := ask(t, rnd, p.Cues, fmt.Sprintf("== Criando novo handshake (%d passos) ==\n", n)+
		"Para cada movimento do servidor, escolha o movimento com que você responde.\n"+
		"Memorize a sequência: ela não pode ser recuperada, só redefinida.\n")
	if err != nil {
		return nil, nil, err
	}
	if distinct(first) < minDistinct {
		return nil, nil, ErrWeak
	}

	second, err := ask(t, rnd, p.Cues, "== Confirme o handshake (os números das opções foram sorteados de novo) ==\n")
	if err != nil {
		return nil, nil, err
	}
	if string(first) != string(second) {
		return nil, nil, ErrMismatch
	}

	raw, err := json.Marshal(p)
	if err != nil {
		return nil, nil, err
	}
	return raw, first, nil
}

func (v Validator) Challenge(t terminal.Terminal, rnd io.Reader, raw json.RawMessage) ([]byte, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	var p Params
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("handmove: bad params: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return ask(t, rnd, p.Cues, "== ssh-handshake ==\n")
}

// ask runs one pass over the cues and returns the chosen movement indexes.
// It gives no feedback on correctness.
//
// The options are shuffled once per pass, so the digit of each movement stays
// the same for the whole pass and changes on the next login. Before each
// question the answers given so far are shown again. On a TTY the screen is
// redrawn instead of scrolling.
func ask(t terminal.Terminal, rnd io.Reader, cues []int, header string) ([]byte, error) {
	perm, err := shuffle(rnd, len(Movements))
	if err != nil {
		return nil, err
	}
	k, ok := t.(terminal.KeyReader)
	redraw := ok && k.KeyMode()
	if !redraw {
		t.Printf("\n%s", header)
	}
	out := make([]byte, 0, len(cues))
	render := func() {
		if redraw {
			t.Printf("\033[H\033[2J%s", header)
		}
		t.Printf("\nOpções:\n")
		for j, m := range perm {
			t.Printf("  %d) %s\n", j+1, Label(m))
		}
		if len(out) > 0 {
			t.Printf("\nSuas respostas até agora:\n")
			for i, a := range out {
				t.Printf("  [%d/%d] %s  →  %s\n", i+1, len(cues), Label(cues[i]), Label(int(a)))
			}
		}
	}
	for i, cue := range cues {
		render()
		t.Printf("\n[%d/%d] Meu movimento: %s\n", i+1, len(cues), Label(cue))
		choice, err := readChoice(t, len(perm))
		if err != nil {
			return nil, err
		}
		out = append(out, byte(perm[choice-1]))
	}
	if redraw {
		render()
	}
	return out, nil
}

func readChoice(t terminal.Terminal, max int) (int, error) {
	// On a TTY one keypress is enough (options are 1-9): no Enter needed.
	if k, ok := t.(terminal.KeyReader); ok && k.KeyMode() && max <= 9 {
		accept := "123456789"[:max]
		c, err := k.ReadKey(fmt.Sprintf("Sua resposta (1-%d): ", max), accept)
		if err != nil {
			return 0, err
		}
		return int(c - '0'), nil
	}
	for attempt := 0; attempt < maxInvalid; attempt++ {
		line, err := t.ReadLine(fmt.Sprintf("Sua resposta (1-%d): ", max))
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(line)
		if err == nil && n >= 1 && n <= max {
			return n, nil
		}
		t.Printf("Entrada inválida.\n")
	}
	return 0, ErrTooManyInvalid
}

func shuffle(rnd io.Reader, n int) ([]int, error) {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j, err := randInt(rnd, i+1)
		if err != nil {
			return nil, err
		}
		p[i], p[j] = p[j], p[i]
	}
	return p, nil
}

func randInt(rnd io.Reader, n int) (int, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	v, err := rand.Int(rnd, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("handmove: random: %w", err)
	}
	return int(v.Int64()), nil
}

func distinct(b []byte) int {
	seen := map[byte]bool{}
	for _, x := range b {
		seen[x] = true
	}
	return len(seen)
}
