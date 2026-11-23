// Package validator defines the plug-in interface for handshake validators
// and a registry of the available ones.
//
// A validator owns the conversation with the user. It never sees or stores
// the hash: Enroll returns public parameters (stored in clear text) plus the
// secret bytes, and Challenge returns the candidate secret bytes. The caller
// hashes those with Argon2id and does the constant-time comparison. This
// keeps the security-sensitive part in one place for every validator.
package validator

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/nimbfire/ssh-handshake/internal/terminal"
)

// EnrollOptions are generic knobs for enrollment. Validators may ignore
// fields that do not apply to them.
type EnrollOptions struct {
	// Length is the number of steps/questions, when the validator has one.
	// Zero means the validator's default.
	Length int
}

// Validator is one kind of handshake.
type Validator interface {
	// Name is the stable identifier written to the handshake file.
	Name() string
	// Description is a one-line human description.
	Description() string
	// Enroll interacts with the user to create a new handshake. It returns
	// the public parameters to persist and the secret to hash.
	Enroll(t terminal.Terminal, rnd io.Reader, opts EnrollOptions) (params json.RawMessage, secret []byte, err error)
	// Challenge asks the user to prove knowledge of the handshake described
	// by params and returns the candidate secret. It must not reveal, while
	// asking, whether individual answers are right or wrong.
	Challenge(t terminal.Terminal, rnd io.Reader, params json.RawMessage) (secret []byte, err error)
}

var (
	mu       sync.RWMutex
	registry = map[string]Validator{}
)

// Register makes v available by name. It panics on duplicates, like
// database/sql.Register.
func Register(v Validator) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[v.Name()]; dup {
		panic("validator: duplicate registration of " + v.Name())
	}
	registry[v.Name()] = v
}

// Get returns the validator registered under name.
func Get(name string) (Validator, error) {
	mu.RLock()
	defer mu.RUnlock()
	v, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("validator: unknown validator %q", name)
	}
	return v, nil
}

// Names lists registered validators, sorted.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
