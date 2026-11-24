// Package app holds the login, enrollment and install flows, independent of
// process concerns (flags, signals, exec) so they can be tested.
package app

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/nimbfire/ssh-handshake/internal/audit"
	"github.com/nimbfire/ssh-handshake/internal/kdf"
	"github.com/nimbfire/ssh-handshake/internal/store"
	"github.com/nimbfire/ssh-handshake/internal/terminal"
	"github.com/nimbfire/ssh-handshake/internal/validator"
)

// ErrDenied is returned when access must not be granted.
var ErrDenied = errors.New("handshake failed")

// Config drives the flows.
type Config struct {
	Store store.Store
	// AllowSelfEnroll lets a user with no handshake create one on login
	// (trust on first use). Only possible with a self-writable store.
	AllowSelfEnroll bool
	// Validator used for new enrollments.
	Validator string
	// Length passed to the validator on enrollment.
	Length int
	// MinLength passed to the validator on enrollment.
	MinLength int
	// SoundMarkers makes Login print an invisible OSC marker with the result
	// ("success" or "error"). A terminal running inside "fuoda.sh shell"
	// plays the matching sound; other terminals ignore the sequence.
	SoundMarkers bool
	// FailDelay is slept before reporting a failure, to slow online guessing.
	FailDelay time.Duration
	Log       audit.Logger
	Rand      io.Reader
	// Sleep is overridable in tests.
	Sleep func(time.Duration)
}

func (c *Config) defaults() {
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	if c.Log == nil {
		c.Log = audit.Nop{}
	}
	if c.Sleep == nil {
		c.Sleep = time.Sleep
	}
	if c.Validator == "" {
		c.Validator = "handmove"
	}
}

// SoundMarker is the OSC sequence understood by "fuoda.sh shell".
func SoundMarker(event string) string { return "\033]777;fuoda;" + event + "\a" }

func (c Config) sound(t terminal.Terminal, event string) {
	if c.SoundMarkers {
		t.Printf("%s", SoundMarker(event))
	}
}

// Login runs the handshake for acct. A nil error means access is granted.
// Every failure path returns ErrDenied (wrapped) after FailDelay.
func Login(c Config, acct store.Account, t terminal.Terminal) error {
	c.defaults()
	deny := func(reason string, err error) error {
		c.Log.Warn(fmt.Sprintf("denied user=%s %s reason=%q", acct.Name, audit.Remote(), reason))
		c.Sleep(c.FailDelay)
		c.sound(t, "error")
		t.Printf("\nHandshake falhou. Desconectando.\n")
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrDenied, reason, err)
		}
		return fmt.Errorf("%w: %s", ErrDenied, reason)
	}

	rec, err := c.Store.Load(acct)
	if errors.Is(err, store.ErrNotFound) {
		if !c.AllowSelfEnroll || !c.Store.SelfWritable() {
			c.Log.Warn(fmt.Sprintf("denied user=%s %s reason=\"no handshake configured\"", acct.Name, audit.Remote()))
			t.Printf("\nNenhum handshake configurado para %s. Contate o administrador.\n", acct.Name)
			c.Sleep(c.FailDelay)
			c.sound(t, "error")
			return fmt.Errorf("%w: no handshake configured", ErrDenied)
		}
		t.Printf("\nNenhum handshake configurado para %s. Vamos criar um agora.\n", acct.Name)
		if err := Enroll(c, acct, t); err != nil {
			return deny("enrollment failed", err)
		}
		c.Log.Info(fmt.Sprintf("enrolled user=%s %s validator=%s (first login)", acct.Name, audit.Remote(), c.Validator))
		c.sound(t, "success")
		t.Printf("\nHandshake criado. Acesso liberado.\n\n")
		return nil
	}
	if err != nil {
		// Corrupt, tampered or badly-permissioned file: fail closed and do
		// NOT offer enrollment, otherwise breaking the file would reset it.
		return deny("cannot load handshake", err)
	}

	ok, err := Verify(c, rec, t)
	if err != nil {
		return deny("challenge error", err)
	}
	if !ok {
		return deny("wrong answer", nil)
	}
	c.Log.Info(fmt.Sprintf("accepted user=%s %s validator=%s", acct.Name, audit.Remote(), rec.Validator))
	c.sound(t, "success")
	t.Printf("\nHandshake ok.\n\n")
	return nil
}

// Verify asks the challenge for rec and checks the answer.
func Verify(c Config, rec *store.Record, t terminal.Terminal) (bool, error) {
	c.defaults()
	v, err := validator.Get(rec.Validator)
	if err != nil {
		return false, err
	}
	secret, err := v.Challenge(t, c.Rand, rec.Params)
	if err != nil {
		return false, err
	}
	return rec.KDF.Verify(secret, rec.AssociatedData())
}

// NewRecord runs the validator enrollment and returns a hashed record,
// without saving it.
func NewRecord(c Config, acct store.Account, t terminal.Terminal) (*store.Record, error) {
	c.defaults()
	v, err := validator.Get(c.Validator)
	if err != nil {
		return nil, err
	}
	params, secret, err := v.Enroll(t, c.Rand, validator.EnrollOptions{Length: c.Length, MinLength: c.MinLength})
	if err != nil {
		return nil, err
	}
	k, err := kdf.Hash(secret, store.AssociatedData(acct.Name, v.Name(), params), c.Rand)
	if err != nil {
		return nil, err
	}
	rec := &store.Record{
		Version:   store.CurrentVersion,
		User:      acct.Name,
		Validator: v.Name(),
		Params:    params,
		KDF:       k,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	return rec, rec.Check(acct)
}

// Enroll creates a record and saves it to the store.
func Enroll(c Config, acct store.Account, t terminal.Terminal) error {
	rec, err := NewRecord(c, acct, t)
	if err != nil {
		return err
	}
	return c.Store.Save(acct, rec)
}
