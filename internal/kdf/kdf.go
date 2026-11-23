// Package kdf hashes handshake secrets with Argon2id.
//
// The handshake secrets have a small keyspace (e.g. 10 answers from 1..9 is
// ~3.4e9 combinations), so a fast hash would be brute-forced offline in
// seconds. Argon2id is memory-hard, which makes each guess expensive on CPUs
// and GPUs alike.
package kdf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// AlgArgon2id is the only supported algorithm identifier.
const AlgArgon2id = "argon2id"

// Default cost parameters. ~64 MiB and 3 passes takes roughly 100-300 ms on a
// typical server core, which is fine for an interactive login.
const (
	DefaultTime      uint32 = 3
	DefaultMemoryKiB uint32 = 64 * 1024
	DefaultThreads   uint8  = 2
	SaltLen                 = 16
	KeyLen                  = 32
)

// Bounds accepted when verifying a stored record. The lower bound stops a
// tampered record from downgrading the hash; the upper bound stops a crafted
// record from exhausting memory or CPU.
const (
	minTime      uint32 = 1
	maxTime      uint32 = 20
	minMemoryKiB uint32 = 19 * 1024 // OWASP minimum for argon2id
	maxMemoryKiB uint32 = 1024 * 1024
	minThreads   uint8  = 1
	maxThreads   uint8  = 16
)

// Params is the serialized form of a hashed secret.
type Params struct {
	Alg       string `json:"alg"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	Salt      []byte `json:"salt"`
	Hash      []byte `json:"hash"`
}

// Hash derives a new Params for secret, bound to the associated data ad
// (username, validator name and validator parameters), using fresh salt.
func Hash(secret, ad []byte, rnd io.Reader) (Params, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rnd, salt); err != nil {
		return Params{}, fmt.Errorf("kdf: reading salt: %w", err)
	}
	p := Params{
		Alg:       AlgArgon2id,
		Time:      DefaultTime,
		MemoryKiB: DefaultMemoryKiB,
		Threads:   DefaultThreads,
		Salt:      salt,
	}
	p.Hash = derive(p, secret, ad)
	return p, nil
}

// Validate checks that p is well-formed and within the accepted cost bounds.
func (p Params) Validate() error {
	switch {
	case p.Alg != AlgArgon2id:
		return fmt.Errorf("kdf: unsupported algorithm %q", p.Alg)
	case p.Time < minTime || p.Time > maxTime:
		return fmt.Errorf("kdf: time %d out of range", p.Time)
	case p.MemoryKiB < minMemoryKiB || p.MemoryKiB > maxMemoryKiB:
		return fmt.Errorf("kdf: memory %d KiB out of range", p.MemoryKiB)
	case p.Threads < minThreads || p.Threads > maxThreads:
		return fmt.Errorf("kdf: threads %d out of range", p.Threads)
	case len(p.Salt) < SaltLen:
		return errors.New("kdf: salt too short")
	case len(p.Hash) != KeyLen:
		return errors.New("kdf: bad hash length")
	}
	return nil
}

// Verify reports whether secret (with associated data ad) matches p. The
// comparison is constant-time.
func (p Params) Verify(secret, ad []byte) (bool, error) {
	if err := p.Validate(); err != nil {
		return false, err
	}
	got := derive(p, secret, ad)
	return subtle.ConstantTimeCompare(got, p.Hash) == 1, nil
}

func derive(p Params, secret, ad []byte) []byte {
	// Length-prefix both parts so (ad, secret) pairs can never collide.
	in := make([]byte, 0, 16+len(ad)+len(secret))
	in = binary.BigEndian.AppendUint64(in, uint64(len(ad)))
	in = append(in, ad...)
	in = binary.BigEndian.AppendUint64(in, uint64(len(secret)))
	in = append(in, secret...)
	return argon2.IDKey(in, p.Salt, p.Time, p.MemoryKiB, p.Threads, KeyLen)
}
