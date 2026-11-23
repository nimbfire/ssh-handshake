// Package store reads and writes handshake records.
//
// Two backends exist:
//
//   - Home: ~/.ssh/ssh-handshake, owned by the user. Convenient and allows
//     self-enrollment, but the user (or anything running as the user) can
//     delete or replace the file.
//   - System: <dir>/<user> (default /var/lib/ssh-handshake), owned by root
//     and only readable by the user's group. The user cannot change it;
//     only root can enroll or reset. This is the recommended mode.
//
// Both backends refuse symlinks and files or directories that are writable
// by someone who should not be able to write them, in the spirit of sshd's
// StrictModes.
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nimbfire/ssh-handshake/internal/kdf"
)

// FileName is the handshake file name inside ~/.ssh.
const FileName = "ssh-handshake"

// DefaultSystemDir is the default directory of the system store.
const DefaultSystemDir = "/var/lib/ssh-handshake"

// CurrentVersion is the record format version.
const CurrentVersion = 1

const maxRecordSize = 64 << 10

// ErrNotFound means the user has no handshake yet.
var ErrNotFound = errors.New("store: no handshake configured")

// Account identifies the local user a record belongs to.
type Account struct {
	Name string
	UID  int
	GID  int
	Home string
}

// Record is the on-disk handshake.
type Record struct {
	Version   int             `json:"version"`
	User      string          `json:"user"`
	Validator string          `json:"validator"`
	Params    json.RawMessage `json:"params"`
	KDF       kdf.Params      `json:"kdf"`
	CreatedAt time.Time       `json:"created_at"`
}

// AssociatedData is what the secret hash is bound to: changing the user,
// the validator or its parameters invalidates the hash.
func (r *Record) AssociatedData() []byte {
	return AssociatedData(r.User, r.Validator, r.Params)
}

// AssociatedData builds the KDF associated data. params is compacted first
// so that re-indenting the JSON file does not change the binding.
func AssociatedData(user, validatorName string, params []byte) []byte {
	var compact bytes.Buffer
	if err := json.Compact(&compact, params); err == nil {
		params = compact.Bytes()
	}
	var b strings.Builder
	b.WriteString("ssh-handshake/v1\x00")
	b.WriteString(user)
	b.WriteByte(0)
	b.WriteString(validatorName)
	b.WriteByte(0)
	b.Write(params)
	return []byte(b.String())
}

// Check validates the record's structure and owner.
func (r *Record) Check(acct Account) error {
	if r.Version != CurrentVersion {
		return fmt.Errorf("store: unsupported record version %d", r.Version)
	}
	if r.User != acct.Name {
		return fmt.Errorf("store: record belongs to %q, not %q", r.User, acct.Name)
	}
	if r.Validator == "" || len(r.Params) == 0 {
		return errors.New("store: record missing validator")
	}
	return r.KDF.Validate()
}

// Decode parses and checks a record.
func Decode(data []byte, acct Account) (*Record, error) {
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("store: decoding record: %w", err)
	}
	if err := r.Check(acct); err != nil {
		return nil, err
	}
	return &r, nil
}

// Store loads and saves records.
type Store interface {
	// Path returns where acct's record lives.
	Path(acct Account) (string, error)
	Load(acct Account) (*Record, error)
	Save(acct Account, r *Record) error
	// SelfWritable reports whether a user can write their own record.
	SelfWritable() bool
}

// ---- Home store -----------------------------------------------------------

// Home stores the record in ~/.ssh/ssh-handshake.
type Home struct{}

func (Home) SelfWritable() bool { return true }

func (Home) Path(acct Account) (string, error) {
	if acct.Home == "" || !filepath.IsAbs(acct.Home) {
		return "", fmt.Errorf("store: invalid home directory %q", acct.Home)
	}
	return filepath.Join(acct.Home, ".ssh", FileName), nil
}

func (h Home) Load(acct Account) (*Record, error) {
	p, err := h.Path(acct)
	if err != nil {
		return nil, err
	}
	allowed := func(uid int) bool { return uid == acct.UID || uid == 0 }
	if err := checkDir(filepath.Dir(p), allowed, 0o022); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	data, err := readSecure(p, allowed, 0o022)
	if err != nil {
		return nil, err
	}
	return Decode(data, acct)
}

func (h Home) Save(acct Account, r *Record) error {
	p, err := h.Path(acct)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := os.Mkdir(dir, 0o700); err == nil {
		if err := chownIfRoot(dir, acct.UID, acct.GID); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return err
	}
	allowed := func(uid int) bool { return uid == acct.UID || uid == 0 }
	if err := checkDir(dir, allowed, 0o022); err != nil {
		return err
	}
	return writeAtomic(p, r, 0o600, func(f *os.File) error {
		if os.Geteuid() == 0 {
			return f.Chown(acct.UID, acct.GID)
		}
		return nil
	})
}

// ---- System store ---------------------------------------------------------

// System stores records as root-owned files in Dir.
type System struct {
	Dir string
}

func (System) SelfWritable() bool { return false }

func (s System) dir() string {
	if s.Dir == "" {
		return DefaultSystemDir
	}
	return s.Dir
}

func (s System) Path(acct Account) (string, error) {
	if err := validUserName(acct.Name); err != nil {
		return "", err
	}
	return filepath.Join(s.dir(), acct.Name), nil
}

func (s System) Load(acct Account) (*Record, error) {
	p, err := s.Path(acct)
	if err != nil {
		return nil, err
	}
	rootOnly := func(uid int) bool { return uid == 0 }
	if err := checkDir(s.dir(), rootOnly, 0o022); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	data, err := readSecure(p, rootOnly, 0o022)
	if err != nil {
		return nil, err
	}
	return Decode(data, acct)
}

func (s System) Save(acct Account, r *Record) error {
	if os.Geteuid() != 0 {
		return errors.New("store: the system store can only be written by root")
	}
	p, err := s.Path(acct)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir(), 0o755); err != nil {
		return err
	}
	rootOnly := func(uid int) bool { return uid == 0 }
	if err := checkDir(s.dir(), rootOnly, 0o022); err != nil {
		return err
	}
	// root:<user's group> 0640 so the user's login process can read it but
	// nobody except root can change it, and other users cannot read it.
	return writeAtomic(p, r, 0o640, func(f *os.File) error {
		return f.Chown(0, acct.GID)
	})
}

// ---- helpers ----------------------------------------------------------------

func validUserName(n string) error {
	if n == "" || n == "." || n == ".." || len(n) > 64 ||
		strings.ContainsAny(n, "/\x00") || strings.HasPrefix(n, ".") {
		return fmt.Errorf("store: invalid user name %q", n)
	}
	return nil
}

func checkDir(path string, ownerOK func(int) bool, forbidden fs.FileMode) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("store: %s is not a directory", path)
	}
	return checkOwnerMode(path, fi, ownerOK, forbidden)
}

func checkOwnerMode(path string, fi fs.FileInfo, ownerOK func(int) bool, forbidden fs.FileMode) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("store: cannot stat owner of %s", path)
	}
	if !ownerOK(int(st.Uid)) {
		return fmt.Errorf("store: bad owner (uid %d) on %s", st.Uid, path)
	}
	if fi.Mode().Perm()&forbidden != 0 {
		return fmt.Errorf("store: bad permissions %v on %s", fi.Mode().Perm(), path)
	}
	return nil
}

func readSecure(path string, ownerOK func(int) bool, forbidden fs.FileMode) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("store: %s is a symlink", path)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("store: %s is not a regular file", path)
	}
	if err := checkOwnerMode(path, fi, ownerOK, forbidden); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRecordSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRecordSize {
		return nil, fmt.Errorf("store: %s too large", path)
	}
	return data, nil
}

func writeAtomic(path string, r *Record, mode fs.FileMode, fix func(*os.File) error) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if err := fix(tmp); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func chownIfRoot(path string, uid, gid int) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return os.Lchown(path, uid, gid)
}
