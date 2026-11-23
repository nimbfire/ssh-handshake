package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nimbfire/ssh-handshake/internal/kdf"
)

func testAccount(t *testing.T) Account {
	t.Helper()
	return Account{Name: "alice", UID: os.Getuid(), GID: os.Getgid(), Home: t.TempDir()}
}

func testRecord(t *testing.T, acct Account) *Record {
	t.Helper()
	params := json.RawMessage(`{"cues":[1,2,3,4,5,6,7,8]}`)
	k, err := kdf.Hash([]byte("secret"), AssociatedData(acct.Name, "handmove", params), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Record{Version: CurrentVersion, User: acct.Name, Validator: "handmove", Params: params, KDF: k, CreatedAt: time.Now()}
}

func TestHomeRoundTrip(t *testing.T) {
	acct := testAccount(t)
	h := Home{}
	if _, err := h.Load(acct); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing ~/.ssh: err = %v, want ErrNotFound", err)
	}
	rec := testRecord(t, acct)
	if err := h.Save(acct, rec); err != nil {
		t.Fatal(err)
	}
	p, _ := h.Path(acct)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
	got, err := h.Load(acct)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := got.KDF.Verify([]byte("secret"), got.AssociatedData()); !ok {
		t.Fatal("loaded record does not verify")
	}
}

func TestHomeRejectsBadPermissions(t *testing.T) {
	acct := testAccount(t)
	h := Home{}
	if err := h.Save(acct, testRecord(t, acct)); err != nil {
		t.Fatal(err)
	}
	p, _ := h.Path(acct)

	os.Chmod(p, 0o666)
	if _, err := h.Load(acct); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("world-writable file: err = %v", err)
	}
	os.Chmod(p, 0o600)

	os.Chmod(filepath.Dir(p), 0o777)
	if _, err := h.Load(acct); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("world-writable ~/.ssh: err = %v", err)
	}
	os.Chmod(filepath.Dir(p), 0o700)
}

func TestHomeRejectsSymlink(t *testing.T) {
	acct := testAccount(t)
	h := Home{}
	if err := h.Save(acct, testRecord(t, acct)); err != nil {
		t.Fatal(err)
	}
	p, _ := h.Path(acct)
	real := p + ".real"
	os.Rename(p, real)
	os.Symlink(real, p)
	if _, err := h.Load(acct); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("symlink: err = %v", err)
	}
}

func TestRejectsOtherUsersRecord(t *testing.T) {
	acct := testAccount(t)
	h := Home{}
	bob := acct
	bob.Name = "bob"
	// Save bob's record into alice's home.
	if err := h.Save(acct, testRecord(t, bob)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Load(acct); err == nil {
		t.Error("accepted a record belonging to another user")
	}
}

func TestCorruptRecord(t *testing.T) {
	acct := testAccount(t)
	h := Home{}
	p, _ := h.Path(acct)
	os.MkdirAll(filepath.Dir(p), 0o700)
	os.WriteFile(p, []byte("{not json"), 0o600)
	if _, err := h.Load(acct); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("corrupt: err = %v (must fail closed, not look like 'not found')", err)
	}
}

func TestSystemStore(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("system store tests need root")
	}
	dir := filepath.Join(t.TempDir(), "store")
	s := System{Dir: dir}
	acct := testAccount(t)
	if _, err := s.Load(acct); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if err := s.Save(acct, testRecord(t, acct)); err != nil {
		t.Fatal(err)
	}
	p, _ := s.Path(acct)
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
	if _, err := s.Load(acct); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, 0o660)
	if _, err := s.Load(acct); err == nil {
		t.Error("accepted group-writable system record")
	}
}

func TestSystemRejectsBadNames(t *testing.T) {
	s := System{Dir: t.TempDir()}
	for _, n := range []string{"", ".", "..", "../etc/passwd", "a/b", ".hidden"} {
		if _, err := s.Path(Account{Name: n}); err == nil {
			t.Errorf("accepted user name %q", n)
		}
	}
}
