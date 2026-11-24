package app

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nimbfire/ssh-handshake/internal/store"
	"github.com/nimbfire/ssh-handshake/internal/testutil"
	"github.com/nimbfire/ssh-handshake/internal/validator/handmove"
)

var answer = []int{4, 4, 0, 1, 2, 8, 7, 3, 3, 6}

func seq(idx []int) []string {
	out := make([]string, len(idx))
	for i, x := range idx {
		out[i] = handmove.Movements[x]
	}
	return out
}

type recLog struct{ info, warn []string }

func (l *recLog) Info(m string) { l.info = append(l.info, m) }
func (l *recLog) Warn(m string) { l.warn = append(l.warn, m) }

func setup(t *testing.T, selfEnroll bool) (Config, store.Account, *recLog, *[]time.Duration) {
	acct := store.Account{Name: "alice", UID: os.Getuid(), GID: os.Getgid(), Home: t.TempDir()}
	log := &recLog{}
	var slept []time.Duration
	cfg := Config{
		Store:           store.Home{},
		AllowSelfEnroll: selfEnroll,
		FailDelay:       time.Second,
		Log:             log,
		Sleep:           func(d time.Duration) { slept = append(slept, d) },
	}
	return cfg, acct, log, &slept
}

func TestFirstLoginEnrollThenLogin(t *testing.T) {
	cfg, acct, log, _ := setup(t, true)
	a := &testutil.Answerer{Want: append(seq(answer), seq(answer)...)}
	if err := Login(cfg, acct, a); err != nil {
		t.Fatalf("first login: %v\n%s", err, a.Out.String())
	}
	if len(log.info) != 1 {
		t.Fatalf("logs: %v", log.info)
	}

	ok := &testutil.Answerer{Want: seq(answer)}
	if err := Login(cfg, acct, ok); err != nil {
		t.Fatalf("second login: %v", err)
	}

	wrong := append([]int(nil), answer...)
	wrong[9] = 0
	bad := &testutil.Answerer{Want: seq(wrong)}
	err := Login(cfg, acct, bad)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong answer: err = %v", err)
	}
	if len(log.warn) != 1 {
		t.Fatalf("warn logs: %v", log.warn)
	}
}

func TestNoSelfEnrollDenies(t *testing.T) {
	cfg, acct, _, slept := setup(t, false)
	a := &testutil.Answerer{Want: append(seq(answer), seq(answer)...)}
	if err := Login(cfg, acct, a); !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v", err)
	}
	if len(*slept) != 1 {
		t.Fatal("no fail delay")
	}
	if _, err := cfg.Store.Load(acct); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a record was created without self-enroll")
	}
}

func TestBrokenFileDoesNotReEnroll(t *testing.T) {
	cfg, acct, _, _ := setup(t, true)
	a := &testutil.Answerer{Want: append(seq(answer), seq(answer)...)}
	if err := Login(cfg, acct, a); err != nil {
		t.Fatal(err)
	}
	p, _ := cfg.Store.Path(acct)
	os.WriteFile(p, []byte("garbage"), 0o600)
	b := &testutil.Answerer{Want: append(seq(answer), seq(answer)...)}
	if err := Login(cfg, acct, b); !errors.Is(err, ErrDenied) {
		t.Fatalf("corrupted file must deny, got %v", err)
	}
}

func TestSessionEndsOnEOF(t *testing.T) {
	cfg, acct, _, _ := setup(t, true)
	a := &testutil.Answerer{Want: append(seq(answer), seq(answer)...)}
	if err := Login(cfg, acct, a); err != nil {
		t.Fatal(err)
	}
	// Client closes stdin after 3 answers.
	short := &testutil.Answerer{Want: seq(answer[:3])}
	if err := Login(cfg, acct, short); !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v", err)
	}
}

func TestSoundMarkers(t *testing.T) {
	cfg, acct, _, _ := setup(t, true)
	first := &testutil.Answerer{Want: append(seq(answer), seq(answer)...)}
	if err := Login(cfg, acct, first); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(first.Out.String(), "\033]777;") {
		t.Fatal("marker sent without SoundMarkers")
	}

	cfg.SoundMarkers = true
	ok := &testutil.Answerer{Want: seq(answer)}
	if err := Login(cfg, acct, ok); err != nil {
		t.Fatal(err)
	}
	if out := ok.Out.String(); !strings.Contains(out, SoundMarker("success")) || strings.Contains(out, SoundMarker("error")) {
		t.Fatalf("success login output: %q", out)
	}

	wrong := append([]int(nil), answer...)
	wrong[0] = (wrong[0] + 1) % 9
	bad := &testutil.Answerer{Want: seq(wrong)}
	if err := Login(cfg, acct, bad); !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v", err)
	}
	if out := bad.Out.String(); !strings.Contains(out, SoundMarker("error")) || strings.Contains(out, SoundMarker("success")) {
		t.Fatalf("failed login output: %q", out)
	}
}
