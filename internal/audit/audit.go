// Package audit logs handshake outcomes to syslog (facility AUTH) so they
// sit next to sshd's own logs and can feed fail2ban.
package audit

import (
	"fmt"
	"log/syslog"
	"os"
	"strings"
)

// Logger records handshake events.
type Logger interface {
	Info(msg string)
	Warn(msg string)
}

// Syslog logs to the local syslog, falling back to stderr-less no-op when
// syslog is unavailable (we never want logging to break the login path).
type Syslog struct{ w *syslog.Writer }

// NewSyslog opens a syslog writer tagged "ssh-handshake".
func NewSyslog() *Syslog {
	w, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_NOTICE, "ssh-handshake")
	if err != nil {
		return &Syslog{}
	}
	return &Syslog{w: w}
}

func (s *Syslog) Info(msg string) {
	if s.w != nil {
		_ = s.w.Info(msg)
	}
}

func (s *Syslog) Warn(msg string) {
	if s.w != nil {
		_ = s.w.Warning(msg)
	}
}

// Nop discards everything.
type Nop struct{}

func (Nop) Info(string) {}
func (Nop) Warn(string) {}

// Remote returns "from=<ip> port=<port>" built from SSH_CONNECTION.
func Remote() string {
	f := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(f) < 2 {
		return "from=unknown"
	}
	return fmt.Sprintf("from=%s port=%s", f[0], f[1])
}
