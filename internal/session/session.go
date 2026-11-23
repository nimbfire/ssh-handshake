// Package session hands the connection over to the user's shell once the
// handshake has passed.
package session

import (
	"os"
	"path/filepath"
	"syscall"
)

// Exec replaces the current process with the user's login shell, or with
// `$SHELL -c "$SSH_ORIGINAL_COMMAND"` when the client asked for a command.
// It only returns on error.
//
// SHELL is set by sshd from the passwd entry; with PermitUserEnvironment=no
// (the default) the client cannot override it.
func Exec() error {
	shell := os.Getenv("SHELL")
	if shell == "" || !filepath.IsAbs(shell) {
		shell = "/bin/sh"
	}
	argv := []string{"-" + filepath.Base(shell)} // leading '-' = login shell
	if cmd, ok := os.LookupEnv("SSH_ORIGINAL_COMMAND"); ok && cmd != "" {
		argv = []string{filepath.Base(shell), "-c", cmd}
	}
	return syscall.Exec(shell, argv, os.Environ())
}
