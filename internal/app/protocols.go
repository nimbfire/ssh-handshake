package app

import (
	"path/filepath"
	"strings"
)

// IsFileTransfer reports whether the command requested by the SSH client
// (SSH_ORIGINAL_COMMAND) is a machine protocol (sftp, scp, rsync, git) that
// can never answer an interactive handshake. Such sessions are refused right
// away instead of hanging until the timeout.
func IsFileTransfer(cmd string) bool {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return false
	}
	switch filepath.Base(f[0]) {
	case "internal-sftp", "sftp-server", "scp", "git-upload-pack",
		"git-receive-pack", "git-upload-archive":
		return true
	case "rsync":
		return len(f) > 1 && f[1] == "--server"
	}
	return false
}
