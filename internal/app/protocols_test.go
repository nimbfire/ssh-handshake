package app

import "testing"

func TestIsFileTransfer(t *testing.T) {
	yes := []string{"internal-sftp", "/usr/lib/openssh/sftp-server", "scp -t /tmp", "rsync --server -vlogDtpre.iLsfxC . x", "git-upload-pack 'repo.git'", "git-receive-pack 'r'"}
	no := []string{"", "ls -la", "rsync", "vim scp.txt", "bash"}
	for _, c := range yes {
		if !IsFileTransfer(c) {
			t.Errorf("%q should be a file transfer", c)
		}
	}
	for _, c := range no {
		if IsFileTransfer(c) {
			t.Errorf("%q should not be a file transfer", c)
		}
	}
}
