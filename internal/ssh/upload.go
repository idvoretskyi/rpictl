// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT

package ssh

import (
	"context"
	"fmt"
	"os"

	goscp "github.com/bramvdbogaerde/go-scp"
	"golang.org/x/crypto/ssh"
)

// Upload copies a local file to the remote path using SCP.
func (c *Client) Upload(localPath, remotePath string) error {
	scpClient, err := goscp.NewClientBySSH(c.client)
	if err != nil {
		return fmt.Errorf("scp client: %w", err)
	}
	defer scpClient.Close()

	f, err := os.Open(localPath) // #nosec G304 -- localPath is a CLI/config input under user's control
	if err != nil {
		return fmt.Errorf("open %s: %w", localPath, err)
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", localPath, err)
	}

	if err := scpClient.CopyFile(context.Background(), f, remotePath, fmt.Sprintf("%04o", fi.Mode())); err != nil {
		return fmt.Errorf("scp copy to %s: %w", remotePath, err)
	}

	return nil
}

// UploadBytes writes the given bytes to a remote path using a single SSH command.
func (c *Client) UploadBytes(data []byte, remotePath string, mode os.FileMode) error {
	sess, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer func() { _ = sess.Close() }()

	sess.Stdin = newBytesReader(data)
	cmd := fmt.Sprintf("cat > %s && chmod %04o %s", remotePath, mode, remotePath)
	if err := sess.Run(cmd); err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			return fmt.Errorf("upload to %s: exit %d", remotePath, exitErr.ExitStatus())
		}
		return fmt.Errorf("upload to %s: %w", remotePath, err)
	}
	return nil
}

type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
