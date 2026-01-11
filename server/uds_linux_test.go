// Copyright 2020-2025 Michael Utech
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package server

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestUDSAuth_QueryUIDName(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("current user not available: %v", err)
	}
	uid, _ := strconv.Atoi(currentUser.Uid)

	// Match current user by name
	match, err := peerCredQueryUIDName(UDSPeerCreds{UID: uid}, currentUser.Username)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Errorf("expected match for current user %q", currentUser.Username)
	}

	// No match for different UID (non-existent UID returns empty username)
	match, err = peerCredQueryUIDName(UDSPeerCreds{UID: uid + 99999}, currentUser.Username)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Error("expected no match for different UID")
	}

	// Non-existent UID matches empty string
	match, err = peerCredQueryUIDName(UDSPeerCreds{UID: uid + 99999}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Error("expected non-existent UID to match empty string")
	}

	// Existing UID does not match different username
	match, err = peerCredQueryUIDName(UDSPeerCreds{UID: uid}, "nonexistent_user_12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Error("expected no match for different username")
	}
}

func TestUDSAuth_QueryGIDName(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("current user not available: %v", err)
	}
	gid, _ := strconv.Atoi(currentUser.Gid)

	// Look up the group name for the current user's primary GID
	group, err := user.LookupGroupId(currentUser.Gid)
	if err != nil {
		t.Skipf("current group not available: %v", err)
	}

	// Match current group by name
	match, err := peerCredQueryGIDName(UDSPeerCreds{GID: gid}, group.Name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Errorf("expected match for current group %q", group.Name)
	}

	// No match for different GID (non-existent GID returns empty name)
	match, err = peerCredQueryGIDName(UDSPeerCreds{GID: gid + 99999}, group.Name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Error("expected no match for different GID")
	}

	// Non-existent GID matches empty string
	match, err = peerCredQueryGIDName(UDSPeerCreds{GID: gid + 99999}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Error("expected non-existent GID to match empty string")
	}

	// Existing GID does not match different group name
	match, err = peerCredQueryGIDName(UDSPeerCreds{GID: gid}, "nonexistent_group_12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Error("expected no match for different group name")
	}
}

func TestUDSAuth_GetProcessSupplementalGroups(t *testing.T) {
	pid := os.Getpid()

	groups, err := getProcessSupplementalGroups(pid)
	if err != nil {
		t.Fatalf("failed to get supplemental groups: %v", err)
	}

	// Should have at least zero groups (empty is valid)
	if groups == nil {
		t.Error("expected non-nil groups slice")
	}

	// Test with invalid PID
	_, err = getProcessSupplementalGroups(0)
	if err == nil {
		t.Error("expected error for PID 0")
	}

	_, err = getProcessSupplementalGroups(-1)
	if err == nil {
		t.Error("expected error for negative PID")
	}

	// Test with non-existent PID (very high number)
	_, err = getProcessSupplementalGroups(999999999)
	if err == nil {
		t.Error("expected error for non-existent PID")
	}
}

func TestUDSAuth_QueryPIDGID(t *testing.T) {
	pid := os.Getpid()

	groups, err := getProcessSupplementalGroups(pid)
	if err != nil {
		t.Fatalf("failed to get supplemental groups: %v", err)
	}

	if len(groups) > 0 {
		// Match a supplemental group
		gidStr := strconv.Itoa(groups[0])
		match, err := peerCredQueryPIDGID(UDSPeerCreds{PID: pid}, gidStr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !match {
			t.Errorf("expected match for supplemental group %s", gidStr)
		}
	}

	// No match for non-existent group (very high number)
	match, err := peerCredQueryPIDGID(UDSPeerCreds{PID: pid}, "999999999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Error("expected no match for non-existent supplemental group")
	}

	// Error for invalid GID value
	_, err = peerCredQueryPIDGID(UDSPeerCreds{PID: pid}, "abc")
	if err == nil {
		t.Error("expected error for invalid GID value")
	}

	// Error for invalid PID
	_, err = peerCredQueryPIDGID(UDSPeerCreds{PID: -1}, "1000")
	if err == nil {
		t.Error("expected error for invalid PID")
	}
}

func TestUDSAuth_QueryPIDGIDName(t *testing.T) {
	pid := os.Getpid()

	groups, err := getProcessSupplementalGroups(pid)
	if err != nil {
		t.Fatalf("failed to get supplemental groups: %v", err)
	}

	if len(groups) > 0 {
		// Look up the group name
		group, err := user.LookupGroupId(strconv.Itoa(groups[0]))
		if err != nil {
			t.Skipf("could not lookup group %d: %v", groups[0], err)
		}

		// Match by group name
		match, err := peerCredQueryPIDGIDName(UDSPeerCreds{PID: pid}, group.Name)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !match {
			t.Errorf("expected match for supplemental group %q", group.Name)
		}
	}

	// Error for non-existent group name
	_, err = peerCredQueryPIDGIDName(UDSPeerCreds{PID: pid}, "nonexistent_group_12345")
	if err == nil {
		t.Error("expected error for non-existent group")
	}

	// Error for invalid PID
	_, err = peerCredQueryPIDGIDName(UDSPeerCreds{PID: -1}, "root")
	if err == nil {
		t.Error("expected error for invalid PID")
	}
}

// TestUDSAuth_PeerCredAuth_Integration tests the full UDS peer credential
// authentication flow: server with UDS + peer cred users, client connects,
// auth succeeds based on UID.
func TestUDSAuth_PeerCredAuth_Integration(t *testing.T) {
	// Get current UID for the peer cred pattern
	uid := os.Getuid()
	uidPattern := fmt.Sprintf("uid=%d", uid)

	// Create temp socket path
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "nats.sock")

	// Configure server with UDS and peer credential user
	opts := &Options{
		Host:       "127.0.0.1",
		Port:       -1,
		DontListen: true, // no TCP
		UDSPath:    sockPath,
		NoLog:      true,
		NoSigs:     true,
		Users: []*User{
			{
				Username:               uidPattern,
				AllowedConnectionTypes: map[string]struct{}{ConnectionTypeUnix: {}},
				Permissions: &Permissions{
					Publish:   &SubjectPermission{Allow: []string{"test.>"}, Deny: []string{"test.deny.>"}},
					Subscribe: &SubjectPermission{Allow: []string{"test.>"}},
				},
			},
		},
	}

	s, err := NewServer(opts)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	s.Start()
	defer s.Shutdown()

	// Wait for UDS listener to be ready
	if err := s.readyForConnections(5 * time.Second); err != nil {
		t.Fatalf("server not ready: %v", err)
	}

	// Connect via UDS
	conn, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to UDS: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read INFO
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read INFO: %v", err)
	}
	if !strings.HasPrefix(line, "INFO ") {
		t.Fatalf("expected INFO, got: %q", line)
	}

	// Send CONNECT (no user/pass - peer cred auth)
	_, err = conn.Write([]byte("CONNECT {\"verbose\":false,\"pedantic\":false}\r\n"))
	if err != nil {
		t.Fatalf("failed to send CONNECT: %v", err)
	}

	// Send PING
	_, err = conn.Write([]byte("PING\r\n"))
	if err != nil {
		t.Fatalf("failed to send PING: %v", err)
	}

	// Read response - should be PONG (auth success) or -ERR (auth failure)
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	if strings.HasPrefix(line, "-ERR") {
		t.Fatalf("authentication failed: %s", strings.TrimSpace(line))
	}
	if !strings.HasPrefix(line, "PONG") {
		t.Fatalf("expected PONG, got: %q", line)
	}

	// Test publish permission - should succeed for allowed subject
	_, err = conn.Write([]byte("PUB test.foo 5\r\nhello\r\n"))
	if err != nil {
		t.Fatalf("failed to send PUB: %v", err)
	}

	// Send another PING to flush and check for errors
	_, err = conn.Write([]byte("PING\r\n"))
	if err != nil {
		t.Fatalf("failed to send PING: %v", err)
	}

	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if strings.HasPrefix(line, "-ERR") {
		t.Fatalf("publish to allowed subject failed: %s", strings.TrimSpace(line))
	}
	if !strings.HasPrefix(line, "PONG") {
		t.Fatalf("expected PONG after publish, got: %q", line)
	}

	// Test publish to denied subject - should get permission error
	_, err = conn.Write([]byte("PUB denied.foo 5\r\nhello\r\n"))
	if err != nil {
		t.Fatalf("failed to send PUB: %v", err)
	}

	// Read error for denied publish
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if !strings.Contains(line, "Permissions Violation") {
		t.Fatalf("expected permission violation for denied subject, got: %q", line)
	}

	// Test publish to explicitly denied subject (deny overrides allow)
	_, err = conn.Write([]byte("PUB test.deny.foo 5\r\nhello\r\n"))
	if err != nil {
		t.Fatalf("failed to send PUB: %v", err)
	}

	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if !strings.Contains(line, "Permissions Violation") {
		t.Fatalf("expected permission violation for explicitly denied subject, got: %q", line)
	}
}
