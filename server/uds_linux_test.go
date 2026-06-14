// Copyright 2026 Michael Utech
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
	"bytes"
	"flag"
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

func TestUDS_Auth_QueryUIDName(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("current user not available: %v", err)
	}
	uid, _ := strconv.Atoi(currentUser.Uid)

	// Match current user by name
	match, err := peerCredQueryUIDName("uid.name", UDSPeerCreds{UID: uid}, currentUser.Username, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Errorf("expected match for current user %q", currentUser.Username)
	}

	// No match for different UID (non-existent UID returns empty username)
	match, err = peerCredQueryUIDName("uid.name", UDSPeerCreds{UID: uid + 99999}, currentUser.Username, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Error("expected no match for different UID")
	}

	// Non-existent UID matches empty string
	match, err = peerCredQueryUIDName("uid.name", UDSPeerCreds{UID: uid + 99999}, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Error("expected non-existent UID to match empty string")
	}

	// Existing UID does not match different username
	match, err = peerCredQueryUIDName("uid.name", UDSPeerCreds{UID: uid}, "nonexistent_user_12345", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Error("expected no match for different username")
	}
}

func TestUDS_Auth_QueryGIDName(t *testing.T) {
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
	match, err := peerCredQueryGIDName("gid.name", UDSPeerCreds{GID: gid}, group.Name, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Errorf("expected match for current group %q", group.Name)
	}

	// No match for different GID (non-existent GID returns empty name)
	match, err = peerCredQueryGIDName("gid.name", UDSPeerCreds{GID: gid + 99999}, group.Name, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Error("expected no match for different GID")
	}

	// Non-existent GID matches empty string
	match, err = peerCredQueryGIDName("gid.name", UDSPeerCreds{GID: gid + 99999}, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Error("expected non-existent GID to match empty string")
	}

	// Existing GID does not match different group name
	match, err = peerCredQueryGIDName("gid.name", UDSPeerCreds{GID: gid}, "nonexistent_group_12345", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Error("expected no match for different group name")
	}
}

func TestUDS_Auth_GetProcessSupplementalGroups(t *testing.T) {
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

func TestUDS_Auth_GroupsMatchesPrimaryGid(t *testing.T) {
	// A synthetic primary gid that won't be in our real supplemental groups,
	// proving getProcessGroups adds the primary gid from peer creds, not just
	// the /proc "Groups:" line (which omits it).
	const primary = 999998
	creds := UDSPeerCreds{UID: os.Getuid(), GID: primary, PID: os.Getpid()}

	ok, err := peerCredQueryGroups("groups", creds, int64(primary), nil)
	if err != nil {
		t.Fatalf("peerCredQueryGroups: %v", err)
	}
	if !ok {
		t.Fatal("groups query should match the primary gid")
	}

	// The primary must not be duplicated if it is also a supplemental group.
	groups, err := getProcessGroups(creds)
	if err != nil {
		t.Fatalf("getProcessGroups: %v", err)
	}
	seen := map[int]int{}
	for _, g := range groups {
		if seen[g]++; seen[g] > 1 {
			t.Fatalf("getProcessGroups returned gid %d more than once: %v", g, groups)
		}
	}
}

func TestUDS_Auth_QueryPIDGID(t *testing.T) {
	pid := os.Getpid()

	groups, err := getProcessSupplementalGroups(pid)
	if err != nil {
		t.Fatalf("failed to get supplemental groups: %v", err)
	}

	if len(groups) > 0 {
		// Match a supplemental group
		match, err := peerCredQueryGroups("groups", UDSPeerCreds{PID: pid}, int64(groups[0]), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !match {
			t.Errorf("expected match for supplemental group %d", groups[0])
		}
	}

	// No match for non-existent group (very high number)
	match, err := peerCredQueryGroups("groups", UDSPeerCreds{PID: pid}, int64(999999999), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Error("expected no match for non-existent supplemental group")
	}

	// Error for wrong type
	_, err = peerCredQueryGroups("groups", UDSPeerCreds{PID: pid}, "not-an-int", nil)
	if err == nil {
		t.Error("expected error for wrong type")
	}

	// Error for invalid PID
	_, err = peerCredQueryGroups("groups", UDSPeerCreds{PID: -1}, int64(1000), nil)
	if err == nil {
		t.Error("expected error for invalid PID")
	}
}

func TestUDS_Auth_QueryPIDGIDName(t *testing.T) {
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
		match, err := peerCredQueryGroupsName("groups.name", UDSPeerCreds{PID: pid}, group.Name, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !match {
			t.Errorf("expected match for supplemental group %q", group.Name)
		}
	}

	// Error for non-existent group name
	_, err = peerCredQueryGroupsName("groups.name", UDSPeerCreds{PID: pid}, "nonexistent_group_12345", nil)
	if err == nil {
		t.Error("expected error for non-existent group")
	}

	// Error for invalid PID
	_, err = peerCredQueryGroupsName("groups.name", UDSPeerCreds{PID: -1}, "root", nil)
	if err == nil {
		t.Error("expected error for invalid PID")
	}
}

// TestUDSAuth_PeerCredAuth_Integration tests the full UDS peer credential
// authentication flow: server with UDS + peer cred users, client connects,
// auth succeeds based on UID.
func TestUDS_Auth_PeerCredAuth_Integration(t *testing.T) {
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
		UDS:        UDSOptions{Path: sockPath},
		NoLog:      true,
		NoSigs:     true,
		UDSRules: []*UDSRule{
			{
				Username: uidPattern,
				Match: &UDSRulePattern{
					{UDSRuleExpression{QueryName: "uid"}: int64(uid)},
				},
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

// udsSystemAccountConfig builds a server config that maps the current uid to a
// user in the system account over UDS.
func udsSystemAccountConfig(sockPath string, uid int) string {
	return fmt.Sprintf(`
		port: -1
		uds { path: %q }
		system_account: "$SYS"
		accounts {
			$SYS {
				users = [
					{
						user: "uds-admin"
						uds { match { uid: %d } }
						permissions {
							publish { allow: [ ">" ] }
							subscribe { allow: [ ">" ] }
						}
					}
				]
			}
		}
	`, sockPath, uid)
}

// TestUDS_Account_PlacesPeerInSystemAccount maps the current uid into $SYS over
// UDS and verifies the peer lands there. With only $G+$SYS and no authorization
// block, the server auto-creates a no_auth_user→$G (sysAccOnlyNoAuthUser); this
// also guards that it does not shadow UDS peer-cred auth.
func TestUDS_Account_PlacesPeerInSystemAccount(t *testing.T) {
	uid := os.Getuid()
	sockPath := udsTempSock(t)
	conf := udsSystemAccountConfig(sockPath, uid)

	s, _ := RunServerWithConfig(createConfFile(t, []byte(conf)))
	defer s.Shutdown()

	if err := s.readyForConnections(5 * time.Second); err != nil {
		t.Fatalf("server not ready: %v", err)
	}

	conn, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		t.Fatalf("dial uds: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil { // INFO
		t.Fatalf("read INFO: %v", err)
	}
	if _, err := conn.Write([]byte("CONNECT {\"verbose\":false}\r\nPING\r\n")); err != nil {
		t.Fatalf("write CONNECT/PING: %v", err)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read PONG: %v", err)
	}
	if strings.HasPrefix(line, "-ERR") {
		t.Fatalf("authentication failed: %s", strings.TrimSpace(line))
	}
	if !strings.HasPrefix(line, "PONG") {
		t.Fatalf("expected PONG, got: %q", line)
	}

	// The authenticated UDS peer must have landed in $SYS, not $G.
	if got := connClientAccount(t, s); got != DEFAULT_SYSTEM_ACCOUNT {
		t.Fatalf("peer account = %q, want %q", got, DEFAULT_SYSTEM_ACCOUNT)
	}
}

// TestUDS_Account_ReloadKeepsConnection guards the regression where config
// reload disconnected live UDS peer-cred connections: the reload authorization
// machinery is user-based and classified a UDS peer (whose stored username is
// the synthesized identity, not a configured user) as "account moved", closing
// it. UDS peer-cred connections must survive reload.
func TestUDS_Account_ReloadKeepsConnection(t *testing.T) {
	uid := os.Getuid()
	sockPath := udsTempSock(t)
	s, _ := RunServerWithConfig(createConfFile(t, []byte(udsSystemAccountConfig(sockPath, uid))))
	defer s.Shutdown()
	if err := s.readyForConnections(5 * time.Second); err != nil {
		t.Fatalf("server not ready: %v", err)
	}

	conn, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		t.Fatalf("dial uds: %v", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil { // INFO
		t.Fatalf("read INFO: %v", err)
	}
	if _, err := conn.Write([]byte("CONNECT {\"verbose\":false}\r\nPING\r\n")); err != nil {
		t.Fatalf("write CONNECT/PING: %v", err)
	}
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "PONG") {
		t.Fatalf("pre-reload PONG: line=%q err=%v", line, err)
	}
	if got := connClientAccount(t, s); got != DEFAULT_SYSTEM_ACCOUNT {
		t.Fatalf("pre-reload account = %q, want %q", got, DEFAULT_SYSTEM_ACCOUNT)
	}

	if err := s.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	// The connection must still be alive and usable after reload.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		t.Fatalf("post-reload write (connection dropped?): %v", err)
	}
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "PONG") {
		t.Fatalf("post-reload PONG (connection dropped?): line=%q err=%v", line, err)
	}
	if got := connClientAccount(t, s); got != DEFAULT_SYSTEM_ACCOUNT {
		t.Fatalf("post-reload account = %q, want %q", got, DEFAULT_SYSTEM_ACCOUNT)
	}
}

func TestUDS_Account_ReloadSupported(t *testing.T) {
	uid := os.Getuid()
	sockPath := udsTempSock(t)
	conf := udsSystemAccountConfig(sockPath, uid)

	s, _ := RunServerWithConfig(createConfFile(t, []byte(conf)))
	defer s.Shutdown()

	// Regression guard: a UDS rule carrying a live *Account must not make
	// diffOptions reject the reload (see uds-account-reload-landmine).
	if err := s.Reload(); err != nil {
		t.Fatalf("reload with UDS-in-account config failed: %v", err)
	}
	if err := s.Reload(); err != nil {
		t.Fatalf("second reload failed: %v", err)
	}
}

// udsTempSock returns a socket path short enough to stay under the unix
// sun_path limit (~107 bytes); t.TempDir() embeds the (long) test name and can
// overflow it. The directory is removed when the test ends.
func udsTempSock(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "uds")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// connClientAccount returns the account name of the single external CLIENT
// connection registered on the server, waiting briefly for it to appear.
func connClientAccount(t *testing.T, s *Server) string {
	t.Helper()
	var got string
	checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
		s.mu.RLock()
		defer s.mu.RUnlock()
		for _, c := range s.clients {
			c.mu.Lock()
			kind := c.kind
			var accName string
			if c.acc != nil {
				accName = c.acc.Name
			}
			c.mu.Unlock()
			if kind == CLIENT {
				got = accName
				return nil
			}
		}
		return fmt.Errorf("no CLIENT connection registered yet")
	})
	return got
}

// TestUDS_ExplicitCredsReachDedicatedAccount proves that a client may bypass
// peer-cred auth and authenticate normally (here: user/pass) over the UNIX
// socket, landing in a dedicated account. This is the escape hatch for a
// process that needs an account other than the one its peer creds map to.
func TestUDS_ExplicitCredsReachDedicatedAccount(t *testing.T) {
	sockPath := udsTempSock(t)
	conf := fmt.Sprintf(`
		port: -1
		uds { path: %q }
		accounts {
			APP {
				users = [ { user: "svc", password: "pw" } ]
			}
		}
	`, sockPath)

	s, _ := RunServerWithConfig(createConfFile(t, []byte(conf)))
	defer s.Shutdown()

	if err := s.readyForConnections(5 * time.Second); err != nil {
		t.Fatalf("server not ready: %v", err)
	}

	conn, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		t.Fatalf("dial uds: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil { // INFO
		t.Fatalf("read INFO: %v", err)
	}
	// Explicit user/pass on CONNECT must skip peer-cred auth entirely.
	if _, err := conn.Write([]byte("CONNECT {\"verbose\":false,\"user\":\"svc\",\"pass\":\"pw\"}\r\nPING\r\n")); err != nil {
		t.Fatalf("write CONNECT/PING: %v", err)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read PONG: %v", err)
	}
	if strings.HasPrefix(line, "-ERR") {
		t.Fatalf("explicit-cred authentication failed: %s", strings.TrimSpace(line))
	}
	if !strings.HasPrefix(line, "PONG") {
		t.Fatalf("expected PONG, got: %q", line)
	}

	if got := connClientAccount(t, s); got != "APP" {
		t.Fatalf("peer account = %q, want APP", got)
	}
}

// TestUDS_NoAuthUserNotAppliedToPeer verifies an explicit no_auth_user does not
// shadow UDS peer-cred auth: a no-credential UDS peer must authenticate via its
// UDS rule (account APP), not be assigned the no_auth_user identity (account
// ANON).
func TestUDS_NoAuthUserNotAppliedToPeer(t *testing.T) {
	uid := os.Getuid()
	sockPath := udsTempSock(t)
	conf := fmt.Sprintf(`
		port: -1
		uds { path: %q }
		accounts {
			ANON { users = [ { user: "anon", password: "x" } ] }
			APP  { users = [ { user: "uds-app"
			                   uds { match { uid: %d } }
			                   permissions { publish { allow: [ ">" ] }, subscribe { allow: [ ">" ] } } } ] }
		}
		no_auth_user: "anon"
	`, sockPath, uid)

	s, _ := RunServerWithConfig(createConfFile(t, []byte(conf)))
	defer s.Shutdown()
	if err := s.readyForConnections(5 * time.Second); err != nil {
		t.Fatalf("server not ready: %v", err)
	}

	conn, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		t.Fatalf("dial uds: %v", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil { // INFO
		t.Fatalf("read INFO: %v", err)
	}
	if _, err := conn.Write([]byte("CONNECT {\"verbose\":false}\r\nPING\r\n")); err != nil {
		t.Fatalf("write CONNECT/PING: %v", err)
	}
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "PONG") {
		t.Fatalf("PONG: line=%q err=%v", line, err)
	}
	if got := connClientAccount(t, s); got != "APP" {
		t.Fatalf("peer account = %q, want APP (no_auth_user must not apply to UDS)", got)
	}
}

func TestUDS_NewSocketSpec(t *testing.T) {
	// Get root group for name lookup test (always exists)
	rootGroup, err := user.LookupGroupId("0")
	if err != nil {
		t.Fatalf("cannot lookup gid 0: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		group   string
		mode    string
		wantGid int
		wantErr bool
		errMsg  string // substring to check in error
	}{
		// Valid cases - defaults
		{"valid path only", "/var/run/nats.sock", "", "", -1, false, ""},
		{"valid with mode", "/var/run/nats.sock", "", "0660", -1, false, ""},

		// Valid cases - group by numeric GID (Atoi path)
		{"numeric gid", "/var/run/nats.sock", "1000", "", 1000, false, ""},
		{"numeric gid 0", "/var/run/nats.sock", "0", "", 0, false, ""},

		// Valid cases - group by name (lookup path)
		{"group name lookup", "/var/run/nats.sock", rootGroup.Name, "", 0, false, ""},

		// Path attack vectors
		{"empty path", "", "", "", -1, true, "expect canonical absolute path"},
		{"relative path", "var/run/nats.sock", "", "", -1, true, "expect canonical absolute path"},
		{"dot relative", "./nats.sock", "", "", -1, true, "expect canonical absolute path"},
		{"parent traversal", "/var/run/../nats.sock", "", "", -1, true, "expect canonical absolute path"},
		{"double slash", "/var//run/nats.sock", "", "", -1, true, "expect canonical absolute path"},
		{"trailing slash", "/var/run/nats.sock/", "", "", -1, true, "expect canonical absolute path"},
		{"dot in path", "/var/run/./nats.sock", "", "", -1, true, "expect canonical absolute path"},
		{"double dot end", "/var/run/nats.sock/..", "", "", -1, true, "expect canonical absolute path"},
		{"just slash", "/", "", "", -1, false, ""}, // technically valid, will fail at listen

		// Mode validation (parseFileMode tests cover details, verify integration)
		{"invalid mode format", "/var/run/nats.sock", "", "666", -1, true, "invalid file mode"},
		{"invalid mode octal", "/var/run/nats.sock", "", "0888", -1, true, "invalid file mode"},

		// Group validation - errors
		{"nonexistent group name", "/var/run/nats.sock", "nonexistent_group_xyz_12345", "", -1, true, "invalid group"},
		{"negative gid", "/var/run/nats.sock", "-1", "", -1, true, "negative ID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := newUdsSocketSpec(tt.path, tt.group, tt.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("newUdsSocketSpec(%q, %q, %q) error = %v, wantErr %v",
					tt.path, tt.group, tt.mode, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
			}
			if !tt.wantErr {
				if spec.path != tt.path {
					t.Errorf("spec.path = %q, want %q", spec.path, tt.path)
				}
				if spec.gid != tt.wantGid {
					t.Errorf("spec.gid = %d, want %d", spec.gid, tt.wantGid)
				}
			}
		})
	}
}

func TestUDS_ParseFileMode(t *testing.T) {
	tests := []struct {
		input   string
		want    os.FileMode
		wantErr bool
	}{
		// Valid modes
		{"0000", 0o000, false},
		{"0600", 0o600, false},
		{"0644", 0o644, false},
		{"0660", 0o660, false},
		{"0700", 0o700, false},
		{"0755", 0o755, false},
		{"0777", 0o777, false},

		// Wrong length
		{"", 0, true},
		{"0", 0, true},
		{"00", 0, true},
		{"000", 0, true},
		{"00000", 0, true},
		{"07777", 0, true},

		// Wrong first char
		{"1777", 0, true},
		{"a777", 0, true},
		{" 777", 0, true},

		// Invalid octal digit in position 1
		{"0800", 0, true},
		{"0900", 0, true},
		{"0a00", 0, true},

		// Invalid octal digit in position 2
		{"0080", 0, true},
		{"0090", 0, true},
		{"00a0", 0, true},

		// Invalid octal digit in position 3
		{"0008", 0, true},
		{"0009", 0, true},
		{"000a", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseFileMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFileMode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseFileMode(%q) = %o, want %o", tt.input, got, tt.want)
			}
		})
	}
}

func TestUDS_CLI_Option(t *testing.T) {
	defer func() { FlagSnapshot = nil }()

	// Helper to parse CLI args and return options
	mustNotFail := func(args []string) *Options {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		opts, err := ConfigureOptions(fs, args, PrintServerAndExit, fs.Usage, PrintTLSHelpAndDie)
		if err != nil {
			t.Fatalf("Error on configure: %v", err)
		}
		return opts
	}

	// Helper to expect failure
	expectToFail := func(args []string) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(&bytes.Buffer{}) // silence errors
		opts, err := ConfigureOptions(fs, args, PrintServerAndExit, fs.Usage, PrintTLSHelpAndDie)
		if opts != nil || err == nil {
			t.Fatalf("Expected error for args %v, got opts=%v err=%v", args, opts, err)
		}
	}

	// Basic path only
	opts := mustNotFail([]string{"--uds", "/tmp/nats.sock"})
	if opts.UDS.Path != "/tmp/nats.sock" {
		t.Fatalf("Expected path /tmp/nats.sock, got %q", opts.UDS.Path)
	}

	// Path with group
	opts = mustNotFail([]string{"--uds", "/tmp/nats.sock;group=nats"})
	if opts.UDS.Path != "/tmp/nats.sock" || opts.UDS.Group != "nats" {
		t.Fatalf("Expected path=/tmp/nats.sock group=nats, got path=%q group=%q", opts.UDS.Path, opts.UDS.Group)
	}

	// Path with mode
	opts = mustNotFail([]string{"--uds", "/tmp/nats.sock;mode=0660"})
	if opts.UDS.Path != "/tmp/nats.sock" || opts.UDS.Mode != "0660" {
		t.Fatalf("Expected path=/tmp/nats.sock mode=0660, got path=%q mode=%q", opts.UDS.Path, opts.UDS.Mode)
	}

	// Path with group and mode
	opts = mustNotFail([]string{"--uds", "/tmp/nats.sock;group=nats;mode=0660"})
	if opts.UDS.Path != "/tmp/nats.sock" || opts.UDS.Group != "nats" || opts.UDS.Mode != "0660" {
		t.Fatalf("Expected path=/tmp/nats.sock group=nats mode=0660, got path=%q group=%q mode=%q",
			opts.UDS.Path, opts.UDS.Group, opts.UDS.Mode)
	}

	// Empty value should fail
	expectToFail([]string{"--uds", ""})

	// Missing path should fail
	expectToFail([]string{"--uds", ";group=nats"})
}

func TestUDS_Config_Block(t *testing.T) {
	// Create temp config file with uds block
	conf := `
		uds {
			path: "/tmp/nats.sock"
			group: "nats"
			mode: "0660"
		}
	`
	confFile := filepath.Join(t.TempDir(), "test.conf")
	if err := os.WriteFile(confFile, []byte(conf), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	opts, err := ProcessConfigFile(confFile)
	if err != nil {
		t.Fatalf("Error processing config: %v", err)
	}

	if opts.UDS.Path != "/tmp/nats.sock" {
		t.Errorf("Expected path /tmp/nats.sock, got %q", opts.UDS.Path)
	}
	if opts.UDS.Group != "nats" {
		t.Errorf("Expected group nats, got %q", opts.UDS.Group)
	}
	if opts.UDS.Mode != "0660" {
		t.Errorf("Expected mode 0660, got %q", opts.UDS.Mode)
	}
}

func TestUDS_Config_PathOnly(t *testing.T) {
	// Test path-only config (no group/mode)
	conf := `uds { path: "/tmp/nats.sock" }`
	confFile := filepath.Join(t.TempDir(), "test.conf")
	if err := os.WriteFile(confFile, []byte(conf), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	opts, err := ProcessConfigFile(confFile)
	if err != nil {
		t.Fatalf("Error processing config: %v", err)
	}

	if opts.UDS.Path != "/tmp/nats.sock" {
		t.Errorf("Expected path /tmp/nats.sock, got %q", opts.UDS.Path)
	}
}
