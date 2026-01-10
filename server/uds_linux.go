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
	"strconv"
	"strings"
	"syscall"
)

func (c *client) getUDSPeerCreds() (UDSPeerCreds, error) {
	conn, ok := c.nc.(*net.UnixConn)
	if !ok {
		return UDSPeerCreds{UID: -1, GID: -1, PID: -1}, fmt.Errorf("connection is not a UNIX domain socket")
	}

	return getUDSPeerCreds(conn)
}

func getUDSPeerCreds(conn *net.UnixConn) (UDSPeerCreds, error) {
	result := UDSPeerCreds{UID: -1, GID: -1, PID: -1}

	raw, err := conn.SyscallConn()
	if err != nil {
		return result, err
	}

	// Avoid setting the connection to blocking mode via conn.File, use raw socket instead:
	err = raw.Control(func(fd uintptr) {
		ucred, callerr := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if callerr != nil {
			err = callerr
			return
		}
		result = UDSPeerCreds{
			UID: int(ucred.Uid),
			GID: int(ucred.Gid),
			PID: int(ucred.Pid),
		}
	})

	return result, err
}

func (s *Server) UDSAcceptLoop(clr chan struct{}) {
	// If we were to exit before the listener is setup properly,
	// make sure we close the channel.
	defer func() {
		if clr != nil {
			close(clr)
		}
	}()

	if s.isShuttingDown() {
		return
	}

	// Snapshot server options.
	opts := s.getOpts()

	if opts.UDSPath == _EMPTY_ {
		return
	}

	// Setup state that can enable shutdown
	s.mu.Lock()
	path := opts.UDSPath
	if s.udsListener == nil {
		s.udsListener, s.udsListenerErr = natsListen("unix", path)
		if s.udsListenerErr != nil {
			conn, dialErr := net.Dial("unix", path)
			if dialErr == nil {
				defer conn.Close()

				// Socket is active - someone else is using it
				unixConn := conn.(*net.UnixConn)
				creds, credErr := getUDSPeerCreds(unixConn)
				s.mu.Unlock()
				if credErr != nil {
					s.Fatalf("UNIX domain socket %s in use, PID not available: %v", path, credErr)
					return
				}
				s.Fatalf("UNIX domain socket %s already in use by PID %d (UID %d)", path, creds.PID, creds.UID)
				return
			}
			// Dial failed - socket is stale, remove and retry
			s.Noticef("UNIX domain socket %s appears stale, removing...", path)
			os.Remove(path)
			s.udsListener, s.udsListenerErr = natsListen("unix", path)
		}
	}
	if s.udsListenerErr != nil {
		s.mu.Unlock()
		s.Fatalf("Error listening on UNIX domain socket: %s, %q", path, s.udsListenerErr)
		return
	}
	s.Noticef("Listening for client connections on UNIX domain socket %s", path)

	// Alert if PROXY protocol is enabled
	if opts.ProxyProtocol {
		s.Noticef("PROXY protocol enabled for client connections")
	}

	// Alert of TLS enabled.
	if opts.TLSConfig != nil {
		s.Noticef("TLS required for client connections")
		if opts.TLSHandshakeFirst && opts.TLSHandshakeFirstFallback == 0 {
			s.Warnf("Clients that are not using \"TLS Handshake First\" option will fail to connect")
		}
	}

	s.info.UDSPath = path

	// Initialize peercred query handlers (s.mu already held)
	s.initializePeerCredQueries()

	// We do not advertize UDS sockets since they are not remotely available and clients connected
	// via UDS already know the path. Advertizing local UDS to remote is useless and might break clients.

	go s.acceptConnections(s.udsListener, "Client",
		func(conn net.Conn) {
			s.createClient(conn)
			// TODO: perform UDS specific initialization, either here or in createClient()
		},
		func(_ error) bool {
			if s.isLameDuckMode() {
				// Signal that we are not accepting new clients
				s.ldmCh <- true
				// Now wait for the Shutdown...
				<-s.quitCh
				return true
			}
			return false
		})
	s.mu.Unlock()

	// Let the caller know that we are ready
	if clr != nil {
		close(clr)
	}
	clr = nil
}

// peerCredQueryUIDName matches UID against a username lookup.
func peerCredQueryUIDName(c UDSPeerCreds, v string) (bool, error) {
	u, err := user.Lookup(v)
	if err != nil {
		return false, fmt.Errorf("user lookup %q: %w", v, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return false, fmt.Errorf("invalid uid from lookup %q: %w", u.Uid, err)
	}
	return c.UID == uid, nil
}

// peerCredQueryGIDName matches GID against a group name lookup.
func peerCredQueryGIDName(c UDSPeerCreds, v string) (bool, error) {
	g, err := user.LookupGroup(v)
	if err != nil {
		return false, fmt.Errorf("group lookup %q: %w", v, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return false, fmt.Errorf("invalid gid from lookup %q: %w", g.Gid, err)
	}
	return c.GID == gid, nil
}

// getProcessSupplementalGroups reads supplemental groups from /proc/<pid>/status.
func getProcessSupplementalGroups(pid int) ([]int, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid pid %d", pid)
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, fmt.Errorf("open /proc/%d/status: %w", pid, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Groups:") {
			fields := strings.Fields(line[7:])
			groups := make([]int, 0, len(fields))
			for _, field := range fields {
				gid, err := strconv.Atoi(field)
				if err != nil {
					return nil, fmt.Errorf("invalid gid %q in /proc/%d/status: %w", field, pid, err)
				}
				groups = append(groups, gid)
			}
			return groups, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read /proc/%d/status: %w", pid, err)
	}
	return nil, fmt.Errorf("/proc/%d/status: Groups line not found", pid)
}

// peerCredQueryPIDGID matches GID against process supplemental groups.
func peerCredQueryPIDGID(c UDSPeerCreds, v string) (bool, error) {
	gid, err := strconv.Atoi(v)
	if err != nil {
		return false, fmt.Errorf("invalid gid value %q: %w", v, err)
	}
	groups, err := getProcessSupplementalGroups(c.PID)
	if err != nil {
		return false, err
	}
	for _, g := range groups {
		if g == gid {
			return true, nil
		}
	}
	return false, nil
}

// peerCredQueryPIDGIDName matches group name against process supplemental groups.
func peerCredQueryPIDGIDName(c UDSPeerCreds, v string) (bool, error) {
	g, err := user.LookupGroup(v)
	if err != nil {
		return false, fmt.Errorf("group lookup %q: %w", v, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return false, fmt.Errorf("invalid gid from lookup %q: %w", g.Gid, err)
	}
	groups, err := getProcessSupplementalGroups(c.PID)
	if err != nil {
		return false, err
	}
	for _, grp := range groups {
		if grp == gid {
			return true, nil
		}
	}
	return false, nil
}
