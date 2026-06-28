// Extension tests (snats): file:// resolution for nkey config values.
//
// These cover the resolveNkeyValue helper and every config entry point that
// accepts an nkey — leaf remote seed, leaf authorization nkey, account nkey, and
// authorization (client) users — verifying that a "file://" value is read from
// disk and that the existing nkey validation still runs on the resolved value,
// for both file-backed and inline nkeys.
package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nkeys"
)

func mkUserKey(t *testing.T) (seed []byte, pub string) {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if seed, err = kp.Seed(); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if pub, err = kp.PublicKey(); err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	return seed, pub
}

func mkAccountPub(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	return pub
}

// secretFile writes content to a fresh temp file and returns its file:// URL.
func secretFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nkey")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	return "file://" + p
}

func findAccount(opts *Options, name string) *Account {
	for _, a := range opts.Accounts {
		if a.Name == name {
			return a
		}
	}
	return nil
}

func TestResolveNkeyValue(t *testing.T) {
	_, pub := mkUserKey(t)

	// Inline values (no scheme) pass through untouched.
	for _, in := range []string{pub, "", "SUAGARBAGE", "not a url at all"} {
		got, err := resolveNkeyValue(in)
		if err != nil {
			t.Fatalf("resolveNkeyValue(%q) unexpected err: %v", in, err)
		}
		if got != in {
			t.Fatalf("resolveNkeyValue(%q) = %q, want unchanged", in, got)
		}
	}

	// A non-file scheme is left alone.
	if got, err := resolveNkeyValue("nats://example"); err != nil || got != "nats://example" {
		t.Fatalf("non-file scheme changed: got %q err %v", got, err)
	}

	// file:// is read and trimmed (trailing newline stripped).
	url := secretFile(t, pub+"\n")
	got, err := resolveNkeyValue(url)
	if err != nil {
		t.Fatalf("resolveNkeyValue(file) err: %v", err)
	}
	if got != pub {
		t.Fatalf("resolveNkeyValue(file) = %q, want %q", got, pub)
	}

	// Missing file: deferred — the reference is returned unchanged, no error
	// (build-time `snatsd -t` before the secret is deployed). isFileRef flags it.
	ref := "file:///no/such/snats/nkey/file"
	if got, err := resolveNkeyValue(ref); err != nil || got != ref {
		t.Fatalf("missing file should defer to %q, got %q err %v", ref, got, err)
	}
	if !isFileRef(ref) {
		t.Fatalf("isFileRef(%q) = false, want true", ref)
	}
	if isFileRef(pub) {
		t.Fatalf("isFileRef(%q) = true, want false (resolved key)", pub)
	}
}

func TestNkeyFileLeafRemoteSeed(t *testing.T) {
	seed, _ := mkUserKey(t)

	// file:// with a trailing newline, resolved + validated as a user seed.
	conf := func(nkey string) string {
		return `
		leafnodes {
			remotes = [
				{ url: "nats-leaf://127.0.0.1:7422", account: "A", nkey: "` + nkey + `" }
			]
		}`
	}

	t.Run("file", func(t *testing.T) {
		cf := createConfFile(t, []byte(conf(secretFile(t, string(seed)+"\n"))))
		opts, err := ProcessConfigFile(cf)
		if err != nil {
			t.Fatalf("ProcessConfigFile: %v", err)
		}
		if got := opts.LeafNode.Remotes[0].Nkey; got != string(seed) {
			t.Fatalf("remote nkey = %q, want resolved seed %q", got, seed)
		}
	})

	t.Run("inline", func(t *testing.T) {
		cf := createConfFile(t, []byte(conf(string(seed))))
		opts, err := ProcessConfigFile(cf)
		if err != nil {
			t.Fatalf("ProcessConfigFile: %v", err)
		}
		if got := opts.LeafNode.Remotes[0].Nkey; got != string(seed) {
			t.Fatalf("remote nkey = %q, want %q", got, seed)
		}
	})

	t.Run("file with garbage fails seed validation", func(t *testing.T) {
		cf := createConfFile(t, []byte(conf(secretFile(t, "not-a-seed"))))
		if _, err := ProcessConfigFile(cf); err == nil {
			t.Fatalf("expected seed validation error")
		}
	})

	t.Run("file with wrong-prefix key fails (account, not user)", func(t *testing.T) {
		cf := createConfFile(t, []byte(conf(secretFile(t, mkAccountPub(t)))))
		if _, err := ProcessConfigFile(cf); err == nil {
			t.Fatalf("expected error: account key is not a user seed")
		}
	})

	t.Run("missing file defers (parses; seed validation skipped)", func(t *testing.T) {
		ref := "file:///no/such/snats/seed"
		cf := createConfFile(t, []byte(conf(ref)))
		opts, err := ProcessConfigFile(cf)
		if err != nil {
			t.Fatalf("deferred parse should succeed (build-time -t), got: %v", err)
		}
		if got := opts.LeafNode.Remotes[0].Nkey; got != ref {
			t.Fatalf("remote nkey = %q, want unresolved ref %q", got, ref)
		}
	})
}

func TestNkeyFileLeafAuthorization(t *testing.T) {
	_, pub := mkUserKey(t)
	conf := func(nkey string) string {
		return `leafnodes { authorization { nkey: "` + nkey + `" } }`
	}

	t.Run("file", func(t *testing.T) {
		cf := createConfFile(t, []byte(conf(secretFile(t, pub+"\n"))))
		opts, err := ProcessConfigFile(cf)
		if err != nil {
			t.Fatalf("ProcessConfigFile: %v", err)
		}
		if opts.LeafNode.Nkey != pub {
			t.Fatalf("leaf authz nkey = %q, want %q", opts.LeafNode.Nkey, pub)
		}
	})

	t.Run("inline", func(t *testing.T) {
		cf := createConfFile(t, []byte(conf(pub)))
		opts, err := ProcessConfigFile(cf)
		if err != nil {
			t.Fatalf("ProcessConfigFile: %v", err)
		}
		if opts.LeafNode.Nkey != pub {
			t.Fatalf("leaf authz nkey = %q, want %q", opts.LeafNode.Nkey, pub)
		}
	})

	t.Run("file with garbage fails pubkey validation", func(t *testing.T) {
		cf := createConfFile(t, []byte(conf(secretFile(t, "not-a-pubkey"))))
		if _, err := ProcessConfigFile(cf); err == nil {
			t.Fatalf("expected public user key validation error")
		}
	})

	t.Run("missing file defers (parses; pubkey validation skipped)", func(t *testing.T) {
		ref := "file:///no/such/snats/pub"
		cf := createConfFile(t, []byte(conf(ref)))
		opts, err := ProcessConfigFile(cf)
		if err != nil {
			t.Fatalf("deferred parse should succeed, got: %v", err)
		}
		if opts.LeafNode.Nkey != ref {
			t.Fatalf("leaf authz nkey = %q, want unresolved ref %q", opts.LeafNode.Nkey, ref)
		}
	})
}

func TestNkeyFileAccount(t *testing.T) {
	apub := mkAccountPub(t)
	conf := func(nkey string) string {
		return `accounts { A { nkey: "` + nkey + `" } }`
	}

	t.Run("file", func(t *testing.T) {
		cf := createConfFile(t, []byte(conf(secretFile(t, apub+"\n"))))
		opts, err := ProcessConfigFile(cf)
		if err != nil {
			t.Fatalf("ProcessConfigFile: %v", err)
		}
		acc := findAccount(opts, "A")
		if acc == nil || acc.Nkey != apub {
			t.Fatalf("account nkey = %v, want %q", acc, apub)
		}
	})

	t.Run("inline", func(t *testing.T) {
		cf := createConfFile(t, []byte(conf(apub)))
		opts, err := ProcessConfigFile(cf)
		if err != nil {
			t.Fatalf("ProcessConfigFile: %v", err)
		}
		acc := findAccount(opts, "A")
		if acc == nil || acc.Nkey != apub {
			t.Fatalf("account nkey = %v, want %q", acc, apub)
		}
	})

	t.Run("file with garbage fails account-key validation", func(t *testing.T) {
		cf := createConfFile(t, []byte(conf(secretFile(t, "not-an-account-key"))))
		if _, err := ProcessConfigFile(cf); err == nil {
			t.Fatalf("expected account key validation error")
		}
	})

	t.Run("missing file defers (parses; account-key validation skipped)", func(t *testing.T) {
		ref := "file:///no/such/snats/acc"
		cf := createConfFile(t, []byte(conf(ref)))
		opts, err := ProcessConfigFile(cf)
		if err != nil {
			t.Fatalf("deferred parse should succeed, got: %v", err)
		}
		acc := findAccount(opts, "A")
		if acc == nil || acc.Nkey != ref {
			t.Fatalf("account nkey = %v, want unresolved ref %q", acc, ref)
		}
	})
}

func TestNkeyFileAuthorizationUsers(t *testing.T) {
	_, pub := mkUserKey(t)
	conf := func(nkey string) string {
		return `authorization { users = [ { nkey: "` + nkey + `" } ] }`
	}

	t.Run("file", func(t *testing.T) {
		cf := createConfFile(t, []byte(conf(secretFile(t, pub+"\n"))))
		opts, err := ProcessConfigFile(cf)
		if err != nil {
			t.Fatalf("ProcessConfigFile: %v", err)
		}
		if len(opts.Nkeys) != 1 || opts.Nkeys[0].Nkey != pub {
			t.Fatalf("nkey users = %v, want one with %q", opts.Nkeys, pub)
		}
	})

	t.Run("inline", func(t *testing.T) {
		cf := createConfFile(t, []byte(conf(pub)))
		opts, err := ProcessConfigFile(cf)
		if err != nil {
			t.Fatalf("ProcessConfigFile: %v", err)
		}
		if len(opts.Nkeys) != 1 || opts.Nkeys[0].Nkey != pub {
			t.Fatalf("nkey users = %v, want one with %q", opts.Nkeys, pub)
		}
	})

	t.Run("file with garbage fails pubkey validation", func(t *testing.T) {
		cf := createConfFile(t, []byte(conf(secretFile(t, "not-a-pubkey"))))
		if _, err := ProcessConfigFile(cf); err == nil {
			t.Fatalf("expected public user key validation error")
		}
	})
}
