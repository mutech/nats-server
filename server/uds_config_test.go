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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func parseUDSConfigString(t *testing.T, conf string) (*Options, error) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "uds.conf")
	if err := os.WriteFile(f, []byte(conf), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return ProcessConfigFile(f)
}

func mustParseUDSConfig(t *testing.T, conf string) *Options {
	t.Helper()
	opts, err := parseUDSConfigString(t, conf)
	if err != nil {
		t.Fatalf("unexpected config error: %v\nconfig:\n%s", err, conf)
	}
	return opts
}

func udsRuleByUsername(t *testing.T, opts *Options, name string) *UDSRule {
	t.Helper()
	for _, r := range opts.UDSRules {
		if r.Username == name {
			return r
		}
	}
	t.Fatalf("no UDS rule with username %q (have %d rules)", name, len(opts.UDSRules))
	return nil
}

func assertExpr(t *testing.T, alt map[UDSRuleExpression]any, query string, negate bool, want any) {
	t.Helper()
	got, ok := alt[UDSRuleExpression{QueryName: query, Negate: negate}]
	if !ok {
		t.Fatalf("expression %q (negate=%v) not found in alternative %#v", query, negate, alt)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expression %q value = %#v (%T), want %#v (%T)", query, got, got, want, want)
	}
}

func TestUDS_Config_Parsing(t *testing.T) {
	t.Run("connection block full", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `
			uds {
				path: "/tmp/full.sock"
				group: "nats"
				mode: "0660"
			}
		`)
		if opts.UDS.Path != "/tmp/full.sock" {
			t.Errorf("Path = %q, want /tmp/full.sock", opts.UDS.Path)
		}
		if opts.UDS.Group != "nats" {
			t.Errorf("Group = %q, want nats", opts.UDS.Group)
		}
		if opts.UDS.Mode != "0660" {
			t.Errorf("Mode = %q, want 0660", opts.UDS.Mode)
		}
	})

	t.Run("connection block path only", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `uds { path: "/tmp/only.sock" }`)
		if opts.UDS.Path != "/tmp/only.sock" {
			t.Errorf("Path = %q, want /tmp/only.sock", opts.UDS.Path)
		}
		if opts.UDS.Group != "" || opts.UDS.Mode != "" {
			t.Errorf("expected empty group/mode, got group=%q mode=%q", opts.UDS.Group, opts.UDS.Mode)
		}
	})

	t.Run("user rule single match", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `
			authorization {
				users = [
					{
						user: "alice"
						uds { match { uid: 1000 } }
					}
				]
			}
		`)
		if len(opts.UDSRules) != 1 {
			t.Fatalf("want 1 UDS rule, got %d", len(opts.UDSRules))
		}
		for _, u := range opts.Users {
			if u.Username == "alice" {
				t.Fatalf("UDS rule user %q leaked into opts.Users", u.Username)
			}
		}
		r := udsRuleByUsername(t, opts, "alice")
		if r.Rolename != "" {
			t.Errorf("Rolename = %q, want empty", r.Rolename)
		}
		if r.Match == nil || len(*r.Match) != 1 {
			t.Fatalf("Match = %#v, want one alternative", r.Match)
		}
		assertExpr(t, (*r.Match)[0], "uid", false, int64(1000))
	})

	t.Run("role only rule", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `
			authorization {
				users = [
					{
						uds {
							role: "admin"
							match { gid: 0 }
						}
					}
				]
			}
		`)
		if len(opts.UDSRules) != 1 {
			t.Fatalf("want 1 UDS rule, got %d", len(opts.UDSRules))
		}
		r := opts.UDSRules[0]
		if r.Username != "" {
			t.Errorf("Username = %q, want empty", r.Username)
		}
		if r.Rolename != "admin" {
			t.Errorf("Rolename = %q, want admin", r.Rolename)
		}
		if r.Match == nil || len(*r.Match) != 1 {
			t.Fatalf("Match = %#v, want one alternative", r.Match)
		}
		assertExpr(t, (*r.Match)[0], "gid", false, int64(0))
	})

	t.Run("mixed user and role rule", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `
			authorization {
				users = [
					{
						user: "bob"
						uds {
							role: "ops"
							match { uid: 1000 }
						}
					}
				]
			}
		`)
		r := udsRuleByUsername(t, opts, "bob")
		if r.Rolename != "ops" {
			t.Errorf("Rolename = %q, want ops", r.Rolename)
		}
		assertExpr(t, (*r.Match)[0], "uid", false, int64(1000))
	})

	t.Run("match multiple AND conditions", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `
			authorization {
				users = [
					{
						user: "carol"
						uds {
							match {
								uid: 1000
								gid: 1000
							}
						}
					}
				]
			}
		`)
		r := udsRuleByUsername(t, opts, "carol")
		if r.Match == nil || len(*r.Match) != 1 {
			t.Fatalf("Match = %#v, want one alternative", r.Match)
		}
		alt := (*r.Match)[0]
		if len(alt) != 2 {
			t.Fatalf("want 2 AND expressions, got %d: %#v", len(alt), alt)
		}
		assertExpr(t, alt, "uid", false, int64(1000))
		assertExpr(t, alt, "gid", false, int64(1000))
	})

	t.Run("match OR alternatives", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `
			authorization {
				users = [
					{
						user: "dave"
						uds {
							match: [
								{uid: 1000}
								{gid: 0}
							]
						}
					}
				]
			}
		`)
		r := udsRuleByUsername(t, opts, "dave")
		if r.Match == nil || len(*r.Match) != 2 {
			t.Fatalf("Match = %#v, want two alternatives", r.Match)
		}
		assertExpr(t, (*r.Match)[0], "uid", false, int64(1000))
		assertExpr(t, (*r.Match)[1], "gid", false, int64(0))
	})

	t.Run("match negation", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `
			authorization {
				users = [
					{
						user: "erin"
						uds { match { "!uid": 0 } }
					}
				]
			}
		`)
		r := udsRuleByUsername(t, opts, "erin")
		assertExpr(t, (*r.Match)[0], "uid", true, int64(0))
	})

	t.Run("match string query", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `
			authorization {
				users = [
					{
						user: "frank"
						uds { match { "uid.name": "frank" } }
					}
				]
			}
		`)
		r := udsRuleByUsername(t, opts, "frank")
		assertExpr(t, (*r.Match)[0], "uid.name", false, "frank")
	})

	t.Run("error array value for scalar query", func(t *testing.T) {
		// Array match values are not implemented; a scalar query must reject one
		// at config time rather than fail per-connection at match time.
		_, err := parseUDSConfigString(t, `
			authorization {
				users = [
					{ user: "grace", uds { match { groups: [ 10, 20 ] } } }
				]
			}
		`)
		if err == nil || !strings.Contains(err.Error(), "groups") {
			t.Fatalf("want error rejecting array value for %q, got: %v", "groups", err)
		}
	})

	t.Run("error wrong scalar type for query", func(t *testing.T) {
		_, err := parseUDSConfigString(t, `
			authorization {
				users = [
					{ user: "heidi", uds { match { uid: "not-an-int" } } }
				]
			}
		`)
		if err == nil || !strings.Contains(err.Error(), "uid") {
			t.Fatalf("want error rejecting string value for %q, got: %v", "uid", err)
		}
	})

	t.Run("rule permissions", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `
			authorization {
				users = [
					{
						user: "heidi"
						uds { match { uid: 1000 } }
						permissions {
							publish {
								allow: [ "pub.allow.>" ]
								deny: [ "pub.deny.>" ]
							}
							subscribe {
								allow: [ "sub.allow.>" ]
								deny: [ "sub.deny.>" ]
							}
						}
					}
				]
			}
		`)
		r := udsRuleByUsername(t, opts, "heidi")
		if r.Permissions == nil {
			t.Fatal("Permissions = nil, want populated")
		}
		if r.Permissions.Publish == nil || !reflect.DeepEqual(r.Permissions.Publish.Allow, []string{"pub.allow.>"}) {
			t.Errorf("Publish.Allow = %#v, want [pub.allow.>]", r.Permissions.Publish)
		}
		if !reflect.DeepEqual(r.Permissions.Publish.Deny, []string{"pub.deny.>"}) {
			t.Errorf("Publish.Deny = %#v, want [pub.deny.>]", r.Permissions.Publish.Deny)
		}
		if r.Permissions.Subscribe == nil || !reflect.DeepEqual(r.Permissions.Subscribe.Allow, []string{"sub.allow.>"}) {
			t.Errorf("Subscribe.Allow = %#v, want [sub.allow.>]", r.Permissions.Subscribe)
		}
		if !reflect.DeepEqual(r.Permissions.Subscribe.Deny, []string{"sub.deny.>"}) {
			t.Errorf("Subscribe.Deny = %#v, want [sub.deny.>]", r.Permissions.Subscribe.Deny)
		}
	})

	t.Run("combined connection block and rules", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `
			uds {
				path: "/tmp/combined.sock"
				mode: "0660"
			}
			authorization {
				users = [
					{
						user: "ivan"
						uds { match { uid: 1000 } }
						permissions { publish { allow: [ ">" ] } }
					}
				]
			}
		`)
		if opts.UDS.Path != "/tmp/combined.sock" {
			t.Errorf("Path = %q, want /tmp/combined.sock", opts.UDS.Path)
		}
		r := udsRuleByUsername(t, opts, "ivan")
		assertExpr(t, (*r.Match)[0], "uid", false, int64(1000))
		if r.Permissions == nil || r.Permissions.Publish == nil {
			t.Fatalf("expected publish permissions, got %#v", r.Permissions)
		}
	})

	t.Run("error missing match clause", func(t *testing.T) {
		_, err := parseUDSConfigString(t, `
			authorization {
				users = [ { user: "x", uds { role: "r" } } ]
			}
		`)
		if err == nil || !strings.Contains(err.Error(), "match clause") {
			t.Fatalf("want error about missing match clause, got: %v", err)
		}
	})

	t.Run("error no user or role", func(t *testing.T) {
		_, err := parseUDSConfigString(t, `
			authorization {
				users = [ { uds { match { uid: 0 } } } ]
			}
		`)
		if err == nil || !strings.Contains(err.Error(), "user and/or role") {
			t.Fatalf("want error about requiring user and/or role, got: %v", err)
		}
	})

	t.Run("error uds rule with password", func(t *testing.T) {
		_, err := parseUDSConfigString(t, `
			authorization {
				users = [ { user: "x", password: "y", uds { match { uid: 0 } } } ]
			}
		`)
		if err == nil || !strings.Contains(err.Error(), "passwords") {
			t.Fatalf("want error about passwords, got: %v", err)
		}
	})
}

func TestUDS_Config_Account(t *testing.T) {
	t.Run("uds rule in account binds account", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `
			accounts {
				APP {
					users = [
						{
							user: "alice"
							uds { match { uid: 1000 } }
							permissions { publish { allow: [ ">" ] } }
						}
					]
				}
			}
		`)
		r := udsRuleByUsername(t, opts, "alice")
		if r.Account == nil {
			t.Fatal("Account = nil, want APP account")
		}
		if r.Account.Name != "APP" {
			t.Errorf("Account.Name = %q, want APP", r.Account.Name)
		}
	})

	t.Run("uds rule in $SYS account", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `
			system_account: "$SYS"
			accounts {
				$SYS {
					users = [
						{
							user: "uds-admin"
							uds { match { uid: 0 } }
							permissions {
								publish { allow: [ ">" ] }
								subscribe { allow: [ ">" ] }
							}
						}
					]
				}
			}
		`)
		r := udsRuleByUsername(t, opts, "uds-admin")
		if r.Account == nil || r.Account.Name != "$SYS" {
			t.Fatalf("Account = %#v, want $SYS", r.Account)
		}
	})

	t.Run("authorization-block rule stays accountless", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `
			authorization {
				users = [
					{
						user: "alice"
						uds { match { uid: 1000 } }
						permissions { publish { allow: [ ">" ] } }
					}
				]
			}
		`)
		r := udsRuleByUsername(t, opts, "alice")
		if r.Account != nil {
			t.Fatalf("Account = %#v, want nil for authorization{} rule", r.Account)
		}
	})

	t.Run("error duplicate username across account and authorization", func(t *testing.T) {
		_, err := parseUDSConfigString(t, `
			authorization {
				users = [
					{ user: "dup", uds { match { uid: 1000 } }, permissions { publish { allow: [ ">" ] } } }
				]
			}
			accounts {
				APP {
					users = [
						{ user: "dup", uds { match { uid: 2000 } }, permissions { publish { allow: [ ">" ] } } }
					]
				}
			}
		`)
		if err == nil || !strings.Contains(err.Error(), "Duplicate user") {
			t.Fatalf("want duplicate user error, got: %v", err)
		}
	})

	t.Run("error duplicate username across two accounts", func(t *testing.T) {
		_, err := parseUDSConfigString(t, `
			accounts {
				APP {
					users = [
						{ user: "dup", uds { match { uid: 1000 } }, permissions { publish { allow: [ ">" ] } } }
					]
				}
				OTHER {
					users = [
						{ user: "dup", uds { match { uid: 2000 } }, permissions { publish { allow: [ ">" ] } } }
					]
				}
			}
		`)
		if err == nil || !strings.Contains(err.Error(), "Duplicate user") {
			t.Fatalf("want duplicate user error across accounts, got: %v", err)
		}
	})

	t.Run("role-only rule in account is bound to account", func(t *testing.T) {
		opts := mustParseUDSConfig(t, `
			accounts {
				APP {
					users = [
						{ uds { role: "r", match { uid: 1000 } }, permissions { publish { allow: [ ">" ] } } }
					]
				}
			}
		`)
		var role *UDSRule
		for _, r := range opts.UDSRules {
			if r.Rolename == "r" {
				role = r
			}
		}
		if role == nil {
			t.Fatalf("no UDS rule with role %q (have %d rules)", "r", len(opts.UDSRules))
		}
		if role.Account == nil || role.Account.Name != "APP" {
			t.Fatalf("role rule Account = %#v, want APP", role.Account)
		}
	})
}
