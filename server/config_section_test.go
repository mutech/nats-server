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

package server

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestRegisterConfigSectionParsesCustomBlock(t *testing.T) {
	const key = "myapp"
	var handlerInput any
	RegisterConfigSection(key, func(v any) (any, error) {
		handlerInput = v
		return v, nil
	})
	defer unregisterConfigSection(key)

	conf := createConfFile(t, []byte(`
		port: 4242
		myapp {
			section {
				name: "alpha"
				interval: "1s"
				count: 3
				enabled: true
				tags: [ "a", "b" ]
			}
		}
	`))

	opts, err := ProcessConfigFile(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A regular server option outside the custom section is still parsed.
	if opts.Port != 4242 {
		t.Fatalf("expected port 4242, got %d", opts.Port)
	}

	// The section is stored under the lower-cased key.
	stored, ok := opts.CustomConfig[key]
	if !ok {
		t.Fatalf("CustomConfig missing key %q; have %v", key, opts.CustomConfig)
	}
	if !reflect.DeepEqual(stored, handlerInput) {
		t.Fatalf("stored value differs from the value passed to the handler")
	}

	// The handler receives plain Go values with all parser tokens removed,
	// including nested blocks, arrays and scalars.
	want := map[string]any{
		"section": map[string]any{
			"name":     "alpha",
			"interval": "1s",
			"count":    int64(3),
			"enabled":  true,
			"tags":     []any{"a", "b"},
		},
	}
	if !reflect.DeepEqual(stored, want) {
		t.Fatalf("parsed section mismatch:\n got: %#v\nwant: %#v", stored, want)
	}
}

func TestRegisterConfigSectionKeyIsCaseInsensitive(t *testing.T) {
	RegisterConfigSection("MyApp", func(v any) (any, error) {
		return v, nil
	})
	defer unregisterConfigSection("myapp")

	conf := createConfFile(t, []byte(`myapp { a: 1 }`))
	opts, err := ProcessConfigFile(conf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := opts.CustomConfig["myapp"]; !ok {
		t.Fatalf("expected section stored under lower-cased key; have %v", opts.CustomConfig)
	}
}

func TestRegisterConfigSectionHandlerErrorAbortsLoad(t *testing.T) {
	const key = "myapp"
	RegisterConfigSection(key, func(v any) (any, error) {
		return nil, errors.New("bad custom section")
	})
	defer unregisterConfigSection(key)

	conf := createConfFile(t, []byte(`myapp { x: 1 }`))
	if _, err := ProcessConfigFile(conf); err == nil {
		t.Fatalf("expected handler error to abort config load")
	} else if !strings.Contains(err.Error(), "bad custom section") {
		t.Fatalf("expected handler error to be surfaced, got: %v", err)
	}
}

func TestRegisterConfigSectionDoesNotMaskUnknownFields(t *testing.T) {
	// Ensure the dispatch hook still rejects genuinely unknown top-level fields
	// (i.e. ones without a registered handler). Guard the global strict-mode
	// flag so this case is independent of other tests.
	NoErrOnUnknownFields(false)

	const handled = "myapp"
	RegisterConfigSection(handled, func(v any) (any, error) { return v, nil })
	defer unregisterConfigSection(handled)

	conf := createConfFile(t, []byte(`
		myapp { ok: 1 }
		definitely_not_a_known_field { foo: bar }
	`))
	_, err := ProcessConfigFile(conf)
	if err == nil {
		t.Fatalf("expected an unknown-field error for the unhandled section")
	}
	if !strings.Contains(err.Error(), "definitely_not_a_known_field") {
		t.Fatalf("expected error to mention the unknown field, got: %v", err)
	}
}

func TestDeepUnwrapConfigValue(t *testing.T) {
	// Parsing a config block yields token-wrapped nested values; deep-unwrapping
	// must leave no token behind at any depth.
	var captured any
	const key = "myapp"
	RegisterConfigSection(key, func(v any) (any, error) {
		captured = v
		return v, nil
	})
	defer unregisterConfigSection(key)

	conf := createConfFile(t, []byte(`
		myapp {
			nested {
				list: [ { k: "v" }, 2, true ]
			}
		}
	`))
	if _, err := ProcessConfigFile(conf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertNoConfigTokens(t, captured)

	want := map[string]any{
		"nested": map[string]any{
			"list": []any{map[string]any{"k": "v"}, int64(2), true},
		},
	}
	if !reflect.DeepEqual(captured, want) {
		t.Fatalf("deep unwrap mismatch:\n got: %#v\nwant: %#v", captured, want)
	}
}

func TestRegisterConfigSectionRejectsInvalidInput(t *testing.T) {
	assertConfigPanics(t, "empty key", func() { RegisterConfigSection("", func(v any) (any, error) { return v, nil }) })
	assertConfigPanics(t, "nil handler", func() { RegisterConfigSection("myapp", nil) })
}

// assertNoConfigTokens fails the test if v, or anything nested within it, is
// still a configuration-parser token.
func assertNoConfigTokens(t *testing.T, v any) {
	t.Helper()
	if _, ok := v.(token); ok {
		t.Fatalf("found a leftover config token: %#v", v)
	}
	switch vv := v.(type) {
	case map[string]any:
		for _, e := range vv {
			assertNoConfigTokens(t, e)
		}
	case []any:
		for _, e := range vv {
			assertNoConfigTokens(t, e)
		}
	}
}

func assertConfigPanics(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: expected panic, got none", name)
		}
	}()
	fn()
}
