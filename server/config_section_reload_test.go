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
	"reflect"
	"testing"
)

func TestRegisterConfigSectionReloadInvokesHandlerOnChange(t *testing.T) {
	const key = "myapp"
	RegisterConfigSection(key, func(v any) (any, error) { return v, nil })
	defer unregisterConfigSection(key)

	type call struct{ oldVal, newVal any }
	var calls []call
	SetConfigSectionReloadHandler(key, func(oldVal, newVal any) error {
		calls = append(calls, call{oldVal, newVal})
		return nil
	})

	s, _, conf := runReloadServerWithContent(t, []byte(`
		port: -1
		myapp { service: "x" }
	`))
	defer s.Shutdown()

	changeCurrentConfigContentWithNewContent(t, conf, []byte(`
		port: -1
		myapp { service: "y" }
	`))
	if err := s.Reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	if len(calls) != 1 {
		t.Fatalf("expected the reload handler to be called once, got %d", len(calls))
	}
	oldMap, _ := calls[0].oldVal.(map[string]any)
	newMap, _ := calls[0].newVal.(map[string]any)
	if oldMap["service"] != "x" || newMap["service"] != "y" {
		t.Fatalf("unexpected reload values: old=%v new=%v", calls[0].oldVal, calls[0].newVal)
	}

	// The new value is also reflected in the reloaded options.
	got, _ := s.getOpts().CustomConfig[key].(map[string]any)
	if got["service"] != "y" {
		t.Fatalf("expected reloaded CustomConfig service=y, got %v", s.getOpts().CustomConfig[key])
	}
}

func TestRegisterConfigSectionReloadUnrelatedChangeSucceeds(t *testing.T) {
	const key = "myapp"
	RegisterConfigSection(key, func(v any) (any, error) { return v, nil })
	defer unregisterConfigSection(key)

	reloadCalled := false
	SetConfigSectionReloadHandler(key, func(oldVal, newVal any) error {
		reloadCalled = true
		return nil
	})

	s, _, conf := runReloadServerWithContent(t, []byte(`
		port: -1
		debug: false
		myapp { service: "x" }
	`))
	defer s.Shutdown()

	// Change only an unrelated, reloadable option; the custom section is left
	// unchanged. Without skipping map[string]any in imposeOrder, the presence of
	// a parsed custom section would make every reload fail outright.
	changeCurrentConfigContentWithNewContent(t, conf, []byte(`
		port: -1
		debug: true
		myapp { service: "x" }
	`))
	if err := s.Reload(); err != nil {
		t.Fatalf("reload with an unrelated change failed: %v", err)
	}
	if reloadCalled {
		t.Fatalf("reload handler must not fire when the section is unchanged")
	}
	if !s.getOpts().Debug {
		t.Fatalf("expected the unrelated change (debug) to be applied")
	}
}

func TestOptionsCloneCopiesCustomConfig(t *testing.T) {
	orig := &Options{
		CustomConfig: map[string]any{
			"myapp": map[string]any{"service": "x"},
		},
	}
	clone := orig.Clone()

	if !reflect.DeepEqual(clone.CustomConfig, orig.CustomConfig) {
		t.Fatalf("clone CustomConfig differs from original")
	}

	// Contract: Clone copies the top-level map (so mutating the clone's map does
	// not affect the original), while the values are shared by reference — the
	// server treats them as read-only.
	clone.CustomConfig["added"] = 1
	if _, ok := orig.CustomConfig["added"]; ok {
		t.Fatalf("clone shares the top-level CustomConfig map with the original")
	}
	delete(clone.CustomConfig, "myapp")
	if _, ok := orig.CustomConfig["myapp"]; !ok {
		t.Fatalf("deleting from the clone affected the original map")
	}
}
