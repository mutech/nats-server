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
	"strings"
	"sync"
)

// ConfigSectionHandler parses a custom top-level configuration section.
//
// It receives the section's value with all configuration-parser tokens
// removed, i.e. as plain Go types: map[string]any for blocks, []any for
// arrays, and string/int64/float64/bool for scalars. This allows handlers
// living outside the server package (which cannot reach the unexported token
// machinery) to work with ordinary values.
//
// The returned value is stored verbatim in Options.CustomConfig under the
// lower-cased section name for the embedding program to consume. A non-nil
// error aborts configuration loading and is reported against the section's
// position in the file.
type ConfigSectionHandler func(v any) (any, error)

// ConfigSectionReloadHandler is invoked during a live configuration reload when
// a registered section's parsed value changed. It receives the previous and the
// new parsed value (as returned by the section's ConfigSectionHandler); for a
// section that was added or removed, the corresponding value is nil. It runs
// after the reload has been validated and committed, so a returned error cannot
// abort the reload — it is logged. Structural validation belongs in the
// ConfigSectionHandler, which is re-run on reload and whose error does abort it.
type ConfigSectionReloadHandler func(oldVal, newVal any) error

var (
	configSectionsMu       sync.RWMutex
	configSections         = map[string]ConfigSectionHandler{}
	configSectionReloaders = map[string]ConfigSectionReloadHandler{}
)

// RegisterConfigSection registers handler for a custom top-level configuration
// key (matched case-insensitively). Programs that embed the server call this
// before loading configuration so that an otherwise-unknown top-level section
// — for example a `myapp { ... }` block — is handed to handler instead of being
// rejected as an unknown field.
//
// Registering with an empty key or a nil handler panics. Registering a key that
// is already present replaces the previous handler. Registration is global and
// intended to be performed once during program startup.
func RegisterConfigSection(key string, handler ConfigSectionHandler) {
	if key == "" {
		panic("server: RegisterConfigSection requires a non-empty key")
	}
	if handler == nil {
		panic("server: RegisterConfigSection requires a non-nil handler")
	}
	configSectionsMu.Lock()
	defer configSectionsMu.Unlock()
	configSections[strings.ToLower(key)] = handler
}

// SetConfigSectionReloadHandler registers an optional reload handler for a
// custom section (matched case-insensitively). It is independent of
// RegisterConfigSection: if no reload handler is set, a changed section is
// accepted on reload without notifying the embedder (the new value is available
// via Options.CustomConfig). Registering with an empty key or a nil handler
// panics. Registering a key that is already present replaces the previous
// handler.
func SetConfigSectionReloadHandler(key string, handler ConfigSectionReloadHandler) {
	if key == "" {
		panic("server: SetConfigSectionReloadHandler requires a non-empty key")
	}
	if handler == nil {
		panic("server: SetConfigSectionReloadHandler requires a non-nil handler")
	}
	configSectionsMu.Lock()
	defer configSectionsMu.Unlock()
	configSectionReloaders[strings.ToLower(key)] = handler
}

// lookupConfigSection returns the handler registered for key, if any. The key
// is matched case-insensitively.
func lookupConfigSection(key string) (ConfigSectionHandler, bool) {
	configSectionsMu.RLock()
	defer configSectionsMu.RUnlock()
	h, ok := configSections[strings.ToLower(key)]
	return h, ok
}

// lookupConfigSectionReloadHandler returns the reload handler registered for
// key, if any. The key is matched case-insensitively.
func lookupConfigSectionReloadHandler(key string) (ConfigSectionReloadHandler, bool) {
	configSectionsMu.RLock()
	defer configSectionsMu.RUnlock()
	h, ok := configSectionReloaders[strings.ToLower(key)]
	return h, ok
}

// unregisterConfigSection removes the parse and reload handlers registered for
// key. It is used by tests to avoid leaking global registrations between cases.
func unregisterConfigSection(key string) {
	configSectionsMu.Lock()
	defer configSectionsMu.Unlock()
	lk := strings.ToLower(key)
	delete(configSections, lk)
	delete(configSectionReloaders, lk)
}

// deepUnwrapConfigValue recursively strips configuration-parser tokens from v,
// returning plain Go values (map[string]any, []any, and scalars). The
// configuration parser wraps every value in a token carrying its source
// position; only the top-level value passed to a section is unwrapped by the
// caller, so nested values must be unwrapped here before a handler can use them.
func deepUnwrapConfigValue(v any) any {
	if tk, ok := v.(token); ok {
		v = tk.Value()
	}
	switch vv := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(vv))
		for k, e := range vv {
			m[k] = deepUnwrapConfigValue(e)
		}
		return m
	case []any:
		s := make([]any, len(vv))
		for i, e := range vv {
			s[i] = deepUnwrapConfigValue(e)
		}
		return s
	default:
		return v
	}
}

// customConfigOption is the reload option produced when Options.CustomConfig
// changes. On apply it invokes the registered reload handler for each section
// whose parsed value changed (or was added/removed). It is a no-op for built-in
// server behavior; the new values are already part of the reloaded options.
type customConfigOption struct {
	noopOption
	oldConfig map[string]any
	newConfig map[string]any
}

// newCustomConfigReloadOption builds the reload option from the old and new
// Options.CustomConfig values. It is called from diffOptions when the field
// changed.
func newCustomConfigReloadOption(oldValue, newValue any) option {
	oldConfig, _ := oldValue.(map[string]any)
	newConfig, _ := newValue.(map[string]any)
	return &customConfigOption{oldConfig: oldConfig, newConfig: newConfig}
}

func (o *customConfigOption) Apply(s *Server) {
	notify := func(key string, oldVal, newVal any) {
		if h, ok := lookupConfigSectionReloadHandler(key); ok {
			if err := h(oldVal, newVal); err != nil {
				s.Errorf("Reloaded: custom config section %q reload handler failed: %v", key, err)
			}
		}
	}
	for key, newVal := range o.newConfig {
		if oldVal, ok := o.oldConfig[key]; !ok || !reflect.DeepEqual(oldVal, newVal) {
			notify(key, o.oldConfig[key], newVal)
		}
	}
	for key, oldVal := range o.oldConfig {
		if _, present := o.newConfig[key]; !present {
			notify(key, oldVal, nil)
		}
	}
	s.Noticef("Reloaded: custom configuration sections")
}
