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
	"fmt"
	"strings"
	"testing"
)

// The following type and handler illustrate how a program embedding the server
// would consume its own top-level configuration section.

// appConfig is the typed configuration such a program builds from its section.
type appConfig struct {
	Service  string
	Interval string
	Subject  string
}

// parseAppSection is an example ConfigSectionHandler: it converts the plain map
// handed to it by the parser into a typed config, validating as it goes. A
// returned error aborts configuration loading.
func parseAppSection(v any) (any, error) {
	root, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("myapp: expected a block, got %T", v)
	}
	var cfg appConfig
	if s, ok := root["service"].(string); ok {
		cfg.Service = s
	}
	if s, ok := root["interval"].(string); ok {
		cfg.Interval = s
	}
	if s, ok := root["subject"].(string); ok {
		cfg.Subject = s
	}
	if cfg.Subject == "" {
		return nil, fmt.Errorf("myapp: 'subject' is required")
	}
	return cfg, nil
}

// TestRegisterConfigSectionEndToEnd exercises the feature through the real
// config-loading path (ProcessConfigFile, which ConfigureOptions delegates to),
// proving that a custom section is parsed when registered and refused when it is
// not.
func TestRegisterConfigSectionEndToEnd(t *testing.T) {
	conf := createConfFile(t, []byte(`
		port: 4222
		myapp {
			service:  "scraper"
			interval: "1s"
			subject:  "app.events"
		}
	`))

	// load goes through the same config-loading entry the server uses; we call
	// ProcessConfigFile directly rather than ConfigureOptions so the test does
	// not touch process-level (flag/signal) global state.
	load := func() (*Options, error) {
		return ProcessConfigFile(conf)
	}

	t.Run("registered section is parsed through the real entry point", func(t *testing.T) {
		RegisterConfigSection("myapp", parseAppSection)
		defer unregisterConfigSection("myapp")

		opts, err := load()
		if err != nil {
			t.Fatalf("ProcessConfigFile failed: %v", err)
		}
		if opts.Port != 4222 {
			t.Fatalf("expected port 4222, got %d", opts.Port)
		}
		cfg, ok := opts.CustomConfig["myapp"].(appConfig)
		if !ok {
			t.Fatalf("expected typed appConfig, got %T", opts.CustomConfig["myapp"])
		}
		want := appConfig{Service: "scraper", Interval: "1s", Subject: "app.events"}
		if cfg != want {
			t.Fatalf("parsed config mismatch:\n got: %#v\nwant: %#v", cfg, want)
		}
	})

	t.Run("same section is refused when not registered", func(t *testing.T) {
		NoErrOnUnknownFields(false) // strict (default) mode

		_, err := load()
		if err == nil {
			t.Fatalf("expected ConfigureOptions to reject the unregistered 'myapp' section")
		}
		if !strings.Contains(err.Error(), "myapp") {
			t.Fatalf("expected error to mention the unknown 'myapp' section, got: %v", err)
		}
	})
}
