// Copyright 2026 Policy-as-Code Laboratories (PAC.Labs)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/paclabsnet/PortcullisMCP/internal/gate"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	"github.com/paclabsnet/PortcullisMCP/internal/telemetry"
	"github.com/paclabsnet/PortcullisMCP/internal/version"
)

func main() {
	cfgPath := flag.String("config", "~/.portcullis/gate.yaml", "path to gate config file")
	flag.Parse()

	slog.Info("portcullis-gate starting", "version", version.Version)

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownTelemetry, err := telemetry.Setup(ctx, cfg.Telemetry)
	if err != nil {
		slog.Error("init telemetry", "error", err)
		os.Exit(1)
	}
	defer func() { _ = shutdownTelemetry(context.Background()) }()

	g, err := gate.New(ctx, cfg)
	if err != nil {
		slog.Error("init gate", "error", err)
		os.Exit(1)
	}

	if err := g.Run(ctx); err != nil && err != context.Canceled {
		slog.Error("gate exited", "error", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (gate.Config, error) {
	expanded, err := expandHome(path)
	if err != nil {
		return gate.Config{}, err
	}
	data, err := os.ReadFile(expanded)
	if err != nil {
		return gate.Config{}, err
	}
	// Expand environment variables in the YAML
	data = shared.ExpandEnvVarsInYAML(data)
	var cfg gate.Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return gate.Config{}, err
	}
	return cfg, cfg.Validate()
}

func expandHome(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return home + path[1:], nil
}
