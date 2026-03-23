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
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/paclabsnet/PortcullisMCP/internal/guard"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	"github.com/paclabsnet/PortcullisMCP/internal/version"
)

func main() {
	cfgPath := flag.String("config", "/etc/portcullis/guard.yaml", "path to guard config file")
	flag.Parse()

	slog.Info("portcullis-guard starting", "version", version.Version)

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv, err := guard.NewServer(cfg)
	if err != nil {
		slog.Error("init guard", "error", err)
		os.Exit(1)
	}

	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		slog.Error("guard exited", "error", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (guard.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return guard.Config{}, err
	}
	data = shared.ExpandEnvVarsInYAML(data)
	var cfg guard.Config
	return cfg, yaml.Unmarshal(data, &cfg)
}
