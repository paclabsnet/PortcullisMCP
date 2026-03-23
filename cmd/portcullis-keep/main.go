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

	"github.com/paclabsnet/PortcullisMCP/internal/keep"
	"github.com/paclabsnet/PortcullisMCP/internal/telemetry"
	"github.com/paclabsnet/PortcullisMCP/internal/version"
)

func main() {
	cfgPath := flag.String("config", "/etc/portcullis/keep.yaml", "path to keep config file")
	flag.Parse()

	slog.Info("portcullis-keep starting", "version", version.Version)

	cfg, err := keep.LoadConfig(*cfgPath)
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

	srv, err := keep.NewServer(cfg, *cfgPath)
	if err != nil {
		slog.Error("init keep", "error", err)
		os.Exit(1)
	}

	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		slog.Error("keep exited", "error", err)
		os.Exit(1)
	}
}

