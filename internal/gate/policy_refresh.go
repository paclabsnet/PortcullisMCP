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

package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// localFSPolicy holds the runtime localfs policy used by FastPath.
// A nil pointer in Gate.localFSPolicy indicates degraded mode — no valid
// policy has been fetched yet (or was discarded due to on_fetch_failure: fail).
type localFSPolicy struct {
	Workspace SandboxConfig
	Forbidden ForbiddenConfig
	Strategy  LocalFSStrategyConfig
}

// localFSPolicyPayload is the JSON shape expected from Keep's
// /config/portcullis-localfs endpoint. It mirrors LocalFSConfig minus the
// Enabled and Rules fields, which are Gate-local concerns.
type localFSPolicyPayload struct {
	Workspace SandboxConfig         `json:"workspace"`
	Forbidden ForbiddenConfig       `json:"forbidden"`
	Strategy  LocalFSStrategyConfig `json:"strategy"`
}

// getLocalFSPolicy returns the current runtime policy snapshot.
// When source is "keep" and no policy has been fetched yet, it returns nil
// (degraded/fail-closed). When source is "local" and localFSPolicy was never
// explicitly set (e.g. in tests or legacy code), it falls back to deriving the
// policy directly from cfg.
func (g *Gate) getLocalFSPolicy() *localFSPolicy {
	g.localFSPolicyMu.RLock()
	p := g.localFSPolicy
	g.localFSPolicyMu.RUnlock()
	if p != nil {
		return p
	}
	// Degraded: nil policy. For source:"keep" this means deny-all (fail-closed).
	if g.cfg.Responsibility.Tools.LocalFS.Rules.Source == "keep" {
		return nil
	}
	// source:"local" with no explicit policy — derive from cfg. This path is
	// taken when Gate is constructed directly (e.g. in tests) without going
	// through New(), which normally pre-populates localFSPolicy.
	return &localFSPolicy{
		Workspace: g.cfg.Responsibility.Tools.LocalFS.Workspace,
		Forbidden: g.cfg.Responsibility.Tools.LocalFS.Forbidden,
		Strategy:  g.cfg.Responsibility.Tools.LocalFS.Strategy,
	}
}

// setLocalFSPolicy atomically replaces the runtime policy.
// Passing nil transitions the tool to degraded mode.
func (g *Gate) setLocalFSPolicy(p *localFSPolicy) {
	g.localFSPolicyMu.Lock()
	defer g.localFSPolicyMu.Unlock()
	g.localFSPolicy = p
}

// fetchAndApplyLocalFSPolicy fetches the localfs policy from Keep's
// /config/portcullis-localfs endpoint, validates the schema, then atomically
// applies it to both the localfs Server (sandbox enforcement) and the Gate
// fast-path (workspace/forbidden/strategy checks).
//
// Returns an error on fetch failure, invalid JSON, or schema violations.
// On success the tool transitions from degraded to healthy.
func (g *Gate) fetchAndApplyLocalFSPolicy(ctx context.Context) error {
	raw, err := g.forwarder.GetStaticPolicy(ctx, "portcullis-localfs")
	if err != nil {
		return fmt.Errorf("fetch localfs policy from Keep: %w", err)
	}

	var payload localFSPolicyPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return fmt.Errorf("localfs policy contains invalid JSON: %w", err)
	}

	// Schema validation: workspace must have at least one usable directory.
	if len(payload.Workspace.EffectiveDirs()) == 0 {
		return fmt.Errorf("localfs policy invalid: workspace must contain at least one directory")
	}

	// Validate strategy values using the existing config-level validator.
	if err := payload.Strategy.Validate(); err != nil {
		return fmt.Errorf("localfs policy invalid strategy: %w", err)
	}

	// Expand and resolve workspace directories.
	rawDirs := payload.Workspace.EffectiveDirs()
	expanded := make([]string, 0, len(rawDirs))
	for _, d := range rawDirs {
		exp, err := expandHome(d)
		if err != nil {
			return fmt.Errorf("expand sandbox dir %q: %w", d, err)
		}
		// We use the expanded path here; localfs.UpdatePolicy will handle
		// the final EvalSymlinks and skip missing ones.
		expanded = append(expanded, exp)
	}

	// Expand and resolve forbidden directories.
	rawForbidden := payload.Forbidden.Directories
	expandedForbidden := make([]string, 0, len(rawForbidden))
	for _, d := range rawForbidden {
		exp, err := expandHome(d)
		if err != nil {
			return fmt.Errorf("expand forbidden dir %q: %w", d, err)
		}
		// Resolve symlinks if possible, but keep the path even if it doesn't
		// exist (resolvePath handles the walk-up logic).
		res, err := resolvePath(exp)
		if err != nil {
			// If resolution fails completely, fall back to the expanded path
			// so it remains forbidden.
			expandedForbidden = append(expandedForbidden, exp)
		} else {
			expandedForbidden = append(expandedForbidden, res)
		}
	}

	// Apply to the localfs Server (sandbox path enforcement in tool handlers).
	if g.localFSServer != nil {
		if err := g.localFSServer.UpdatePolicy(expanded); err != nil {
			return fmt.Errorf("apply localfs sandbox policy: %w", err)
		}
	}

	// Apply to Gate fast-path (forbidden + strategy + workspace checks).
	g.setLocalFSPolicy(&localFSPolicy{
		Workspace: SandboxConfig{Directories: expanded},
		Forbidden: ForbiddenConfig{Directories: expandedForbidden},
		Strategy:  payload.Strategy,
	})

	slog.Info("gate: localfs policy applied from Keep", "dirs", expanded)
	return nil
}

// startLocalFSPolicyRefresh starts a background goroutine that re-fetches the
// localfs policy from Keep on each TTL tick. On failure the behaviour is
// controlled by on_fetch_failure:
//   - "cached" (default): keep the last valid policy; log a warning.
//   - "fail": discard the policy, transitioning the tool back to degraded.
func (g *Gate) startLocalFSPolicyRefresh(ctx context.Context) {
	ttl := time.Duration(g.cfg.Responsibility.Tools.LocalFS.Rules.TTL) * time.Second
	onFailure := g.cfg.Responsibility.Tools.LocalFS.Rules.OnFetchFailure
	go func() {
		ticker := time.NewTicker(ttl)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := g.fetchAndApplyLocalFSPolicy(ctx); err != nil {
					slog.Warn("gate: localfs policy refresh failed",
						"error", err,
						"on_fetch_failure", onFailure,
					)
					if onFailure == "fail" {
						// Discard cached policy — tool transitions to degraded.
						// FastPath will deny all localfs requests until next
						// successful fetch.
						g.setLocalFSPolicy(nil)
					}
					// "cached": leave existing policy in place.
				}
			}
		}
	}()
}
