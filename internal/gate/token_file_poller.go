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
	"os"
	"strings"
	"time"
)

// TokenFilePoller watches a file for changes and invokes a callback when
// the content changes. Used in duplicate_mcp_hack secondary mode to pick up the
// OIDC token written by the primary instance.
//
// The callback is invoked with the new JWT when the file appears or changes.
// If the file disappears or becomes empty after previously having content,
// the callback is invoked with an empty string so the caller can clear its
// identity and return to the unauthenticated state.
type TokenFilePoller struct {
	path     string
	interval time.Duration
	onToken  func(rawJWT string)
}

// NewTokenFilePoller creates a TokenFilePoller. interval <= 0 defaults to 5s.
func NewTokenFilePoller(path string, interval time.Duration, onToken func(string)) *TokenFilePoller {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &TokenFilePoller{path: path, interval: interval, onToken: onToken}
}

// Start begins polling in a background goroutine. It stops when ctx is cancelled.
func (p *TokenFilePoller) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(p.interval)
		defer ticker.Stop()
		lastSeen := ""
		hadContent := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				data, err := os.ReadFile(p.path)
				content := strings.TrimSpace(string(data))
				if err != nil || content == "" {
					if hadContent {
						hadContent = false
						lastSeen = ""
						p.onToken("")
					}
					continue
				}
				if content != lastSeen {
					hadContent = true
					p.onToken(content)
					lastSeen = content
				}
			}
		}
	}()
}
