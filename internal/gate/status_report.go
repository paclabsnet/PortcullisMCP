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
	"fmt"
	"net/http"
	"time"
)

// pingReadiness performs a GET to <endpoint>/readyz with a 3-second timeout.
// Returns "available" if any HTTP response is received, "unavailable" otherwise.
func pingReadiness(ctx context.Context, endpoint string) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/readyz", nil)
	if err != nil {
		return "unavailable"
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "unavailable"
	}
	resp.Body.Close()
	return "available"
}

// buildStatusReport returns the portcullis_status message and whether Gate is
// in an error state. It performs live /readyz checks against Keep and Guard.
func (g *Gate) buildStatusReport(ctx context.Context) (msg string, isErr bool) {
	gateStatus := "operating normally"
	if g.stateMachine != nil {
		switch g.stateMachine.State() {
		case StateAuthenticated:
			gateStatus = "operating normally"
		case StateUnauthenticated:
			if g.cfg.Identity.Strategy == "oidc-login" {
				gateStatus = "unauthenticated — use portcullis_login to log in"
				isErr = true
			} else {
				gateStatus = "operating normally"
			}
		case StateAuthenticating:
			gateStatus = "authenticating — login in progress"
		case StateSystemError:
			summary, _ := g.stateMachine.SystemError()
			gateStatus = "degraded — " + summary
			isErr = true
		}
	}

	keepStatus := pingReadiness(ctx, g.cfg.Peers.Keep.Endpoint)

	guardStatus := "not configured"
	if g.cfg.Peers.Guard.Endpoints.ApprovalUI != "" {
		guardStatus = pingReadiness(ctx, g.cfg.Peers.Guard.Endpoints.ApprovalUI)
	}

	msg = fmt.Sprintf(
		"Portcullis Gate:  %s\nPortcullis Keep:  %s\nPortcullis Guard: %s",
		gateStatus, keepStatus, guardStatus,
	)
	return msg, isErr
}
