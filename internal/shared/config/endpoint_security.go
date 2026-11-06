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

package config

import "fmt"

// ValidateEndpointSecurity enforces the production security rules that apply
// to every Portcullis service's server endpoints:
//
//   - Authentication must not be "none".
//   - Non-loopback endpoints must have TLS configured.
//
// It is called only when mode is "production"; callers are responsible for
// the mode guard. Returns the first validation error encountered.
func ValidateEndpointSecurity(endpoints map[string]EndpointConfig) error {
	for name, ep := range endpoints {
		if ep.Auth.Type == "none" {
			return fmt.Errorf("auth.type \"none\" for endpoint %q is not allowed in production mode", name)
		}
		if !IsLoopback(ep.Listen) && !ep.IsSecure() {
			return fmt.Errorf("TLS is required for non-loopback endpoint %q in production mode", name)
		}
	}
	return nil
}

// AnnotateEndpointPosture adds WARN posture findings for server endpoints that
// lack authentication or TLS. It is unconditional — callers apply any mode
// guard before calling. Property paths follow the convention used across all
// three Portcullis services: "server.endpoints.<name>.auth.type" and
// "server.endpoints.<name>.tls.cert".
func AnnotateEndpointPosture(report *PostureReport, endpoints map[string]EndpointConfig) {
	for name, ep := range endpoints {
		if ep.Auth.Type == "none" {
			report.SetStatus("server.endpoints."+name+".auth.type", "WARN",
				"Configure authentication for this endpoint in production")
		}
		if !ep.IsSecure() {
			report.SetStatus("server.endpoints."+name+".tls.cert", "WARN",
				"Enable TLS for this endpoint in production")
		}
	}
}
