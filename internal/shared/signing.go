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

package shared

// SigningConfig holds an HMAC key and a token TTL in seconds.
// It is shared by portcullis-keep (escalation request signing) and
// portcullis-guard (escalation token signing).
type SigningConfig struct {
	Key string `yaml:"key"` // HMAC secret; reference a secret URI with envvar:// or vault://
	TTL int    `yaml:"ttl"` // token TTL in seconds; 0 means use the service default
}
