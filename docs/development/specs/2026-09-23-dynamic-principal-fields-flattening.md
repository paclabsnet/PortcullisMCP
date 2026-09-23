# Specification: Dynamic Principal Fields and Serialization

> **Feature:** Enable dynamic, customer-configurable identity attributes within the Portcullis `Principal` struct, utilizing custom JSON flattening serialization to expose these attributes as first-class fields to Policy Decision Points (PDPs) without requiring code plugins or custom compilation.

---

## 1. Goal

Portcullis-Keep is designed to normalize user identity into a standard `Principal` structure. However, enterprise and government customers often have highly custom identity architectures containing security classifications (e.g., `clearance_level`), department sub-units, or physical locations (e.g., `facility`). 

To avoid the operational overhead of custom plugins, dynamic claims must be supportable out-of-the-box. This specification defines how arbitrary claims can be parsed from a JWT or returned by an identity normalization webhook, stored within a dynamic `Attributes` map, and serialized transparently into a flat JSON representation so policy engines (such as Open Policy Agent or Cedar) can query them directly using simple paths (e.g., `input.principal.clearance`).

---

## 2. Architecture

### A. Separation of Standard and Dynamic Fields
The `shared.Principal` struct (defined in `internal/shared/types.go`) will retain its first-class, high-frequency, strongly typed fields for core system operations (e.g., caching, tenancy, standard auditing). An `Attributes` map of type `map[string]any` is introduced to hold all dynamic, client-defined claims.

```go
type Principal struct {
	UserID            string         `json:"user_id"`
	Email             string         `json:"email,omitempty"`
	DisplayName       string         `json:"display_name,omitempty"`
	Groups            []string       `json:"groups,omitempty"`
	Roles             []string       `json:"roles,omitempty"`
	Department        string         `json:"department,omitempty"`
	AuthMethod        []string       `json:"auth_method,omitempty"`
	PreferredUsername string         `json:"preferred_username,omitempty"`
	ACR               string         `json:"acr,omitempty"`
	TokenExpiry       int64          `json:"token_expiry,omitempty"`
	SourceType        string         `json:"source_type"`
	
	// Attributes stores arbitrary custom claims parsed from OIDC/HMAC tokens or webhooks
	Attributes        map[string]any `json:"attributes,omitempty"`
}
```

### B. Custom JSON Flattening Serialization
When Keep forwards the authorization request to the PDP, or when Gate evaluates tabular rules, the `Principal` is serialized to JSON. 

Rather than exposing a nested `attributes` key (e.g., `principal.attributes.clearance`), a custom `MarshalJSON` implementation will dynamically merge the entries of `Attributes` into the top-level JSON representation. This maintains path symmetry and keeps policies clean.

```go
func (p Principal) MarshalJSON() ([]byte, error) {
	// Avoid infinite recursion by casting to a type alias
	type Alias Principal
	standardBytes, err := json.Marshal(Alias(p))
	if err != nil {
		return nil, fmt.Errorf("marshal standard principal fields: %w", err)
	}

	var merged map[string]any
	if err := json.Unmarshal(standardBytes, &merged); err != nil {
		return nil, fmt.Errorf("unmarshal standard fields for merging: %w", err)
	}

	// Dynamic attributes are merged directly into the top-level JSON object
	for k, v := range p.Attributes {
		// Prevent accidental/malicious overwrite of core, statically-typed fields
		if _, reserved := merged[k]; !reserved {
			merged[k] = v
		}
	}

	// Clean up the nested "attributes" key in the output to avoid duplicate paths
	delete(merged, "attributes")

	return json.Marshal(merged)
}
```

### C. Transparent JSON Deserialization
When retrieving a `Principal` from the Redis cache or parsing the response from an identity normalization webhook, the JSON payload must be unmarshaled back into the Go struct. Unmapped fields must automatically route into the `Attributes` map instead of being silently ignored.

```go
func (p *Principal) UnmarshalJSON(data []byte) error {
	// Unmarshal all standard fields using a type alias
	type Alias Principal
	var temp Alias
	if err := json.Unmarshal(data, &temp); err != nil {
		return fmt.Errorf("unmarshal standard principal fields: %w", err)
	}
	*p = Principal(temp)

	// Unmarshal everything into a generic map to capture extra attributes
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("unmarshal generic principal map: %w", err)
	}

	// Filter out keys that match the JSON tags of statically-typed fields
	reservedKeys := map[string]bool{
		"user_id":            true,
		"email":              true,
		"display_name":       true,
		"groups":             true,
		"roles":              true,
		"department":         true,
		"auth_method":        true,
		"preferred_username": true,
		"acr":                true,
		"token_expiry":       true,
		"source_type":        true,
		"attributes":         true, // ensure the literal attributes key is ignored
	}

	p.Attributes = make(map[string]any)
	for k, v := range raw {
		if !reservedKeys[k] {
			p.Attributes[k] = v
		}
	}

	return nil
}
```

---

## 3. Core Component Flow

### A. OIDC/HMAC Token Extraction in Keep
When parsing claims from a cryptographically validated JWT inside Keep (`internal/keep/identity.go`), the token verifier will map standard claims to typed fields. If a list of `custom_claims` is configured, Keep will look up these keys in the validated JWT claims and write them to the `Attributes` map.

```go
// In hmacVerifyingNormalizer and oidcVerifyingNormalizer
func (n *oidcVerifyingNormalizer) extractCustomClaims(claims map[string]any) map[string]any {
	if len(n.customClaims) == 0 {
		return nil
	}
	attrs := make(map[string]any)
	for _, key := range n.customClaims {
		if val, exists := claims[key]; exists {
			attrs[key] = val
		}
	}
	return attrs
}
```

### B. Identity Normalization Webhook
The identity normalization webhook client (`internal/keep/identity_webhook.go`) currently decodes the webhook's response directly into a `shared.Principal` struct. 

By defining the custom `UnmarshalJSON` method on `Principal`, the webhook response can contain any custom fields, and they will automatically populate `Principal.Attributes` without modification to the webhook client logic.

### C. Validation & Defense-in-Depth
To protect against Resource Exhaustion (DoS) and JSON injection attacks, we will expand Keep's Principal validation checks (`ValidatePrincipal` or similar) to enforce limits on dynamic attributes:

1.  **Keys Limit**: The number of dynamic attributes in `Attributes` cannot exceed `max_custom_attributes_count` (default: `20`).
2.  **Value Size**: The serialized JSON size of any single dynamic attribute value cannot exceed `max_custom_attribute_bytes` (default: `4096` bytes).
3.  **No Recursive Deep Nesting**: Deeply nested JSON structures can crash the JSON unmarshaler. We enforce a maximum value nesting depth of `3`.

---

## 4. Configuration Schema Changes

No change is required to the `Principal` serialization JSON output, keeping downstream systems fully backward-compatible. We introduce configuration options inside `keep-config.yaml` to specify which dynamic claims to extract from incoming JWTs:

```yaml
# keep-config.yaml
identity:
  strategy: "oidc-verify"
  config:
    issuer: "https://idp.corp.com"
    jwks_url: "https://idp.corp.com/keys"

    # Dynamic claim extraction
    # Keep will look for these claims in the validated JWT and place them in Principal.Attributes
    custom_claims:
      - "clearance_level"
      - "facility_id"
      - "project_codes"

    # Resource exhaustion guards
    max_custom_attributes_count: 20
    max_custom_attribute_bytes: 4096
```

---

## 5. Verification Plan

### A. Unit Testing Strategy (`internal/shared/types_test.go`)
1.  **TestMarshalPrincipal**:
    *   Initialize `shared.Principal` with standard fields and dynamic attributes (`clearance_level: "top-secret"`, `project_codes: ["omega", "alpha"]`).
    *   Marshal to JSON and assert that the output contains standard fields and custom attributes **flattened at the top level** (no nested `"attributes"` block).
    *   Assert that standard fields cannot be overwritten by keys inside `Attributes`.
2.  **TestUnmarshalPrincipal**:
    *   Provide a flat JSON payload containing standard and custom fields.
    *   Unmarshal into `shared.Principal`.
    *   Assert that standard fields populate the struct fields directly, and custom fields populate the `Attributes` map.
    *   Verify type preservation (e.g., lists unmarshal to `[]any`, numbers to `float64`/`json.Number`).

### B. Integration Testing Strategy
Verify that Keep's OIDC normalizer successfully extracts configured custom claims, stores them in the principal cache (proving cache serialization works), and successfully forwards them to policy files in `policies/rego/`.
