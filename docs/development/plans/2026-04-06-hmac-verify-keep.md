# HMAC-Verify Identity Normalizer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Support HMAC-signed JWTs (HS256/HS384/HS512) as a user identity source in Keep, enabling integration with AWS AgentCore and other systems that issue HMAC tokens.

**Architecture:** Implement a new `Normalizer` in `portcullis-keep` that performs strict HMAC algorithm matching and signature verification, while adhering to the existing identity contract for claim stripping and token requirements.

**Tech Stack:** Go, `github.com/golang-jwt/jwt/v5`, `mitchellh/mapstructure`.

---

### Task 1: Update Shared Identity Configuration Schema

**Files:**
- Modify: `internal/shared/identity/identity.go`

- [ ] **Step 1: Add HMACVerifyConfig struct**

```go
// HMACVerifyConfig holds settings for the hmac-verify identity normalizer.
type HMACVerifyConfig struct {
	// Secret is the shared secret used for HMAC signature verification.
	// Supports envvar:// and vault:// URIs. Required.
	Secret string `yaml:"secret"`

	// Algorithm specifies the HMAC variant: "HS256", "HS384", or "HS512".
	// Defaults to "HS256" if empty.
	Algorithm string `yaml:"algorithm"`

	// Issuer is the optional expected iss claim value.
	Issuer string `yaml:"issuer"`

	// Audiences is an optional list of allowed audience (aud) values.
	Audiences []string `yaml:"audiences"`

	// AllowMissingExpiry defaults to false. If false, tokens without an exp claim are rejected.
	AllowMissingExpiry bool `yaml:"allow_missing_expiry"`

	// MaxTokenAgeSecs is the maximum allowed age of the token in seconds, measured from iat.
	MaxTokenAgeSecs int `yaml:"max_token_age_secs"`
}
```

- [ ] **Step 2: Update NormalizerConfig and Validation**

Add `HMACVerify HMACVerifyConfig` to `NormalizerConfig` (tagged `yaml:"-"`). Update `Validate()` to support `"hmac-verify"` and include it in error messages.

```go
type NormalizerConfig struct {
	Normalizer string `yaml:"normalizer"` // "passthrough" | "oidc-verify" | "hmac-verify"
	AcceptForgedIdentities bool `yaml:"accept_forged_identities"`
	OIDCVerify OIDCVerifyConfig `yaml:"oidc_verify"`
	HMACVerify HMACVerifyConfig `yaml:"-"` // Decoding handled via mapstructure
}

func (c NormalizerConfig) Validate() error {
	switch c.Normalizer {
	case "passthrough", "oidc-verify", "hmac-verify":
		// valid
	case "":
		return fmt.Errorf("identity.normalizer must be set; valid values: \"passthrough\", \"oidc-verify\", \"hmac-verify\"")
	default:
		return fmt.Errorf("invalid identity.normalizer %q: valid values: \"passthrough\", \"oidc-verify\", \"hmac-verify\"", c.Normalizer)
	}
	// ... existing OIDC validation ...
	if c.Normalizer == "hmac-verify" {
		if c.HMACVerify.Secret == "" {
			return fmt.Errorf("identity.hmac_verify.secret is required when normalizer is \"hmac-verify\"")
		}
		alg := strings.ToUpper(c.HMACVerify.Algorithm)
		if alg != "" && alg != "HS256" && alg != "HS384" && alg != "HS512" {
			return fmt.Errorf("invalid identity.hmac_verify.algorithm %q: must be HS256, HS384, or HS512", c.HMACVerify.Algorithm)
		}
	}
	return nil
}
```

- [ ] **Step 3: Update Build() error message**

Update the "unknown identity normalizer" error in `Build()` to include `"hmac-verify"`.

- [ ] **Step 4: Commit**

```bash
git add internal/shared/identity/identity.go
git commit -m "feat(shared): add HMACVerifyConfig and validation support"
```

---

### Task 2: Configure HMAC Decoding and Secret Allowlisting

**Files:**
- Modify: `internal/keep/config.go`

- [ ] **Step 1: Add HMAC secret to SecretAllowlist**

```go
var SecretAllowlist = []string{
	// ...
	"identity.config.secret",
}
```

- [ ] **Step 2: Add hmac-verify decoding to IdentityConfig.Validate()**

```go
func (c *IdentityConfig) Validate() error {
	// ... existing switch ...
		case "hmac-verify":
			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				Result:  &c.Normalizer.HMACVerify,
				TagName: "yaml",
			})
			if err != nil {
				return err
			}
			if err := decoder.Decode(c.Config); err != nil {
				return fmt.Errorf("decode identity.config for hmac-verify: %w", err)
			}
	// ...
}
```

- [ ] **Step 3: Update Posture Warnings**

Update the warning at `config.go:142` to suggest both alternatives.

```go
if c.Identity.Strategy == "passthrough" {
    report.SetStatus("identity.strategy", "WARN", "Passthrough identity is not suitable for production; use oidc-verify or hmac-verify")
}
```

- [ ] **Step 4: Commit**

```bash
git add internal/keep/config.go
git commit -m "feat(keep): enable hmac-verify config decoding and secret allowlisting"
```

---

### Task 3: Implement HMAC Normalizer Registration

**Files:**
- Modify: `internal/keep/identity.go`

- [ ] **Step 1: Register hmac-verify in init()**

```go
func init() {
	// ... existing registrations ...
	identity.Register("hmac-verify", func(cfg identity.NormalizerConfig) (identity.Normalizer, error) {
		hcfg := cfg.HMACVerify
		if hcfg.Secret == "" {
			return nil, fmt.Errorf("normalizer hmac-verify requires identity.hmac_verify.secret to be set")
		}
		var method jwt.SigningMethod
		alg := strings.ToUpper(hcfg.Algorithm)
		if alg == "" {
			alg = "HS256"
		}
		switch alg {
		case "HS256":
			method = jwt.SigningMethodHS256
		case "HS384":
			method = jwt.SigningMethodHS384
		case "HS512":
			method = jwt.SigningMethodHS512
		default:
			return nil, fmt.Errorf("unsupported HMAC algorithm %q", hcfg.Algorithm)
		}
		return &hmacVerifyingNormalizer{
			method:             method,
			secret:             []byte(hcfg.Secret),
			issuer:             hcfg.Issuer,
			audiences:          hcfg.Audiences,
			allowMissingExpiry: hcfg.AllowMissingExpiry,
			maxTokenAgeSecs:    hcfg.MaxTokenAgeSecs,
		}, nil
	})
}
```

- [ ] **Step 2: Add hmacVerifyingNormalizer struct**

```go
type hmacVerifyingNormalizer struct {
	method             jwt.SigningMethod
	secret             []byte
	issuer             string
	audiences          []string
	allowMissingExpiry bool
	maxTokenAgeSecs    int
}
```

- [ ] **Step 3: Commit**

```bash
git add internal/keep/identity.go
git commit -m "feat(keep): register hmac-verify normalizer and define struct"
```

---

### Task 4: Implement HMAC Normalize Logic (Strict Algorithm & Hard Failure)

**Files:**
- Modify: `internal/keep/identity.go`

- [ ] **Step 1: Implement Normalize()**

Implement the logic as defined in the "Runtime Identity Contract":
1. Check `SourceType` (must be `"oidc"` or `"hmac"`, else return stripped `Principal`).
2. Check `RawToken` presence (error if missing).
3. Verify `alg` header matches `n.method.Alg()` exactly (hard error if mismatch).
4. Parse and verify signature using `jwt.Parse` (hard error if verification fails).
5. Validate claims (`iss`, `aud`, `exp`, `iat` age). Expiry and age violations are hard errors.
6. Extract and return `shared.Principal`.

- [ ] **Step 2: Commit**

```bash
git add internal/keep/identity.go
git commit -m "feat(keep): implement strict HMAC normalization logic"
```

---

### Task 5: Add Normalizer Behavior Tests

**Files:**
- Modify: `internal/keep/identity_test.go`

- [ ] **Step 1: Add signHMAC helper**

```go
func signHMAC(t *testing.T, secret []byte, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	s, err := token.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
```

- [ ] **Step 2: Implement table-driven tests**

Add `TestHMACVerifyingNormalizer` covering all cases in the design spec table (Valid HS256/384/512, Wrong secret, Algorithm mismatch, Malformed JWT, Non-HMAC SourceType, etc.).

- [ ] **Step 3: Run tests**

Run: `go test -v ./internal/keep -run TestHMACVerifyingNormalizer`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/keep/identity_test.go
git commit -m "test(keep): add comprehensive HMAC normalizer behavior tests"
```

---

### Task 6: Add Config-Layer Validation Tests

**Files:**
- Modify: `internal/keep/config_test.go`

- [ ] **Step 1: Add configuration validation tests**

Test that `hmac-verify` is accepted, secret is required, algorithm is validated, and posture warnings are correct.

- [ ] **Step 2: Run tests**

Run: `go test -v ./internal/keep -run TestConfig`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/keep/config_test.go
git commit -m "test(keep): add hmac-verify config validation tests"
```

---

### Task 7: Update Integration Documentation

**Files:**
- Modify: `docs/AWS-bedrock-portcullis-integration.md`

- [ ] **Step 1: Refine HMAC documentation**

Update the "Note for Portcullis Admins" section to accurately reflect the implemented `hmac-verify` strategy.

- [ ] **Step 2: Commit**

```bash
git add docs/AWS-bedrock-portcullis-integration.md
git commit -m "docs: update AWS integration guide for hmac-verify"
```
