# Dynamic Principal Fields & Serialization Implementation Tracking - 2026-09-23

## Current Status
- [x] Complete architectural research of dynamic Principal extension patterns
- [x] Write design specification (`docs/development/specs/2026-09-23-dynamic-principal-fields-flattening.md`)
- [ ] Implement Task 1: Update `shared.Principal` with custom JSON marshalling/unmarshalling in `internal/shared/types.go`
- [ ] Implement Task 2: Add dynamic custom claims extraction to OIDC/HMAC normalizers in `internal/keep/identity.go`
- [ ] Implement Task 3: Expand Keep Configuration schema for `custom_claims`
- [ ] Implement Task 4: Enhance Keep's Principal validation checks with resource-exhaustion guards
- [ ] Implement Task 5: Add complete unit test coverage to types and identity normalizers

## Completed Tasks
- **2026-09-23**: Conducted design research and saved the design specification document `docs/development/specs/2026-09-23-dynamic-principal-fields-flattening.md`.

## Next Steps
- When the user issues a directive to proceed with implementation, start Task 1 (implementing the custom JSON marshalling/unmarshalling for `Principal` inside `internal/shared/types.go`).
