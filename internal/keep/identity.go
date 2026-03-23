package keep

import (
	"log/slog"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// normalizeIdentity enforces Keep's identity policy on an incoming request and
// returns the identity that should be forwarded to the PDP.
//
// In strict mode (the default), OS-sourced identity is reduced to the user_id
// field only. Groups, roles, department, auth_method, and raw_token are all
// cleared because Gate derives them from the local OS — they are trivially
// forgeable and carry no enterprise verification. The PDP will see a principal
// with a user_id but no directory claims, which naturally produces a deny or
// escalate outcome for any policy that requires group membership.
//
// In demo mode, identity is accepted as supplied. A warning is logged on every
// request unless cfg.AcceptForgedIdentities is true, so operators are always
// aware when the deployment is running without identity enforcement.
func normalizeIdentity(id shared.UserIdentity, cfg IdentityConfig) shared.UserIdentity {
	if id.SourceType != "os" {
		// OIDC-sourced or other verified identity — pass through unchanged.
		return id
	}

	mode := cfg.Mode
	if mode == "" {
		mode = "strict"
	}

	switch mode {
	case "strict":
		// Retain only the user_id and source_type so the PDP has a principal
		// to evaluate against, but strip all directory claims that Gate cannot
		// have verified.
		slog.Warn("keep: os-sourced identity received in strict mode — "+
			"directory claims stripped; configure identity.mode=demo for local evaluation",
			"user_id", id.UserID,
		)
		return shared.UserIdentity{
			UserID:     id.UserID,
			SourceType: id.SourceType,
		}

	case "demo":
		if !cfg.AcceptForgedIdentities {
			slog.Warn("keep: accepting os-sourced identity in demo mode — "+
				"identity claims are unverified and MUST NOT be used in production; "+
				"set identity.accept_forged_identities=true to suppress this warning",
				"user_id", id.UserID,
				"groups", id.Groups,
			)
		}
		return id

	default:
		slog.Error("keep: unknown identity mode, defaulting to strict", "mode", mode)
		return shared.UserIdentity{
			UserID:     id.UserID,
			SourceType: id.SourceType,
		}
	}
}
