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

package guard

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// sessionContextKey is the context key used to pass the AuthSession to handlers.
type sessionContextKey struct{}

// sessionFromContext retrieves the AuthSession stored by AuthMiddleware.
// Returns nil if OIDC is not enabled or the session is not present.
func sessionFromContext(ctx context.Context) *AuthSession {
	s, _ := ctx.Value(sessionContextKey{}).(*AuthSession)
	return s
}

// AuthMiddleware returns an HTTP middleware that enforces OIDC session authentication.
// It checks the portcullis_session cookie, validates and refreshes the session as needed,
// and redirects unauthenticated requests to GET /auth/login (which immediately starts
// the PKCE flow — no interstitial page).
//
// On success it stores the AuthSession in the request context for downstream handlers.
func AuthMiddleware(store AuthStore, oidc *OIDCManager, crypto *CookieCrypto, cfg IdentityConfig) func(http.Handler) http.Handler {
	idleTimeout := time.Duration(cfg.Config.Session.IdleTimeoutMins) * time.Minute
	maxLifetime := time.Duration(cfg.Config.Session.MaxLifetimeHours) * time.Hour

	if idleTimeout == 0 {
		idleTimeout = 30 * time.Minute
	}
	if maxLifetime == 0 {
		maxLifetime = 24 * time.Hour
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionID, err := GetSessionCookie(r, crypto)
			if err != nil {
				// Tampered or unreadable cookie — clear it and restart login.
				slog.Warn("guard/auth: invalid session cookie", "error", err)
				ClearSessionCookie(w)
				redirectToLogin(w, r)
				return
			}
			if sessionID == "" {
				redirectToLogin(w, r)
				return
			}

			sess, err := store.GetSession(r.Context(), sessionID)
			if err != nil {
				slog.Error("guard/auth: session lookup error", "error", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if sess == nil {
				ClearSessionCookie(w)
				redirectToLogin(w, r)
				return
			}

			now := time.Now()

			// Enforce absolute maximum lifetime.
			if now.Sub(sess.CreatedAt) > maxLifetime {
				slog.Info("guard/auth: session exceeded max lifetime", "session_id", sessionID)
				_ = store.DeleteSession(r.Context(), sessionID)
				ClearSessionCookie(w)
				redirectToLogin(w, r)
				return
			}

			// Enforce idle timeout.
			if now.Sub(sess.LastActiveAt) > idleTimeout {
				slog.Info("guard/auth: session idle timeout", "session_id", sessionID)
				_ = store.DeleteSession(r.Context(), sessionID)
				ClearSessionCookie(w)
				redirectToLogin(w, r)
				return
			}

			// On-demand token refresh if the ID token has expired.
			if now.After(sess.Tokens.Expiry) && sess.Tokens.RefreshToken != "" {
				newTokens, refreshErr := oidc.DoRefresh(r.Context(), sess.Tokens.RefreshToken)
				if refreshErr != nil {
					if IsInvalidGrant(refreshErr) {
						slog.Info("guard/auth: refresh token expired, terminating session", "session_id", sessionID)
					} else {
						slog.Warn("guard/auth: token refresh failed", "session_id", sessionID, "error", refreshErr)
					}
					_ = store.DeleteSession(r.Context(), sessionID)
					ClearSessionCookie(w)
					redirectToLogin(w, r)
					return
				}
				sess.Tokens = *newTokens
				sess.LastActiveAt = now
				if storeErr := store.StoreSession(r.Context(), *sess); storeErr != nil {
					slog.Error("guard/auth: failed to persist refreshed session", "error", storeErr)
				}
			} else {
				// Update activity timestamp.
				if updateErr := store.UpdateSessionActivity(r.Context(), sessionID); updateErr != nil {
					slog.Warn("guard/auth: failed to update session activity", "error", updateErr)
				}
			}

			ctx := context.WithValue(r.Context(), sessionContextKey{}, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// redirectToLogin captures the current request path as return_path and redirects
// to GET /auth/login, which immediately initiates the PKCE flow.
func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	returnPath := validateReturnPath(r.URL.RequestURI())
	target := "/auth/login"
	if returnPath != "" {
		target += "?return_path=" + returnPath
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// validateReturnPath ensures the return_path is a safe same-origin relative path.
// It must start with "/" but not "//" (protocol-relative), and must match one of
// the known UI routes. Returns "" if the path is invalid, causing the caller to
// fall back to the default (/approve).
func validateReturnPath(raw string) string {
	if raw == "" {
		return ""
	}
	// Must be a relative path starting with "/" but not "//".
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return ""
	}
	// Restrict to known UI routes.
	path := raw
	if idx := strings.IndexByte(raw, '?'); idx != -1 {
		path = raw[:idx]
	}
	switch path {
	case "/approve":
		return raw
	default:
		return ""
	}
}
