package keep

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// PolicyDecisionPoint evaluates an enriched MCP request and returns a decision.
type PolicyDecisionPoint interface {
	Evaluate(ctx context.Context, req shared.EnrichedMCPRequest) (shared.PDPResponse, error)
}

// opaClient calls the OPA REST API to evaluate policy.
type opaClient struct {
	endpoint string
	client   *http.Client
}

// NewOPAClient creates a PolicyDecisionPoint backed by an OPA REST endpoint.
// endpoint should be the full URL to the OPA data path, e.g.:
//
//	http://opa.internal:8181/v1/data/portcullis/decision
func NewOPAClient(endpoint string) PolicyDecisionPoint {
	return &opaClient{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// opaRequest is the envelope OPA expects: {"input": <payload>}.
type opaRequest struct {
	Input shared.EnrichedMCPRequest `json:"input"`
}

// opaResponse is the envelope OPA returns: {"result": <decision>}.
type opaResponse struct {
	Result struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	} `json:"result"`
}

// Evaluate sends the enriched request to OPA and returns the PDP decision.
func (c *opaClient) Evaluate(ctx context.Context, req shared.EnrichedMCPRequest) (shared.PDPResponse, error) {
	body, err := json.Marshal(opaRequest{Input: req})
	if err != nil {
		return shared.PDPResponse{}, fmt.Errorf("marshal opa request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return shared.PDPResponse{}, fmt.Errorf("build opa request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return shared.PDPResponse{}, fmt.Errorf("%w: %s", shared.ErrPDPUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return shared.PDPResponse{}, fmt.Errorf("%w: opa returned %d", shared.ErrPDPUnavailable, resp.StatusCode)
	}

	var opaResp opaResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return shared.PDPResponse{}, fmt.Errorf("decode opa response: %w", err)
	}

	decision := opaResp.Result.Decision
	if decision == "" {
		// OPA returned an empty result — treat as deny (safe default).
		decision = "deny"
	}

	return shared.PDPResponse{
		Decision: decision,
		Reason:   opaResp.Result.Reason,
	}, nil
}
