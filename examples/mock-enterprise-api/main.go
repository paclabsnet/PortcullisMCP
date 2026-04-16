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

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// logRequests is HTTP middleware that logs all incoming request headers and body
// before passing the request to the MCP handler.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("mock-enterprise-api: incoming request %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		for name, vals := range r.Header {
			log.Printf("  header: %s: %s", name, strings.Join(vals, ", "))
		}
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			if len(body) > 0 {
				log.Printf("  body: %s", body)
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		next.ServeHTTP(w, r)
	})
}

// MockHTTPMCPServer is a simple HTTP MCP server for testing/demo purposes.
// It exposes a few example tools that represent enterprise resources.
func main() {
	impl := &mcp.Implementation{
		Name:    "mock-enterprise-api",
		Version: "1.0.0",
	}

	server := mcp.NewServer(impl, nil)
	api := &apiServer{}

	// Add enterprise API tools
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_customer",
		Description: "Retrieve customer information by ID",
	}, api.handleGetCustomer)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "update_order_status",
		Description: "Update the status of an order",
	}, api.handleUpdateOrder)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "query_inventory",
		Description: "Query product inventory levels",
	}, api.handleQueryInventory)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "delete_order",
		Description: "Delete an order (admin only)",
	}, api.handleDeleteOrder)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "query_order",
		Description: "Retrieve orders for a customer, optionally filtered by status",
	}, api.handleQueryOrder)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "update_customer",
		Description: "Update customer profile information such as email, name, or address",
	}, api.handleUpdateCustomer)

	mcp.AddTool(server, &mcp.Tool{
		Name: "echo_header",
		Description: "Echo back the identity of the caller. The caller's identity is injected " +
			"automatically by Portcullis via the X-User-Identity HTTP header — no arguments " +
			"are required from the AI agent.",
	}, api.handleEchoHeader)

	mcp.AddTool(server, &mcp.Tool{
		Name: "echo_user",
		Description: "Echo back the identity of the caller. The identity_jwt argument is injected " +
			"automatically by Portcullis and must NOT be provided or guessed by the AI agent — " +
			"leave it empty or omit it entirely.",
	}, api.handleEchoUser)

	// HTTP handler using Streamable HTTP transport (compatible with Keep's http backend type).
	// Wrapped with withIdentityHeader middleware so that the X-User-Identity header injected
	// by Portcullis Keep is available to tool handlers via context.
	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		log.Printf("MCP connection from %s", r.RemoteAddr)
		return server
	}, nil)
	http.Handle("/mcp", logRequests(mcpHandler))

	// Health endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	addr := ":3000"
	log.Printf("Mock HTTP MCP Server listening on http://localhost%s/mcp", addr)
	log.Printf("Available tools: get_customer, update_order_status, query_inventory, delete_order, query_order, update_customer, echo_user, echo_header")
	log.Printf("Health check: http://localhost%s/health", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}

type apiServer struct{}

type customerInput struct {
	CustomerID string `json:"customer_id"`
}

type orderInput struct {
	OrderID string `json:"order_id"`
	Status  string `json:"status"`
}

type inventoryInput struct {
	ProductSKU string `json:"product_sku"`
}

type deleteOrderInput struct {
	OrderID string `json:"order_id"`
}

type queryOrderInput struct {
	CustomerID string `json:"customer_id"`
	Status     string `json:"status,omitempty"` // optional filter: "pending", "shipped", "delivered", "cancelled"
}

type updateCustomerInput struct {
	CustomerID string `json:"customer_id"`
	Name       string `json:"name,omitempty"`
	Email      string `json:"email,omitempty"`
	Phone      string `json:"phone,omitempty"`
	Address    string `json:"address,omitempty"`
}

func (a *apiServer) handleGetCustomer(_ context.Context, _ *mcp.CallToolRequest, in customerInput) (*mcp.CallToolResult, any, error) {
	if in.CustomerID == "" {
		return nil, nil, fmt.Errorf("customer_id is required")
	}

	result := map[string]interface{}{
		"customer_id": in.CustomerID,
		"name":        "John Doe",
		"email":       "john.doe@example.com",
		"status":      "active",
		"created_at":  time.Now().Add(-365 * 24 * time.Hour).Format(time.RFC3339),
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(data)},
		},
	}, nil, nil
}

func (a *apiServer) handleUpdateOrder(_ context.Context, _ *mcp.CallToolRequest, in orderInput) (*mcp.CallToolResult, any, error) {
	if in.OrderID == "" {
		return nil, nil, fmt.Errorf("order_id is required")
	}
	if in.Status == "" {
		return nil, nil, fmt.Errorf("status is required")
	}

	result := map[string]interface{}{
		"order_id":   in.OrderID,
		"old_status": "pending",
		"new_status": in.Status,
		"updated_at": time.Now().Format(time.RFC3339),
		"message":    fmt.Sprintf("Order %s status updated to %s", in.OrderID, in.Status),
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(data)},
		},
	}, nil, nil
}

func (a *apiServer) handleQueryInventory(_ context.Context, _ *mcp.CallToolRequest, in inventoryInput) (*mcp.CallToolResult, any, error) {
	if in.ProductSKU == "" {
		return nil, nil, fmt.Errorf("product_sku is required")
	}

	result := map[string]interface{}{
		"product_sku":  in.ProductSKU,
		"available":    42,
		"reserved":     8,
		"warehouse":    "WH-001",
		"last_updated": time.Now().Format(time.RFC3339),
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(data)},
		},
	}, nil, nil
}

func (a *apiServer) handleQueryOrder(_ context.Context, _ *mcp.CallToolRequest, in queryOrderInput) (*mcp.CallToolResult, any, error) {
	if in.CustomerID == "" {
		return nil, nil, fmt.Errorf("customer_id is required")
	}

	orders := []map[string]interface{}{
		{
			"order_id":    "ORD-1042",
			"customer_id": in.CustomerID,
			"status":      "shipped",
			"total":       149.99,
			"items": []map[string]interface{}{
				{"sku": "WIDGET-A", "qty": 2, "unit_price": 49.99},
				{"sku": "GADGET-B", "qty": 1, "unit_price": 50.01},
			},
			"created_at": time.Now().Add(-72 * time.Hour).Format(time.RFC3339),
			"updated_at": time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
		},
		{
			"order_id":    "ORD-1051",
			"customer_id": in.CustomerID,
			"status":      "pending",
			"total":       29.95,
			"items": []map[string]interface{}{
				{"sku": "DOOHICKEY-C", "qty": 1, "unit_price": 29.95},
			},
			"created_at": time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
			"updated_at": time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
		},
	}

	if in.Status != "" {
		filtered := orders[:0]
		for _, o := range orders {
			if o["status"] == in.Status {
				filtered = append(filtered, o)
			}
		}
		orders = filtered
	}

	result := map[string]interface{}{
		"customer_id": in.CustomerID,
		"orders":      orders,
		"total_count": len(orders),
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

func (a *apiServer) handleUpdateCustomer(_ context.Context, _ *mcp.CallToolRequest, in updateCustomerInput) (*mcp.CallToolResult, any, error) {
	if in.CustomerID == "" {
		return nil, nil, fmt.Errorf("customer_id is required")
	}

	updated := map[string]interface{}{}
	if in.Name != "" {
		updated["name"] = in.Name
	}
	if in.Email != "" {
		updated["email"] = in.Email
	}
	if in.Phone != "" {
		updated["phone"] = in.Phone
	}
	if in.Address != "" {
		updated["address"] = in.Address
	}

	result := map[string]interface{}{
		"customer_id": in.CustomerID,
		"status":      "updated",
		"updated_fields": updated,
		"updated_at":  time.Now().Format(time.RFC3339),
		"message":     fmt.Sprintf("Customer %s profile updated successfully", in.CustomerID),
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

func (a *apiServer) handleEchoHeader(_ context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	var raw string
	if req.Extra != nil {
		raw = req.Extra.Header.Get("X-User-Identity")
	}
	if raw == "" {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: `{"error": "X-User-Identity header not present. To fix this, add the following to the mock-enterprise-api backend entry in Portcullis Keep's keep.yaml:\n\n  user_identity:\n    placement:\n      header: X-User-Identity"}`},
			},
		}, nil, nil
	}

	claims, err := unsafeDecodeJWTClaims(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("decode X-User-Identity JWT: %w", err)
	}

	username := ""
	for _, key := range []string{"preferred_username", "email", "sub"} {
		if v, ok := claims[key].(string); ok && v != "" {
			username = v
			break
		}
	}
	if username == "" {
		username = "(unknown — no preferred_username, email, or sub claim found)"
	}

	result := map[string]interface{}{
		"username": username,
		"claims":   claims,
	}
	data, _ := json.MarshalIndent(result, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

type echoUserInput struct {
	// IdentityJWT is injected by Portcullis (via user_identity.placement.json_path).
	// The AI agent must not supply this value.
	IdentityJWT string `json:"identity_jwt"`
}

func (a *apiServer) handleEchoUser(_ context.Context, _ *mcp.CallToolRequest, in echoUserInput) (*mcp.CallToolResult, any, error) {
	if in.IdentityJWT == "" {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: `{"error": "identity_jwt not provided — is Portcullis identity injection configured for this backend?"}`},
			},
		}, nil, nil
	}

	claims, err := unsafeDecodeJWTClaims(in.IdentityJWT)
	if err != nil {
		return nil, nil, fmt.Errorf("decode identity_jwt: %w", err)
	}

	// Extract the best available username from standard OIDC claims.
	username := ""
	for _, key := range []string{"preferred_username", "email", "sub"} {
		if v, ok := claims[key].(string); ok && v != "" {
			username = v
			break
		}
	}
	if username == "" {
		username = "(unknown — no preferred_username, email, or sub claim found)"
	}

	result := map[string]interface{}{
		"username": username,
		"claims":   claims,
	}
	data, _ := json.MarshalIndent(result, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

// unsafeDecodeJWTClaims decodes the claims segment of a JWT without verifying
// the signature. This is intentional for the mock server — real backends should
// always validate signatures.
func unsafeDecodeJWTClaims(raw string) (map[string]interface{}, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a valid JWT: expected 3 segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal JWT claims: %w", err)
	}
	return claims, nil
}

func (a *apiServer) handleDeleteOrder(_ context.Context, _ *mcp.CallToolRequest, in deleteOrderInput) (*mcp.CallToolResult, any, error) {
	if in.OrderID == "" {
		return nil, nil, fmt.Errorf("order_id is required")
	}

	result := map[string]interface{}{
		"order_id":   in.OrderID,
		"status":     "deleted",
		"deleted_at": time.Now().Format(time.RFC3339),
		"message":    fmt.Sprintf("Order %s has been permanently deleted", in.OrderID),
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(data)},
		},
	}, nil, nil
}
