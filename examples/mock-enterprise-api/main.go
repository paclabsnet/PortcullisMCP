package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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

	// HTTP handler using Streamable HTTP transport (compatible with Keep's http backend type)
	handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		log.Printf("MCP connection from %s", r.RemoteAddr)
		return server
	}, nil)
	http.Handle("/mcp", handler)

	// Health endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	addr := ":3000"
	log.Printf("Mock HTTP MCP Server listening on http://localhost%s/mcp", addr)
	log.Printf("Available tools: get_customer, update_order_status, query_inventory, delete_order")
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
