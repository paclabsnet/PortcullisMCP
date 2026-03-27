# Mock HTTP MCP Server

This is a simple HTTP MCP server for testing and demonstrating PortcullisMCP with enterprise backends.

## Purpose

In enterprise environments, MCP backends are typically HTTP services (not stdio processes). This mock server:

- Exposes MCP tools via Streamable HTTP transport (current MCP standard)
- Simulates enterprise APIs (customer data, orders, inventory)
- Demonstrates policy enforcement for different operation types

## Running

```powershell
go run ./examples/mock-enterprise-api
```

The server starts on `http://localhost:3000/mcp`

## Available Tools

### `get_customer`
**Description:** Retrieve customer information by ID  
**Arguments:**
- `customer_id` (string, required): The customer ID to look up

**Policy:** Allowed for all users (read operation)

### `query_inventory`
**Description:** Query product inventory levels  
**Arguments:**
- `product_sku` (string, required): Product SKU to query

**Policy:** Allowed for all users (read operation)

### `update_order_status`
**Description:** Update the status of an order  
**Arguments:**
- `order_id` (string, required): The order ID to update
- `status` (string, required): New status (pending, shipped, delivered)

**Policy:** Requires escalation (write operation needs approval)

## Architecture

```
Agent → Gate → Keep → OPA (policy decision) → Mock HTTP MCP Server
                                              (this service)
```

This demonstrates the full enterprise flow:
1. Agent requests a tool call
2. Gate forwards to Keep
3. Keep checks policy with OPA
4. If allowed, Keep routes to this HTTP MCP backend
5. Backend returns results through the chain

## Customization

Modify `main.go` to add your own tools that represent your enterprise's APIs, databases, or services.
