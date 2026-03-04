package portcullis

import future.keywords.if
import future.keywords.in

# Default decision is deny
default decision := {
    "decision": "deny",
    "reason": "no policy matched"
}

# ============================================================================
# Local Filesystem Rules (handled by Gate fast-path, these won't reach Keep)
# ============================================================================

# Allow filesystem reads in the current directory
decision := {"decision": "allow", "reason": "filesystem read allowed"} if {
    input.tool_name == "read_file"
    input.server_name == "filesystem"
}

decision := {"decision": "allow", "reason": "filesystem list allowed"} if {
    input.tool_name == "list_directory"
    input.server_name == "filesystem"
}

# Require escalation for write operations
decision := {"decision": "escalate", "reason": "write operations require approval"} if {
    input.tool_name == "write_file"
    input.server_name == "filesystem"
}

# Deny access to protected paths
decision := {"decision": "deny", "reason": "access to .git is forbidden"} if {
    input.arguments.path
    startswith(input.arguments.path, ".git")
}

decision := {"decision": "deny", "reason": "access to .portcullis is forbidden"} if {
    input.arguments.path
    startswith(input.arguments.path, ".portcullis")
}

# ============================================================================
# Enterprise HTTP MCP Backend Rules (mock-enterprise-api)
# ============================================================================

# Allow read operations on customer data
decision := {"decision": "allow", "reason": "customer read allowed"} if {
    input.tool_name == "get_customer"
    input.server_name == "mock-enterprise-api"
}

# Allow inventory queries for all users
decision := {"decision": "allow", "reason": "inventory query allowed"} if {
    input.tool_name == "query_inventory"
    input.server_name == "mock-enterprise-api"
}

# Require escalation for order modifications
decision := {"decision": "escalate", "reason": "order updates require manager approval"} if {
    input.tool_name == "update_order_status"
    input.server_name == "mock-enterprise-api"
}

# ============================================================================
# Tool Discovery
# ============================================================================

# Allow list_tools for discovery
decision := {"decision": "allow", "reason": "tool discovery allowed"} if {
    input.tool_name == "list_tools"
}
