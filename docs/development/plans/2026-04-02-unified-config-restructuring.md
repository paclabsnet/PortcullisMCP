# Unified Peer Model Configuration Migration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update all remaining YAML configuration files in `config/` and `deploy/docker-sandbox/` to the new Unified Peer Model structure.

**Architecture:** Standardize configuration across Gate, Keep, and Guard services into a consistent schema featuring `server.endpoints`, `identity`, `peers`, `responsibility`, and `operations` blocks. This simplifies configuration management and enables shared infrastructure for secrets resolution, telemetry, and logging.

**Tech Stack:** YAML, Go (internal/shared/config)

---

### Task 1: Update Portcullis-Gate Configurations

**Files:**
- Modify: `config/gate-config.minimal-oidc-file.yaml`
- Modify: `config/gate-config.minimal-oidc-login.yaml`
- Modify: `config/gate-config.minimal.yaml`
- Modify: `deploy/docker-sandbox/gate-demo.yaml`

- [ ] **Step 1: Update `config/gate-config.minimal-oidc-file.yaml`**
- [ ] **Step 2: Update `config/gate-config.minimal-oidc-login.yaml`**
- [ ] **Step 3: Update `config/gate-config.minimal.yaml`**
- [ ] **Step 4: Update `deploy/docker-sandbox/gate-demo.yaml`**

### Task 2: Update Portcullis-Keep Configurations

**Files:**
- Modify: `config/keep-config.minimal-oidc.yaml`
- Modify: `config/keep-config.minimal.yaml`
- Modify: `config/keep-config.mock-workflow.yaml`
- Modify: `deploy/docker-sandbox/keep-demo.yaml`

- [ ] **Step 1: Update `config/keep-config.minimal-oidc.yaml`**
- [ ] **Step 2: Update `config/keep-config.minimal.yaml`**
- [ ] **Step 3: Update `config/keep-config.mock-workflow.yaml`**
- [ ] **Step 4: Update `deploy/docker-sandbox/keep-demo.yaml`**

### Task 3: Update Portcullis-Guard Configurations

**Files:**
- Modify: `config/guard-config.minimal.yaml`
- Modify: `deploy/docker-sandbox/guard-demo.yaml`

- [ ] **Step 1: Update `config/guard-config.minimal.yaml`**
- [ ] **Step 2: Update `deploy/docker-sandbox/guard-demo.yaml`**

### Task 4: Verification

- [ ] **Step 1: Run Gate config validation tests**
- [ ] **Step 2: Run Keep config validation tests**
- [ ] **Step 3: Run Guard config validation tests**
