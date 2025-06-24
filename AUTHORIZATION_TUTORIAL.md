# Authorization Models Tutorial: A Complete Beginner's Guide

**Multi-Model Authorization Microservice**  
*Licensed under the MIT License - see [LICENSE](LICENSE) for details*

## Table of Contents

- [Introduction](#introduction)
- [What is Authorization?](#what-is-authorization)
- [Company Scenario: TechCorp Inc.](#company-scenario-techcorp-inc)
- [Getting Started](#getting-started)
- [Tutorial 1: ACL (Access Control List)](#tutorial-1-acl-access-control-list)
- [Tutorial 2: RBAC (Role-Based Access Control)](#tutorial-2-rbac-role-based-access-control)
- [Tutorial 3: ABAC (Attribute-Based Access Control)](#tutorial-3-abac-attribute-based-access-control)
- [Tutorial 4: ReBAC (Relationship-Based Access Control)](#tutorial-4-rebac-relationship-based-access-control)
- [Comparison and When to Use Each Model](#comparison-and-when-to-use-each-model)
- [Next Steps](#next-steps)

## Introduction

Welcome to the complete beginner's guide to auÏthorization systems! This tutorial will teach you about four different authorization models using a practical company scenario. By the end of this guide, you'll understand when and how to use ACL, RBAC, ABAC, and ReBAC authorization systems.

## What is Authorization?

**Authorization** is the process of determining whether a user has permission to perform a specific action on a specific resource. It answers the question: "Is Alice allowed to read the sales report?"

Think of it like a security guard at a building:

- **Authentication**: "Who are you?" (showing your ID)
- **Authorization**: "What are you allowed to do here?" (checking if you can access the 10th floor)

### The Four Authorization Models

1. **ACL (Access Control List)**: Direct user-to-resource permissions
2. **RBAC (Role-Based Access Control)**: Users have roles, roles have permissions
3. **ABAC (Attribute-Based Access Control)**: Decisions based on user, resource, and context attributes
4. **ReBAC (Relationship-Based Access Control)**: Permissions based on relationships between entities

## Company Scenario: TechCorp Inc.

Let's imagine **TechCorp Inc.**, a software company with the following structure:

### Employees

- **Alice**: CEO
- **Bob**: Engineering Manager
- **Charlie**: Software Engineer
- **Diana**: HR Manager
- **Eve**: Sales Representative
- **Frank**: Junior Developer

### Departments

- **Engineering**: Bob (Manager), Charlie (Engineer), Frank (Junior)
- **HR**: Diana (Manager)
- **Sales**: Eve (Representative)
- **Executive**: Alice (CEO)

### Company Files

- **company_strategy.pdf**: Confidential strategic planning document
- **employee_records.xlsx**: HR employee data
- **source_code.zip**: Engineering source code
- **sales_reports.pdf**: Monthly sales data
- **public_handbook.pdf**: Company handbook (public)
- **engineering_docs.md**: Technical documentation

## Getting Started

### Prerequisites

1. The authorization service is running on `http://localhost:8080`
2. You have `curl` installed for making API requests

### Start the Service

```bash
# Option 1: Run directly
go run ./main.go

# Option 2: Build and run
go build -o casbin-server ./main.go
./casbin-server
```

### Verify the Service is Running

```bash
curl http://localhost:8080/api/v1/health
```

Expected response:

```json
{
  "status": "healthy",
  "service": "multi-model-casbin-auth-service",
  "supported_models": ["acl", "rbac", "abac", "rebac"],
  "default_model": "rbac",
  "database": "sqlite",
  "version": "2.0.0",
  "rebac_features": ["ownership", "hierarchy", "groups", "social"]
}
```

### Check Available Models

```bash
curl http://localhost:8080/api/v1/models
```

Expected response:

```json
{
  "models": [
    {
      "name": "acl",
      "description": "Access Control List - Direct user-resource mapping",
      "usage": "Small-scale systems, simple permission management"
    },
    {
      "name": "rbac",
      "description": "Role-Based Access Control - Role-based authorization",
      "usage": "Enterprise systems, organizational permission management"
    },
    {
      "name": "abac",
      "description": "Attribute-Based Access Control - Attribute-based authorization",
      "usage": "Advanced security, dynamic permission control"
    },
    {
      "name": "rebac",
      "description": "Relationship-Based Access Control - Graph-based authorization",
      "usage": "Social media, collaboration platforms, hierarchical organizations"
    }
  ],
  "default": "rbac"
}
```

## Tutorial 1: ACL (Access Control List)

**ACL** is the simplest authorization model. It directly maps users to specific permissions on specific resources.

**Use Case**: Perfect for small companies or simple scenarios where you want direct control over who can access what.

### Scenario

At TechCorp, we want to give specific permissions to individual employees:

### Step 1: Add ACL Policies

Let's give Alice (CEO) access to the strategic planning document:

```bash
curl -X POST http://localhost:8080/api/v1/acl/policies \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "alice",
    "object": "company_strategy.pdf",
    "action": "read"
  }'
```

Expected response:

```json
{
  "added": true,
  "message": "Policy added successfully",
  "policy": {
    "subject": "alice",
    "object": "company_strategy.pdf",
    "action": "read"
  },
  "model": "acl"
}
```

Give Alice write permission too:

```bash
curl -X POST http://localhost:8080/api/v1/acl/policies \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "alice",
    "object": "company_strategy.pdf",
    "action": "write"
  }'
```

Give Diana (HR Manager) access to employee records:

```bash
curl -X POST http://localhost:8080/api/v1/acl/policies \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "diana",
    "object": "employee_records.xlsx",
    "action": "read"
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/acl/policies \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "diana",
    "object": "employee_records.xlsx",
    "action": "write"
  }'
```

Give Charlie (Engineer) read access to source code:

```bash
curl -X POST http://localhost:8080/api/v1/acl/policies \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "charlie",
    "object": "source_code.zip",
    "action": "read"
  }'
```

### Step 2: Test Authorization

Let's test if Alice can read the strategy document:

```bash
curl -X POST http://localhost:8080/api/v1/authorizations \
  -H "Content-Type: application/json" \
  -d '{
    "model": "acl",
    "subject": "alice",
    "object": "company_strategy.pdf",
    "action": "read"
  }'
```

Expected response:

```json
{
  "allowed": true,
  "message": "Access granted",
  "model": "acl"
}
```

Test if Charlie can read employee records (should be denied):

```bash
curl -X POST http://localhost:8080/api/v1/authorizations \
  -H "Content-Type: application/json" \
  -d '{
    "model": "acl",
    "subject": "charlie",
    "object": "employee_records.xlsx",
    "action": "read"
  }'
```

Expected response:

```json
{
  "allowed": false,
  "message": "Access denied",
  "model": "acl"
}
```

### Step 3: View All ACL Policies

```bash
curl http://localhost:8080/api/v1/acl/policies
```

Expected response:

```json
{
  "policies": [
    ["alice", "company_strategy.pdf", "read"],
    ["alice", "company_strategy.pdf", "write"],
    ["diana", "employee_records.xlsx", "read"],
    ["diana", "employee_records.xlsx", "write"],
    ["charlie", "source_code.zip", "read"]
  ],
  "count": 5,
  "model": "acl"
}
```

### ACL Summary

**Pros:**

- Simple and direct
- Easy to understand
- Full control over individual permissions

**Cons:**

- Becomes unmanageable with many users
- Hard to maintain
- No concept of roles or groups

---

## Tutorial 2: RBAC (Role-Based Access Control)

**RBAC** organizes permissions through roles. Users are assigned roles, and roles have permissions.

**Use Case**: Most common in business environments where people have job functions (roles) that determine their access rights.

### Scenario

At TechCorp, instead of managing individual permissions, we'll create roles based on job functions.

### Step 1: Assign Roles to Users

Assign Alice the "ceo" role:

```bash
curl -X POST http://localhost:8080/api/v1/users/alice/roles \
  -H "Content-Type: application/json" \
  -d '{
    "role": "ceo"
  }'
```

Expected response:

```json
{
  "added": true,
  "message": "Role added successfully",
  "user": "alice",
  "role": "ceo",
  "model": "rbac"
}
```

Assign Bob the "manager" role:

```bash
curl -X POST http://localhost:8080/api/v1/users/bob/roles \
  -H "Content-Type: application/json" \
  -d '{
    "role": "manager"
  }'
```

Expected response:

```json
{
  "added": true,
  "message": "Role added successfully",
  "user": "bob",
  "role": "manager",
  "model": "rbac"
}
```

Assign Charlie the "engineer" role:

```bash
curl -X POST http://localhost:8080/api/v1/users/charlie/roles \
  -H "Content-Type: application/json" \
  -d '{
    "role": "engineer"
  }'
```

Expected response:

```json
{
  "added": true,
  "message": "Role added successfully",
  "user": "charlie",
  "role": "engineer",
  "model": "rbac"
}
```

Assign Diana the "hr_manager" role:

```bash
curl -X POST http://localhost:8080/api/v1/users/diana/roles \
  -H "Content-Type: application/json" \
  -d '{
    "role": "hr_manager"
  }'
```

Expected response:

```json
{
  "added": true,
  "message": "Role added successfully",
  "user": "diana",
  "role": "hr_manager",
  "model": "rbac"
}
```

Assign Frank the "engineer" role too:

```bash
curl -X POST http://localhost:8080/api/v1/users/frank/roles \
  -H "Content-Type: application/json" \
  -d '{
    "role": "engineer"
  }'
```

Expected response:

```json
{
  "added": true,
  "message": "Role added successfully",
  "user": "frank",
  "role": "engineer",
  "model": "rbac"
}
```

### Step 2: Define Role Permissions

Give the "ceo" role access to everything:

```bash
curl -X POST http://localhost:8080/api/v1/rbac/policies \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "ceo",
    "object": "company_strategy.pdf",
    "action": "read"
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/rbac/policies \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "ceo",
    "object": "company_strategy.pdf",
    "action": "write"
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/rbac/policies \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "ceo",
    "object": "sales_reports.pdf",
    "action": "read"
  }'
```

Give "hr_manager" role access to employee records:

```bash
curl -X POST http://localhost:8080/api/v1/rbac/policies \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "hr_manager",
    "object": "employee_records.xlsx",
    "action": "read"
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/rbac/policies \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "hr_manager",
    "object": "employee_records.xlsx",
    "action": "write"
  }'
```

Give "engineer" role access to source code:

```bash
curl -X POST http://localhost:8080/api/v1/rbac/policies \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "engineer",
    "object": "source_code.zip",
    "action": "read"
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/rbac/policies \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "engineer",
    "object": "engineering_docs.md",
    "action": "read"
  }'
```

Give "manager" role broader access:

```bash
curl -X POST http://localhost:8080/api/v1/rbac/policies \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "manager",
    "object": "source_code.zip",
    "action": "read"
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/rbac/policies \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "manager",
    "object": "engineering_docs.md",
    "action": "write"
  }'
```

### Step 3: Test RBAC Authorization

Test if Alice (CEO) can read the strategy document:

```bash
curl -X POST http://localhost:8080/api/v1/authorizations \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "alice",
    "object": "company_strategy.pdf",
    "action": "read"
  }'
```

Test if Charlie (Engineer) can access source code:

```bash
curl -X POST http://localhost:8080/api/v1/authorizations \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "charlie",
    "object": "source_code.zip",
    "action": "read"
  }'
```

Test if Charlie can access employee records (should be denied):

```bash
curl -X POST http://localhost:8080/api/v1/authorizations \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "charlie",
    "object": "employee_records.xlsx",
    "action": "read"
  }'
```

### Step 4: Check User Roles

See what roles Alice has:

```bash
curl http://localhost:8080/api/v1/users/alice/roles
```

Expected response:

```json
{
  "user": "alice",
  "roles": ["ceo"],
  "count": 1,
  "model": "rbac"
}
```

See what roles Charlie has:

```bash
curl http://localhost:8080/api/v1/users/charlie/roles
```

Expected response:

```json
{
  "user": "charlie",
  "roles": ["engineer"],
  "count": 1,
  "model": "rbac"
}
```

### RBAC Summary

**Pros:**

- Organized by job functions
- Easy to manage large numbers of users
- Clear separation of responsibilities
- Industry standard

**Cons:**

- Can become complex with role hierarchies
- Less flexible than other models
- Role explosion (too many specific roles)

---

## Tutorial 3: ABAC (Attribute-Based Access Control)

**ABAC** makes authorization decisions based on attributes of users, objects, and the environment/context using a sophisticated policy engine.

**Use Case**: Complex organizations with dynamic access requirements based on location, time, clearance levels, departments, etc.

### Understanding the ABAC Policy Engine

Our ABAC implementation features a powerful, configurable policy engine that supports:

- **Dynamic Policies**: Rules stored in database and evaluated in real-time
- **Rich Operators**: eq, ne, gt, gte, lt, lte, in, contains, regex
- **Logic Combinations**: AND/OR operations for complex conditions
- **Priority System**: Policies evaluated by priority order
- **Attribute Types**: User, object, environment, and action attributes
- **Generic Design**: No hardcoded policies - completely customizable

### Generic Policy Engine

The ABAC engine starts completely empty, providing a pure generic authorization platform. This tutorial will show you how to create custom policies from scratch to demonstrate the flexibility and power of the system.

### Scenario

At TechCorp, we want sophisticated access control based on:

- Employee department and position
- Security clearance level
- Access location (office vs. remote)
- Document sensitivity
- Time of access

### Step 1: Create a Custom ABAC Policy

Let's create a policy that allows managers to access resources from their own department:

```bash
curl -X POST http://localhost:8080/api/v1/abac/policies \
  -H "Content-Type: application/json" \
  -d '{
    "id": "manager_dept_access",
    "name": "Manager Department Access",
    "description": "Managers can access resources from their department",
    "effect": "allow",
    "priority": 100,
    "conditions": [
      {
        "type": "user",
        "field": "position",
        "operator": "eq",
        "value": "manager",
        "logic_op": "and"
      },
      {
        "type": "user",
        "field": "department",
        "operator": "eq",
        "value": "engineering",
        "logic_op": "and"
      },
      {
        "type": "object",
        "field": "department",
        "operator": "eq",
        "value": "engineering",
        "logic_op": ""
      }
    ]
  }'
```

Expected response:

```json
{
  "message": "ABAC policy added successfully",
  "policy": {
    "id": "manager_dept_access",
    "name": "Manager Department Access",
    "description": "Managers can access resources from their department",
    "effect": "allow",
    "priority": 100,
    "conditions": [...],
    "created_at": "2024-06-24T...",
    "updated_at": "2024-06-24T..."
  }
}
```

### Step 2: Set User Attributes

Set attributes for Bob (Engineering Manager):

```bash
curl -X PUT http://localhost:8080/api/v1/users/bob/attributes \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "department": "engineering",
      "position": "manager"
    }
  }'
```

Expected response:

```json
{
  "message": "User attributes set successfully",
  "user": "bob",
  "attributes": {
    "department": "engineering",
    "position": "manager"
  },
  "count": 2,
  "model": "abac"
}
```

Set attributes for Charlie (Engineer):

```bash
curl -X PUT http://localhost:8080/api/v1/users/charlie/attributes \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "department": "engineering",
      "position": "engineer"
    }
  }'
```

### Step 3: Set Object Attributes

Set attributes for engineering project documents:

```bash
curl -X PUT http://localhost:8080/api/v1/objects/project_docs/attributes \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "department": "engineering",
      "classification": "internal"
    }
  }'
```

Expected response:

```json
{
  "message": "Object attributes set successfully",
  "object": "project_docs",
  "attributes": {
    "department": "engineering",
    "classification": "internal"
  },
  "count": 2,
  "model": "abac"
}
```

### Step 4: Test ABAC Authorization with Policy Engine

The ABAC model uses the policy engine to evaluate authorization requests based on our custom policy.

Test if Bob (manager) can access engineering project documents:

```bash
curl -X POST http://localhost:8080/api/v1/authorizations \
  -H "Content-Type: application/json" \
  -d '{
    "model": "abac",
    "subject": "bob",
    "object": "project_docs",
    "action": "read",
    "attributes": {
      "location": "office"
    }
  }'
```

Expected response:

```json
{
  "allowed": true,
  "message": "Access granted",
  "model": "abac"
}
```

Test if Charlie (engineer, not manager) can access the same documents:

```bash
curl -X POST http://localhost:8080/api/v1/authorizations \
  -H "Content-Type: application/json" \
  -d '{
    "model": "abac",
    "subject": "charlie",
    "object": "project_docs",
    "action": "read",
    "attributes": {
      "location": "office"
    }
  }'
```

Expected response:

```json
{
  "allowed": false,
  "message": "Access denied",
  "model": "abac"
}
```

### Step 5: Understanding Policy Evaluation

The policy engine evaluates policies in priority order (highest first) and returns the first matching policy's effect. In our example:

1. **Priority 100**: Manager Department Access policy

This policy evaluates the following conditions using AND logic:

- User position must equal "manager"
- User department must equal "engineering"
- Object department must equal "engineering"

For Bob: ✅ position=manager, department=engineering → conditions met → access granted
For Charlie: ❌ position=engineer (not manager) → conditions not met → access denied

### Step 6: Managing Policies

View all policies:

```bash
curl "http://localhost:8080/api/v1/abac/policies"
```

Get a specific policy:

```bash
curl "http://localhost:8080/api/v1/abac/policies/manager_dept_access"
```

Create additional policies as needed for your business logic.

### Step 7: View User and Object Attributes

Check Bob's attributes:

```bash
curl http://localhost:8080/api/v1/users/bob/attributes
```

Expected response:

```json
{
  "user": "bob",
  "attributes": {
    "department": "engineering",
    "position": "manager"
  },
  "count": 2,
  "model": "abac"
}
```

Check object attributes:

```bash
curl http://localhost:8080/api/v1/objects/project_docs/attributes
```

Expected response:

```json
{
  "object": "project_docs",
  "attributes": {
    "department": "engineering",
    "classification": "internal"
  },
  "count": 2,
  "model": "abac"
}
```

### Step 8: Creating More Complex Policies

You can create additional policies with different operators and logic combinations. For example, a time-based policy:

```bash
curl -X POST http://localhost:8080/api/v1/abac/policies \
  -H "Content-Type: application/json" \
  -d '{
    "id": "business_hours",
    "name": "Business Hours Access",
    "description": "Allow access only during business hours",
    "effect": "allow",
    "priority": 50,
    "conditions": [
      {
        "type": "environment",
        "field": "hour",
        "operator": "gte",
        "value": "9",
        "logic_op": "and"
      },
      {
        "type": "environment",
        "field": "hour",
        "operator": "lte",
        "value": "17",
        "logic_op": ""
      }
    ]
  }'
```

### ABAC Summary

**Pros:**

- **Generic Engine**: No hardcoded policies - completely customizable for any business logic
- **Dynamic Evaluation**: Real-time policy evaluation with configurable rules
- **Rich Logic**: Support for complex conditions with multiple operators (eq, ne, gt, gte, lt, lte, in, contains, regex)
- **Context-Aware**: Decisions based on location, time, and other environmental factors
- **Scalable**: Database-stored policies with in-memory caching
- **Fine-Grained Control**: Attribute-level access control
- **Policy Management**: Easy to create, modify, or remove policies via API
- **Priority System**: Handle complex scenarios with policy precedence

**Cons:**

- **Complexity**: Requires careful policy design and testing
- **Learning Curve**: Understanding how to design effective policies
- **Debugging**: Complex policy interactions can be hard to trace
- **Attribute Management**: Requires maintaining accurate user and object attributes

**Key Features:**

- **Complete Flexibility**: Define any authorization logic through custom policies
- **Business Rule Engine**: Implement complex business rules as authorization policies
- **API-Driven**: All policy management through RESTful APIs
- **Production Ready**: Built for enterprise-scale authorization needs

---

## Tutorial 4: ReBAC (Relationship-Based Access Control)

**ReBAC** uses relationships between entities to determine access permissions. It's like a social network for authorization.

**Use Case**: Organizations with complex hierarchies, document sharing, social platforms, collaborative environments.

### Scenario

At TechCorp, we want to model relationships:

- Team memberships
- Document ownership
- Hierarchical relationships
- Collaborative permissions

### Step 1: Create Ownership Relationships

Alice owns the company strategy document:

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "alice",
    "relationship": "owner",
    "object": "company_strategy.pdf"
  }'
```

Expected response:

```json
{
  "message": "Relationship added successfully",
  "subject": "alice",
  "relationship": "owner",
  "object": "company_strategy.pdf",
  "model": "rebac"
}
```

Bob owns the engineering documentation:

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "bob",
    "relationship": "owner",
    "object": "engineering_docs.md"
  }'
```

Diana owns the employee records:

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "diana",
    "relationship": "owner",
    "object": "employee_records.xlsx"
  }'
```

### Step 2: Create Team Memberships

Create an engineering team:

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "bob",
    "relationship": "member",
    "object": "engineering_team"
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "charlie",
    "relationship": "member",
    "object": "engineering_team"
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "frank",
    "relationship": "member",
    "object": "engineering_team"
  }'
```

### Step 3: Grant Team Access to Resources

Give the engineering team access to source code:

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "engineering_team",
    "relationship": "group_access",
    "object": "source_code.zip"
  }'
```

Give the engineering team access to engineering docs:

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "engineering_team",
    "relationship": "group_access",
    "object": "engineering_docs.md"
  }'
```

### Step 4: Create Editor Relationships

Give Charlie editor access to the engineering docs:

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "charlie",
    "relationship": "editor",
    "object": "engineering_docs.md"
  }'
```

### Step 5: Create Hierarchical Relationships

Bob manages Charlie:

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "bob",
    "relationship": "manager",
    "object": "charlie"
  }'
```

Alice manages Bob:

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "alice",
    "relationship": "manager",
    "object": "bob"
  }'
```

### Step 6: Test ReBAC Authorization

Test if Alice can write to the strategy document (as owner):

```bash
curl -X POST http://localhost:8080/api/v1/authorizations \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rebac",
    "subject": "alice",
    "object": "company_strategy.pdf",
    "action": "write"
  }'
```

Test if Charlie can read source code (via team membership):

```bash
curl -X POST http://localhost:8080/api/v1/authorizations \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rebac",
    "subject": "charlie",
    "object": "source_code.zip",
    "action": "read"
  }'
```

Test if Charlie can edit engineering docs (as editor):

```bash
curl -X POST http://localhost:8080/api/v1/authorizations \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rebac",
    "subject": "charlie",
    "object": "engineering_docs.md",
    "action": "write"
  }'
```

### Step 7: Understanding Authorization vs. Relationship Paths

**Important**: ReBAC follows best practices by separating authorization checks from relationship queries.

#### Authorization Check (Recommended for Access Control)

Test if Charlie can read source code (actual permission check):

```bash
curl -X POST http://localhost:8080/api/v1/authorizations \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rebac",
    "subject": "charlie",
    "object": "source_code.zip",
    "action": "read"
  }'
```

Expected response:

```json
{
  "allowed": true,
  "message": "Access granted (relationship path: charlie -[member]-> engineering_team -[group_access]-> source_code.zip)",
  "model": "rebac"
}
```

#### Relationship Path Discovery (Debugging/Audit Only)

Find how Charlie is connected to source code:

```bash
curl "http://localhost:8080/api/v1/relationships/paths?subject=charlie&object=source_code.zip&max_depth=5"
```

Expected response:

```json
{
  "found": true,
  "path": "charlie -[member]-> engineering_team -[group_access]-> source_code.zip",
  "subject": "charlie",
  "object": "source_code.zip",
  "max_depth": 5,
  "model": "rebac",
  "note": "This endpoint shows relationship connectivity, not authorization. Use /api/v1/authorizations for permission checks."
}
```

**Key Difference**: Path discovery shows connectivity, but authorization checks determine actual permissions based on relationship types.

### Step 8: Understanding Relationship-Permission Mappings

ReBAC uses configurable relationship-to-permission mappings. View the default mappings:

```bash
curl http://localhost:8080/api/v1/relationships/permissions
```

Expected response:

```json
{
  "mappings": {
    "owner": ["read", "write", "delete", "admin"],
    "editor": ["read", "write", "edit"],
    "viewer": ["read", "view"],
    "member": ["inherit"],
    "group_access": ["read", "write"],
    "parent": ["inherit"],
    "friend": ["read_limited"],
    "manager": ["read", "write", "delete", "manage"]
  },
  "description": "Relationship types and their associated permissions",
  "model": "rebac",
  "note": "These mappings define what permissions each relationship type grants"
}
```

#### Check Specific Relationship Permissions

Check if the "editor" relationship grants "write" permission:

```bash
curl -X POST http://localhost:8080/api/v1/relationships/permissions/check \
  -H "Content-Type: application/json" \
  -d '{
    "relationship": "editor",
    "permission": "write"
  }'
```

Expected response:

```json
{
  "relationship": "editor",
  "permission": "write",
  "granted": true,
  "all_permissions": ["read", "write", "edit"],
  "model": "rebac"
}
```

### Step 9: List Relationships

See all relationships for Charlie:

```bash
curl "http://localhost:8080/api/v1/relationships?subject=charlie"
```

Expected response:

```json
{
  "relationships": [
    {
      "subject": "charlie",
      "relationship": "member",
      "object": "engineering_team"
    },
    {
      "subject": "charlie",
      "relationship": "editor",
      "object": "engineering_docs.md"
    }
  ],
  "subject": "charlie",
  "model": "rebac"
}
```

See all relationships involving the engineering team:

```bash
curl "http://localhost:8080/api/v1/relationships?subject=engineering_team"
```

Expected response:

```json
{
  "relationships": [
    {
      "subject": "engineering_team",
      "relationship": "group_access",
      "object": "source_code.zip"
    },
    {
      "subject": "engineering_team",
      "relationship": "group_access",
      "object": "engineering_docs.md"
    }
  ],
  "subject": "engineering_team",
  "model": "rebac"
}
```

### ReBAC Summary

**Pros:**

- **Separation of Concerns**: Clear distinction between relationship queries and authorization decisions
- **Industry Standards**: Follows Google Zanzibar and other proven ReBAC patterns
- **Configurable Permissions**: Relationship-to-permission mappings can be customized
- **Natural Modeling**: Models real-world relationships and hierarchies intuitively
- **Flexible Authorization**: Supports ownership, groups, hierarchies, and social relationships
- **Debugging Support**: Path discovery helps understand relationship connectivity
- **Performance**: Efficient direct relationship checks with inheritance support

**Cons:**

- **Learning Curve**: Understanding relationship vs. permission concepts
- **Complexity**: Can become complex with deep relationship graphs
- **Debugging**: Complex permission paths can be challenging to trace
- **Design Required**: Requires careful relationship and permission modeling

**Best Practices Implemented:**

1. **Authorization vs. Query Separation**: Use `POST /authorizations` for access control decisions
2. **Relationship Discovery**: Use `GET /relationships/paths` for debugging and auditing
3. **Permission Transparency**: View relationship-permission mappings via API
4. **Configurable Logic**: Relationship permissions can be modified as needed
5. **Industry Patterns**: Follows established ReBAC patterns from major systems

---

## Comparison and When to Use Each Model

### Quick Reference

| Model     | Best For                                 | Complexity  | Scalability | Flexibility |
| --------- | ---------------------------------------- | ----------- | ----------- | ----------- |
| **ACL**   | Small teams, simple permissions          | Low         | Poor        | Low         |
| **RBAC**  | Traditional business environments        | Medium      | Good        | Medium      |
| **ABAC**  | Dynamic, context-aware permissions       | High        | Excellent   | Very High   |
| **ReBAC** | Social networks, collaborative platforms | Medium-High | Good        | High        |

### Decision Guide

**Choose ACL when:**

- You have a small team (< 20 people)
- Simple, direct permissions are sufficient
- You need complete control over individual access

**Choose RBAC when:**

- You have clear job roles and responsibilities
- Traditional corporate environment
- You need industry-standard access control
- Medium to large organization

**Choose ABAC when:**

- You need context-aware permissions (time, location, etc.)
- Complex business rules for access
- Dynamic permission requirements
- High security environments

**Choose ReBAC when:**

- You have complex organizational hierarchies
- Document sharing and collaboration
- Social networking features
- Team-based access patterns

### Combining Models

In practice, many organizations use combinations:

- **RBAC + ABAC**: Role-based foundation with attribute-based overrides
- **RBAC + ReBAC**: Role-based for basic access, relationship-based for collaboration
- **All Four**: Different models for different parts of the system

## Next Steps

### For Production Use

1. **Database Configuration**: Switch from SQLite to PostgreSQL or MySQL for production
2. **Performance Optimization**: Add caching layers and database indexes
3. **Monitoring**: Add logging and metrics for authorization decisions
4. **Security**: Add authentication, rate limiting, and audit trails
5. **Scalability**: Deploy multiple instances with load balancing

### Learning More

1. **Study the Code**: Examine the implementation in `main.go`
2. **Extend the Models**: Add custom relationship types or ABAC rules
3. **Integration**: Connect this service to your applications
4. **Testing**: Write comprehensive test scenarios for your use cases

### Advanced Topics

- Policy versioning and rollback
- Real-time policy updates
- Integration with identity providers (LDAP, Active Directory)
- Policy conflict resolution
- Performance optimization for large datasets

---

**Congratulations!** You've now learned how to use all four authorization models with practical, hands-on examples. You can apply these concepts to build secure, scalable authorization systems for your own applications.
