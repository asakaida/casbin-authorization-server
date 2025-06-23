# Authorization Models Tutorial: A Complete Beginner's Guide

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
{ "status": "healthy", "message": "Authorization service is running" }
```

### Check Available Models

```bash
curl http://localhost:8080/api/v1/models
```

Expected response:

```json
{
  "models": ["acl", "rbac", "abac", "rebac"],
  "message": "Supported authorization models"
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
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "acl",
    "subject": "alice",
    "object": "company_strategy.pdf",
    "action": "read"
  }'
```

Give Alice write permission too:

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "acl",
    "subject": "alice",
    "object": "company_strategy.pdf",
    "action": "write"
  }'
```

Give Diana (HR Manager) access to employee records:

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "acl",
    "subject": "diana",
    "object": "employee_records.xlsx",
    "action": "read"
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "acl",
    "subject": "diana",
    "object": "employee_records.xlsx",
    "action": "write"
  }'
```

Give Charlie (Engineer) read access to source code:

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "acl",
    "subject": "charlie",
    "object": "source_code.zip",
    "action": "read"
  }'
```

### Step 2: Test Authorization

Let's test if Alice can read the strategy document:

```bash
curl -X POST http://localhost:8080/api/v1/enforce \
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
  "model": "acl"
}
```

Test if Charlie can read employee records (should be denied):

```bash
curl -X POST http://localhost:8080/api/v1/enforce \
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
  "model": "acl"
}
```

### Step 3: View All ACL Policies

```bash
curl "http://localhost:8080/api/v1/policies?model=acl"
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
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Content-Type: application/json" \
  -d '{
    "user": "alice",
    "role": "ceo"
  }'
```

Assign Bob the "manager" role:

```bash
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Content-Type: application/json" \
  -d '{
    "user": "bob",
    "role": "manager"
  }'
```

Assign Charlie the "engineer" role:

```bash
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Content-Type: application/json" \
  -d '{
    "user": "charlie",
    "role": "engineer"
  }'
```

Assign Diana the "hr_manager" role:

```bash
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Content-Type: application/json" \
  -d '{
    "user": "diana",
    "role": "hr_manager"
  }'
```

Assign Frank the "engineer" role too:

```bash
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Content-Type: application/json" \
  -d '{
    "user": "frank",
    "role": "engineer"
  }'
```

### Step 2: Define Role Permissions

Give the "ceo" role access to everything:

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "ceo",
    "object": "company_strategy.pdf",
    "action": "read"
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "ceo",
    "object": "company_strategy.pdf",
    "action": "write"
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "ceo",
    "object": "sales_reports.pdf",
    "action": "read"
  }'
```

Give "hr_manager" role access to employee records:

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "hr_manager",
    "object": "employee_records.xlsx",
    "action": "read"
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "hr_manager",
    "object": "employee_records.xlsx",
    "action": "write"
  }'
```

Give "engineer" role access to source code:

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "engineer",
    "object": "source_code.zip",
    "action": "read"
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "engineer",
    "object": "engineering_docs.md",
    "action": "read"
  }'
```

Give "manager" role broader access:

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "manager",
    "object": "source_code.zip",
    "action": "read"
  }'
```

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "manager",
    "object": "engineering_docs.md",
    "action": "write"
  }'
```

### Step 3: Test RBAC Authorization

Test if Alice (CEO) can read the strategy document:

```bash
curl -X POST http://localhost:8080/api/v1/enforce \
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
curl -X POST http://localhost:8080/api/v1/enforce \
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
curl -X POST http://localhost:8080/api/v1/enforce \
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
curl "http://localhost:8080/api/v1/users/roles?user=alice"
```

See what roles Charlie has:

```bash
curl "http://localhost:8080/api/v1/users/roles?user=charlie"
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

**ABAC** makes authorization decisions based on attributes of users, objects, and the environment/context.

**Use Case**: Complex organizations with dynamic access requirements based on location, time, clearance levels, departments, etc.

### Scenario

At TechCorp, we want more sophisticated access control based on:

- Employee department
- Security clearance level
- Access location (office vs. remote)
- Document sensitivity

### Step 1: Set User Attributes

Set attributes for Alice (CEO):

```bash
curl -X POST http://localhost:8080/api/v1/users/attributes \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "alice",
    "attributes": {
      "department": "executive",
      "clearance": "top_secret",
      "position": "ceo",
      "location": "office"
    }
  }'
```

Set attributes for Bob (Engineering Manager):

```bash
curl -X POST http://localhost:8080/api/v1/users/attributes \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "bob",
    "attributes": {
      "department": "engineering",
      "clearance": "secret",
      "position": "manager",
      "location": "office"
    }
  }'
```

Set attributes for Charlie (Engineer):

```bash
curl -X POST http://localhost:8080/api/v1/users/attributes \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "charlie",
    "attributes": {
      "department": "engineering",
      "clearance": "confidential",
      "position": "engineer",
      "location": "office"
    }
  }'
```

Set attributes for Diana (HR Manager):

```bash
curl -X POST http://localhost:8080/api/v1/users/attributes \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "diana",
    "attributes": {
      "department": "hr",
      "clearance": "secret",
      "position": "manager",
      "location": "office"
    }
  }'
```

### Step 2: Test ABAC Authorization

The ABAC model in our system uses custom logic to evaluate authorization based on user attributes and context.

Test if Alice can access confidential data (she has top_secret clearance):

```bash
curl -X POST http://localhost:8080/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{
    "model": "abac",
    "subject": "alice",
    "object": "confidential_data",
    "action": "read",
    "attributes": {
      "location": "office"
    }
  }'
```

Test if Charlie can access confidential data (he has confidential clearance):

```bash
curl -X POST http://localhost:8080/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{
    "model": "abac",
    "subject": "charlie",
    "object": "confidential_data",
    "action": "read",
    "attributes": {
      "location": "office"
    }
  }'
```

Test access from remote location (should be more restrictive):

```bash
curl -X POST http://localhost:8080/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{
    "model": "abac",
    "subject": "charlie",
    "object": "confidential_data",
    "action": "read",
    "attributes": {
      "location": "remote"
    }
  }'
```

Test cross-department access (HR manager accessing engineering data):

```bash
curl -X POST http://localhost:8080/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{
    "model": "abac",
    "subject": "diana",
    "object": "engineering_source_code",
    "action": "read",
    "attributes": {
      "location": "office"
    }
  }'
```

### Step 3: View User Attributes

Check Alice's attributes:

```bash
curl "http://localhost:8080/api/v1/users/attributes?user=alice"
```

Check Charlie's attributes:

```bash
curl "http://localhost:8080/api/v1/users/attributes?user=charlie"
```

### ABAC Summary

**Pros:**

- Extremely flexible and dynamic
- Context-aware decisions
- Fine-grained control
- Supports complex business rules

**Cons:**

- Complex to design and implement
- Performance considerations
- Harder to debug and audit
- Requires careful attribute management

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
curl -X POST http://localhost:8080/api/v1/enforce \
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
curl -X POST http://localhost:8080/api/v1/enforce \
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
curl -X POST http://localhost:8080/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rebac",
    "subject": "charlie",
    "object": "engineering_docs.md",
    "action": "write"
  }'
```

### Step 7: Explore Relationship Paths

Find how Charlie can access source code:

```bash
curl "http://localhost:8080/api/v1/relationships/path?subject=charlie&object=source_code.zip&max_depth=5"
```

This should show the path: charlie → member → engineering_team → group_access → source_code.zip

### Step 8: List Relationships

See all relationships for Charlie:

```bash
curl "http://localhost:8080/api/v1/relationships?subject=charlie"
```

See all relationships involving the engineering team:

```bash
curl "http://localhost:8080/api/v1/relationships?subject=engineering_team"
```

### ReBAC Summary

**Pros:**

- Models real-world relationships naturally
- Supports complex hierarchies and collaborations
- Flexible and intuitive
- Great for social and collaborative platforms

**Cons:**

- Can become complex with many relationships
- Performance considerations for deep graphs
- Requires careful relationship modeling
- Can be hard to debug complex permission paths

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
