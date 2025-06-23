# Multi-Model Authorization Microservice

A comprehensive authorization microservice built with Go and Casbin, supporting multiple access control models: ACL, RBAC, ABAC, and ReBAC.

## Overview

This microservice provides a unified authorization solution that supports four different access control models:

- **ACL (Access Control List)**: Direct user-to-resource permission mapping
- **RBAC (Role-Based Access Control)**: Role-based authorization with hierarchical permissions
- **ABAC (Attribute-Based Access Control)**: Dynamic authorization based on user, object, and environmental attributes
- **ReBAC (Relationship-Based Access Control)**: Graph-based authorization using relationships between entities

The service is built using the Casbin authorization library and provides RESTful APIs for managing policies, roles, attributes, and relationships across all supported models.

## 📚 Getting Started

### For Beginners
If you're new to authorization systems, start with our comprehensive tutorial:

**👉 [Complete Authorization Tutorial](./AUTHORIZATION_TUTORIAL.md)**

This hands-on guide walks you through:
- Understanding authorization concepts
- Setting up a fictional company scenario (TechCorp Inc.)
- Step-by-step examples for all 4 authorization models
- Real API calls with curl commands you can copy and paste
- When to use each model in practice

### For Experienced Users
Continue with the API documentation and technical details below.

## Features

- 🔐 **Multi-Model Support**: ACL, RBAC, ABAC, and ReBAC in a single service
- 🗄️ **Persistent Storage**: SQLite database with separate tables for each model
- 🔄 **Auto-Save**: Automatic policy persistence
- 🌐 **RESTful API**: Clean HTTP API with JSON responses
- 📊 **Relationship Graphs**: Advanced graph traversal for ReBAC
- 🎯 **Flexible Policies**: Support for complex authorization rules
- 🔍 **Path Discovery**: Find relationship paths in ReBAC model
- ⚡ **Fast Performance**: Optimized for high-throughput authorization checks
- 🏗️ **Scalable Architecture**: Designed for enterprise-grade scalability
- 💾 **Intelligent Caching**: Memory caching with database persistence for optimal performance

## Build Instructions

### Prerequisites

- Go 1.19 or later
- Git

### Building the Application

```bash
# Clone the repository
git clone <repository-url>
cd casbin-authorization-server

# Download dependencies
go mod tidy

# Build the application
go build -o casbin-server ./main.go
```

## Running the Application

### Option 1: Run with go run (Development)

```bash
# Run directly with Go
go run ./main.go

# Run on a custom port
PORT=8081 go run ./main.go
```

### Option 2: Run compiled binary (Production)

```bash
# Build and run
go build -o casbin-server ./main.go
./casbin-server

# Run on custom port
PORT=8081 ./casbin-server
```

The service will start on port 8080 by default (or the port specified in the `PORT` environment variable).

## Basic Usage

### Health Check

```bash
curl http://localhost:8080/api/v1/health
```

### List Supported Models

```bash
curl http://localhost:8080/api/v1/models
```

### Authorization Check (All Models)

```bash
curl -X POST http://localhost:8080/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "alice",
    "object": "data",
    "action": "read"
  }'
```

## Detailed Use Cases

### 1. ACL (Access Control List)

ACL provides direct user-to-resource permission mapping. Best for simple scenarios with few users and resources.

#### Add ACL Policy

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "acl",
    "subject": "alice",
    "object": "document1",
    "action": "read"
  }'
```

#### Check ACL Permission

```bash
curl -X POST http://localhost:8080/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{
    "model": "acl",
    "subject": "alice",
    "object": "document1",
    "action": "read"
  }'
```

#### List ACL Policies

```bash
curl "http://localhost:8080/api/v1/policies?model=acl"
```

#### Remove ACL Policy

```bash
curl -X DELETE http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "acl",
    "subject": "alice",
    "object": "document1",
    "action": "read"
  }'
```

### 2. RBAC (Role-Based Access Control)

RBAC organizes permissions through roles. Users are assigned roles, and roles have permissions.

#### Assign Role to User

```bash
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Content-Type: application/json" \
  -d '{
    "user": "alice",
    "role": "admin"
  }'
```

#### Add Role Permission

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "admin",
    "object": "data",
    "action": "write"
  }'
```

#### Check RBAC Permission

```bash
curl -X POST http://localhost:8080/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rbac",
    "subject": "alice",
    "object": "data",
    "action": "write"
  }'
```

#### Get User Roles

```bash
curl "http://localhost:8080/api/v1/users/roles?user=alice"
```

#### List RBAC Policies

```bash
curl "http://localhost:8080/api/v1/policies?model=rbac"
```

### 3. ABAC (Attribute-Based Access Control)

ABAC makes authorization decisions based on attributes of users, objects, and environment.

#### Set User Attributes

```bash
curl -X POST http://localhost:8080/api/v1/users/attributes \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "alice",
    "attributes": {
      "department": "hr",
      "clearance": "high",
      "position": "manager"
    }
  }'
```

#### Check ABAC Permission

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

#### Get User Attributes

```bash
curl "http://localhost:8080/api/v1/users/attributes?user=alice"
```

### 4. ReBAC (Relationship-Based Access Control)

ReBAC uses relationships between entities to determine access. It supports complex scenarios like social networks, hierarchical organizations, and collaborative platforms.

#### Add Ownership Relationship

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "alice",
    "relationship": "owner",
    "object": "document1"
  }'
```

#### Add Editor Relationship

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "bob",
    "relationship": "editor",
    "object": "document1"
  }'
```

#### Add Group Membership

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "alice",
    "relationship": "member",
    "object": "hr_team"
  }'
```

#### Add Group Access Rights

```bash
curl -X POST http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "hr_team",
    "relationship": "group_access",
    "object": "hr_documents"
  }'
```

#### Check ReBAC Permission

```bash
curl -X POST http://localhost:8080/api/v1/enforce \
  -H "Content-Type: application/json" \
  -d '{
    "model": "rebac",
    "subject": "alice",
    "object": "document1",
    "action": "write"
  }'
```

#### Find Relationship Path

```bash
curl "http://localhost:8080/api/v1/relationships/path?subject=alice&object=document1&max_depth=5"
```

#### List User Relationships

```bash
curl "http://localhost:8080/api/v1/relationships?subject=alice"
```

#### Remove Relationship

```bash
curl -X DELETE http://localhost:8080/api/v1/relationships \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "bob",
    "relationship": "editor",
    "object": "document1"
  }'
```

## API Endpoints

### General Endpoints

| Method | Endpoint          | Description                         |
| ------ | ----------------- | ----------------------------------- |
| GET    | `/api/v1/health`  | Health check                        |
| GET    | `/api/v1/models`  | List supported authorization models |
| POST   | `/api/v1/enforce` | Check authorization (all models)    |

### Policy Management (ACL/RBAC/ABAC)

| Method | Endpoint                         | Description             |
| ------ | -------------------------------- | ----------------------- |
| POST   | `/api/v1/policies`               | Add policy              |
| DELETE | `/api/v1/policies`               | Remove policy           |
| GET    | `/api/v1/policies?model=<model>` | List policies for model |

### RBAC Specific

| Method | Endpoint                          | Description         |
| ------ | --------------------------------- | ------------------- |
| POST   | `/api/v1/roles`                   | Assign role to user |
| GET    | `/api/v1/users/roles?user=<user>` | Get user roles      |

### ABAC Specific

| Method | Endpoint                               | Description         |
| ------ | -------------------------------------- | ------------------- |
| POST   | `/api/v1/users/attributes`             | Set user attributes |
| GET    | `/api/v1/users/attributes?user=<user>` | Get user attributes |

### ReBAC Specific

| Method | Endpoint                                            | Description            |
| ------ | --------------------------------------------------- | ---------------------- |
| POST   | `/api/v1/relationships`                             | Add relationship       |
| DELETE | `/api/v1/relationships`                             | Remove relationship    |
| GET    | `/api/v1/relationships?subject=<subject>`           | List relationships     |
| GET    | `/api/v1/relationships/path?subject=<s>&object=<o>` | Find relationship path |

## ReBAC Relationship Types

The ReBAC model supports various relationship types:

- **owner**: Full control over the object
- **editor**: Can modify the object
- **viewer**: Can read the object
- **member**: Group membership
- **group_access**: Group-level access to objects
- **parent**: Hierarchical relationship (folder/subfolder)
- **friend**: Social relationship for friend-based access

## Scalable Architecture & Performance

### Enterprise-Grade Scalability

This authorization microservice is designed with scalability as a core principle:

#### Database-First Persistence
- **Full Data Persistence**: All authorization data (policies, roles, attributes, relationships) is stored in the database
- **No Memory Dependencies**: Service can restart without data loss
- **Horizontal Scaling**: Multiple service instances can share the same database
- **Production Ready**: Supports millions of users, roles, and relationships

#### Intelligent Caching Strategy
- **Cache-First Reads**: Frequently accessed data is cached in memory for sub-millisecond response times
- **Write-Through Updates**: All changes are immediately persisted to database and updated in cache
- **Automatic Cache Management**: Cache is automatically populated and invalidated as needed
- **Memory Efficiency**: Only active data is cached, preventing memory bloat

#### Performance Optimizations

##### ABAC Attribute Management
- **Persistent Storage**: User and object attributes stored in dedicated database tables with indexes
- **Bulk Attribute Loading**: Efficient batch loading of user attributes for evaluation
- **Attribute Caching**: Frequently accessed attributes cached for immediate evaluation
- **Scalable for Millions**: Database design supports enterprise-scale attribute datasets

##### ReBAC Relationship Processing
- **Graph Database Design**: Relationships stored with optimized indexes for fast traversal
- **Path Discovery Algorithms**: Efficient breadth-first search for relationship path finding
- **Relationship Caching**: Active relationship graphs cached for real-time authorization
- **Complex Hierarchy Support**: Handles deep organizational hierarchies and social graphs

##### Database Performance
- **Optimized Indexes**: Strategic database indexes on all query-critical columns
- **Connection Pooling**: Efficient database connection management
- **Query Optimization**: Minimized database round-trips through batch operations
- **Auto-Migration**: Database schema automatically maintained and updated

#### Scalability Benefits

1. **User Scale**: Supports millions of users with consistent performance
2. **Policy Scale**: Handles complex policy sets with thousands of rules
3. **Relationship Scale**: Manages large relationship graphs efficiently
4. **Request Scale**: High-throughput authorization checks (thousands per second)
5. **Geographic Scale**: Database can be replicated across regions
6. **Team Scale**: Multiple development teams can work with the same authorization service

### Architecture Highlights

- **Microservice Design**: Standalone service with well-defined API boundaries
- **Stateless Operation**: Each request is independent, enabling easy horizontal scaling
- **Data Consistency**: ACID compliance through database transactions
- **Fault Tolerance**: Service continues operation even with temporary database issues (using cache)
- **Monitoring Ready**: Structured logging and error handling for observability

## Configuration

### Environment Variables

- `PORT`: Server port (default: 8080)

### Database

The service uses SQLite (`casbin.db`) for persistent storage. All data is automatically persisted and restored on service restart.

#### Database Tables

The service creates and manages the following tables:

- `acl_rules`: ACL policies
- `rbac_rules`: RBAC policies and roles  
- `abac_rules`: ABAC policies (pattern-based rules)
- `user_attributes`: ABAC user attributes with full persistence
- `object_attributes`: ABAC object attributes with full persistence
- `relationship_records`: ReBAC relationships with persistent storage

##### 1. `acl_rules` - ACL Policies

Stores Access Control List policies for direct user-resource permissions.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key (auto-increment) |
| `ptype` | VARCHAR(100) | Policy type (always "p" for policies) |
| `v0` | VARCHAR(100) | Subject (user) |
| `v1` | VARCHAR(100) | Object (resource) |
| `v2` | VARCHAR(100) | Action (permission) |
| `v3` | VARCHAR(100) | Reserved for future use |
| `v4` | VARCHAR(100) | Reserved for future use |
| `v5` | VARCHAR(100) | Reserved for future use |

**Example Data:**

```sql
INSERT INTO acl_rules (ptype, v0, v1, v2) VALUES 
('p', 'alice', 'document1', 'read'),
('p', 'bob', 'document2', 'write');
```

##### 2. `rbac_rules` - RBAC Policies and Role Assignments

Stores Role-Based Access Control policies and user-role assignments.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key (auto-increment) |
| `ptype` | VARCHAR(100) | Policy type ("p" for policies, "g" for role assignments) |
| `v0` | VARCHAR(100) | Subject (user for "g", role for "p") |
| `v1` | VARCHAR(100) | Role (for "g") or Object (for "p") |
| `v2` | VARCHAR(100) | Action (for "p" policies only) |
| `v3` | VARCHAR(100) | Reserved for future use |
| `v4` | VARCHAR(100) | Reserved for future use |
| `v5` | VARCHAR(100) | Reserved for future use |

**Example Data:**

```sql
-- Role assignments (ptype = 'g')
INSERT INTO rbac_rules (ptype, v0, v1) VALUES 
('g', 'alice', 'admin'),
('g', 'bob', 'user');

-- Role permissions (ptype = 'p')
INSERT INTO rbac_rules (ptype, v0, v1, v2) VALUES 
('p', 'admin', 'data', 'read'),
('p', 'admin', 'data', 'write'),
('p', 'user', 'data', 'read');
```

##### 3. `abac_rules` - ABAC Policies

Stores Attribute-Based Access Control policies (currently uses the same structure as ACL for pattern matching).

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key (auto-increment) |
| `ptype` | VARCHAR(100) | Policy type (always "p" for policies) |
| `v0` | VARCHAR(100) | Subject pattern |
| `v1` | VARCHAR(100) | Object pattern |
| `v2` | VARCHAR(100) | Action pattern |
| `v3` | VARCHAR(100) | Reserved for future use |
| `v4` | VARCHAR(100) | Reserved for future use |
| `v5` | VARCHAR(100) | Reserved for future use |

**Implementation Note:** ABAC uses a persistent storage approach with caching:

- **User/Object Attributes**: Stored in dedicated database tables with in-memory caching for performance
- **Database Tables**: `user_attributes` and `object_attributes` for scalable attribute storage
- **Evaluation Logic**: Custom application logic handles time-based, location-based, and attribute-based decisions
- **Performance**: Cache-first reads with database persistence for scalability
- **Consistency**: All attribute changes are persisted to database and cached

This design provides both scalability for large datasets and performance for real-time authorization decisions.

##### 4. `user_attributes` - ABAC User Attributes

Stores user attributes for Attribute-Based Access Control with full persistence.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key (auto-increment) |
| `user_id` | VARCHAR(255) | User identifier |
| `attribute` | VARCHAR(255) | Attribute name (e.g., "department", "clearance") |
| `value` | VARCHAR(255) | Attribute value |
| `created_at` | DATETIME | Record creation timestamp |
| `updated_at` | DATETIME | Record last update timestamp |

**Indexes:**

- `idx_user_attributes_user_id` on `user_id`
- `idx_user_attributes_attribute` on `attribute`

**Example Data:**

```sql
INSERT INTO user_attributes (user_id, attribute, value) VALUES 
('alice', 'department', 'hr'),
('alice', 'clearance', 'high'),
('alice', 'position', 'manager'),
('bob', 'department', 'engineering'),
('bob', 'clearance', 'medium');
```

##### 5. `object_attributes` - ABAC Object Attributes

Stores object attributes for Attribute-Based Access Control.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key (auto-increment) |
| `object_id` | VARCHAR(255) | Object identifier |
| `attribute` | VARCHAR(255) | Attribute name (e.g., "classification", "sensitivity") |
| `value` | VARCHAR(255) | Attribute value |
| `created_at` | DATETIME | Record creation timestamp |
| `updated_at` | DATETIME | Record last update timestamp |

**Indexes:**

- `idx_object_attributes_object_id` on `object_id`
- `idx_object_attributes_attribute` on `attribute`

**Example Data:**

```sql
INSERT INTO object_attributes (object_id, attribute, value) VALUES 
('confidential_data', 'classification', 'confidential'),
('confidential_data', 'department', 'hr'),
('confidential_data', 'sensitivity', 'high'),
('public_data', 'classification', 'public');
```

##### 6. `relationship_records` - ReBAC Relationships

Stores Relationship-Based Access Control relationships for graph-based authorization.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key (auto-increment) |
| `subject` | VARCHAR(255) | Subject entity (user, group, or object) |
| `relationship` | VARCHAR(255) | Type of relationship |
| `object` | VARCHAR(255) | Target object or entity |
| `created_at` | DATETIME | Record creation timestamp |
| `updated_at` | DATETIME | Record last update timestamp |

**Indexes:**

- `idx_relationship_records_subject` on `subject`
- `idx_relationship_records_relationship` on `relationship`
- `idx_relationship_records_object` on `object`

**Example Data:**

```sql
INSERT INTO relationship_records (subject, relationship, object) VALUES 
('alice', 'owner', 'document1'),
('bob', 'editor', 'document1'),
('charlie', 'viewer', 'document1'),
('alice', 'member', 'hr_team'),
('hr_team', 'group_access', 'hr_documents');
```

#### Database Schema Creation

The database schema is automatically created when the service starts. No manual database setup is required.

**Schema Creation SQL:**

```sql
-- ACL Rules Table
CREATE TABLE IF NOT EXISTS acl_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ptype VARCHAR(100),
    v0 VARCHAR(100),
    v1 VARCHAR(100),
    v2 VARCHAR(100),
    v3 VARCHAR(100),
    v4 VARCHAR(100),
    v5 VARCHAR(100)
);

-- RBAC Rules Table
CREATE TABLE IF NOT EXISTS rbac_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ptype VARCHAR(100),
    v0 VARCHAR(100),
    v1 VARCHAR(100),
    v2 VARCHAR(100),
    v3 VARCHAR(100),
    v4 VARCHAR(100),
    v5 VARCHAR(100)
);

-- ABAC Rules Table
CREATE TABLE IF NOT EXISTS abac_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ptype VARCHAR(100),
    v0 VARCHAR(100),
    v1 VARCHAR(100),
    v2 VARCHAR(100),
    v3 VARCHAR(100),
    v4 VARCHAR(100),
    v5 VARCHAR(100)
);

-- ABAC User Attributes Table
CREATE TABLE IF NOT EXISTS user_attributes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id VARCHAR(255),
    attribute VARCHAR(255),
    value VARCHAR(255),
    created_at DATETIME,
    updated_at DATETIME
);

-- ABAC Object Attributes Table
CREATE TABLE IF NOT EXISTS object_attributes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id VARCHAR(255),
    attribute VARCHAR(255),
    value VARCHAR(255),
    created_at DATETIME,
    updated_at DATETIME
);

-- ReBAC Relationships Table
CREATE TABLE IF NOT EXISTS relationship_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject VARCHAR(255),
    relationship VARCHAR(255),
    object VARCHAR(255),
    created_at DATETIME,
    updated_at DATETIME
);

-- Indexes for ABAC tables
CREATE INDEX IF NOT EXISTS idx_user_attributes_user_id ON user_attributes(user_id);
CREATE INDEX IF NOT EXISTS idx_user_attributes_attribute ON user_attributes(attribute);
CREATE INDEX IF NOT EXISTS idx_object_attributes_object_id ON object_attributes(object_id);
CREATE INDEX IF NOT EXISTS idx_object_attributes_attribute ON object_attributes(attribute);

-- Indexes for ReBAC table
CREATE INDEX IF NOT EXISTS idx_relationship_records_subject ON relationship_records(subject);
CREATE INDEX IF NOT EXISTS idx_relationship_records_relationship ON relationship_records(relationship);
CREATE INDEX IF NOT EXISTS idx_relationship_records_object ON relationship_records(object);
```

#### Database Location

- **Development**: `./casbin.db` (in the application directory)
- **Production**: Configure with environment variables or mount persistent volume

#### Backup and Recovery

The SQLite database file can be backed up by simply copying the `casbin.db` file. For production environments, consider:

1. **Regular file-based backups**
2. **Database replication** (if using SQLite with replication tools)
3. **Export to SQL dumps** for version control
