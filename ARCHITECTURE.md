# Architecture Overview

This document outlines the architectural design of the Multi-Model Authorization Microservice, which adopts the Ports and Adapters (also known as Hexagonal) architectural pattern. This pattern emphasizes a strong separation of concerns, making the application highly flexible, testable, and independent of external technologies.

## 1. Core Principles

The primary goals of this architecture are:

*   **Flexibility**: Easily swap out external technologies (e.g., HTTP frameworks, databases, messaging systems) without affecting the core business logic.
*   **Testability**: Enable comprehensive unit, integration, and end-to-end testing by isolating components and using interfaces.
*   **Separation of Concerns**: Clearly delineate business logic from infrastructure and external interfaces.
*   **Technology Independence**: The core business logic should not depend on any specific external technology.

## 2. Key Components and Layers

The application is structured into several distinct layers, each with a specific responsibility:

### 2.1. Core (The Hexagon)

This is the heart of the application, containing the pure business logic and defining the application's capabilities. It is completely independent of external technologies.

*   **`internal/core/domain/`**:
    *   Contains the fundamental business entities, value objects, and core types (e.g., `AccessControlModel`, `EnforceRequest`, `ABACPolicy`, `Relationship`).
    *   Defines domain-specific errors.
    *   **Key characteristic**: Pure Go structs and interfaces, no external framework or database dependencies.

*   **`internal/core/ports/`**:
    *   Defines the interfaces (ports) through which the core interacts with the outside world. These are technology-agnostic contracts.
    *   **`driving/` (Primary Ports)**:
        *   Interfaces that define what the application *offers* to external actors (e.g., `AuthorizationService`, `ACLEnforcer`, `RBACEnforcer`, `ABACEnforcer`, `ReBACEnforcer`).
        *   These represent the application's use cases or application services.
    *   **`driven/` (Secondary Ports)**:
        *   Interfaces that define what the application *needs* from external systems (e.g., `ACLPolicyRepository`, `RBACPolicyRepository`, `ABACPolicyRepository`, `AttributeRepository`, `ReBACRepository`).
        *   These represent abstractions over data persistence, external services, or other infrastructure concerns.

*   **`internal/core/services/`**:
    *   Contains the concrete implementations of the `driving` ports (e.g., `authorization_service_impl.go`, `acl_enforcer_impl.go`, `rbac_enforcer_impl.go`, `abac_enforcer_impl.go`, `rebac_enforcer_impl.go`).
    *   These services orchestrate the domain logic and interact with the `driven` ports to fulfill use cases.
    *   **Key characteristic**: They depend only on `domain` types and `ports` interfaces, not on specific adapter implementations.

### 2.2. Adapters

Adapters are the components that connect the core to the outside world. They implement the `ports` interfaces.

*   **`internal/adapters/driving/` (Primary Adapters)**:
    *   Implementations that *drive* the core by calling its `driving` ports.
    *   **`http/`**: Handles HTTP requests, translates them into calls to `AuthorizationService` (or specific enforcers), and formats responses. It uses a router (e.g., Gin) but the core is unaware of this specific choice.
    *   **`grpc/`**: Handles gRPC requests, translates them into calls to `AuthorizationService` (or specific enforcers), and formats responses.

*   **`internal/adapters/driven/` (Secondary Adapters)**:
    *   Implementations that are *driven* by the core by implementing its `driven` ports.
    *   **`persistence/`**:
        *   Provides concrete implementations for various database systems (e.g., `sqlite/`, `postgres/`).
        *   Each subdirectory contains implementations of `ACLPolicyRepository`, `RBACPolicyRepository`, `ABACPolicyRepository`, `AttributeRepository`, and `ReBACRepository` using the respective database driver (e.g., GORM).
    *   **`casbin/`**:
        *   Wraps the Casbin library to implement `ACLPolicyRepository` and `RBACPolicyRepository`. This allows the core to use Casbin's capabilities without direct dependency on the Casbin library itself.

### 2.3. Infrastructure

This layer handles low-level, cross-cutting concerns that are typically initialized once at application startup.

*   **`internal/infrastructure/database/`**: Manages database connection establishment (e.g., GORM setup).
*   **`internal/infrastructure/logger/`**: Configures and provides logging utilities.

### 2.4. Shared

Contains common utilities and data transfer objects (DTOs) used across different layers.

*   **`internal/shared/dto.go`**: Defines request and response structures for APIs.
*   **`internal/shared/util.go`**: General helper functions.

### 2.5. Configuration

*   **`internal/config/`**: Manages application settings (e.g., database connection strings, port numbers, feature flags for enabling/disabling authorization models).

### 2.6. API Definitions

*   **`api/proto/v1/`**: Contains Protocol Buffers (`.proto`) files for gRPC service definitions. This defines the contract for gRPC communication.

### 2.7. Command Line Interface (CLI)

*   **`cmd/server/`**: The application's entry point. It orchestrates the initialization of configurations, infrastructure components, adapters, and the core services, then starts the driving adapters (HTTP/gRPC servers).

## 3. Model-Specific Separation (ACL, RBAC, ABAC, ReBAC)

A key feature of this architecture is the ability to treat each authorization model (ACL, RBAC, ABAC, ReBAC) as a distinct, pluggable component. This is achieved by:

*   **Dedicated Ports**: Each model has its own `driving` port (e.g., `acl_enforcer.go`, `rebac_enforcer.go`) and corresponding `driven` ports (e.g., `acl_policy_repository.go`, `rebac_repository.go`).
*   **Independent Implementations**: Each model's enforcer (`acl_enforcer_impl.go`, `rebac_enforcer_impl.go`) and repository implementations (`acl_policy_repository_sqlite.go`, `rebac_repository_postgres.go`) are separate files.
*   **Composition in `AuthorizationServiceImpl`**: The main `AuthorizationServiceImpl` composes these individual enforcers. When an authorization request comes in, it delegates to the appropriate enforcer based on the requested model.
*   **Conditional Initialization**: In `cmd/server/main.go`, each model's components (enforcer, repository) are initialized only if explicitly enabled via configuration. If a model is not needed, its related code can be physically removed from the codebase, and the application will still function without it. This ensures minimal footprint and clear separation.

## 4. Technology Choices & Flexibility

The architecture allows for easy swapping of underlying technologies:

*   **HTTP Routers**: The `internal/adapters/driving/http/` directory abstracts the choice of HTTP router. Standard `http.ResponseWriter` and `*http.Request` are used by framework-agnostic handlers, each residing in a dedicated file (e.g., `health.go`, `enforcement.go`, `acl.go`). Specific router implementations (e.g., `gin_router.go`, `chi_router.go`) implement a common `HTTPServer` interface, translating framework-specific contexts to standard Go HTTP types before calling these handlers. This allows for easy swapping of router frameworks by simply changing the implementation within this adapter and updating `main.go` to use the new adapter. The core business logic remains untouched.
*   **Databases**: The `internal/adapters/driven/persistence/` layer provides separate implementations for SQLite and PostgreSQL. The `main.go` determines which database adapter to use based on configuration, injecting the correct repository implementations into the core services. Adding support for another database (e.g., MySQL) would involve creating a new subdirectory (e.g., `mysql/`) with its repository implementations.
*   **Casbin**: The Casbin library is encapsulated within `internal/adapters/driven/casbin/`. If a different authorization library were to be used for ACL/RBAC, only this adapter would need to be modified or replaced.

## 5. Testing Strategy

A multi-layered testing strategy ensures the reliability and correctness of the application:

*   **Unit Tests**:
    *   **Location**: Placed alongside the code they test (e.g., `*_test.go` files within `internal/core/domain/`, `internal/core/services/`, `internal/adapters/`).
    *   **Purpose**: Test individual functions, methods, or small components in isolation. Dependencies are typically mocked or stubbed.
*   **Integration Tests**:
    *   **Location**: `test/integration/`
    *   **Purpose**: Verify the interactions between multiple components or layers (e.g., a service interacting with a repository, or an adapter interacting with an external system like a real database). These tests might use in-memory databases or test containers for external dependencies.
*   **End-to-End (E2E) Tests**:
    *   **Location**: `test/e2e/`
    *   **Purpose**: Validate the entire system from an external perspective, simulating real user interactions through the HTTP or gRPC API. These tests ensure that all components work together as expected in a deployed environment.

## 6. Directory Structure

```
.
├── cmd/                                # Application entry points
│   └── server/                         # Main server application
│       └── main.go                     # Server initialization and startup (HTTP, gRPC, DB connection, dependency injection)
├── internal/                           # Application's private code (not exposed externally)
│   ├── core/                           # The application's core (the hexagon)
│   │   ├── domain/                     # Business entities, value objects, core types
│   │   │   ├── model.go                # AccessControlModel, EnforceRequest, ABACPolicy, Relationship, ReBACPermissionMapping
│   │   │   └── errors.go               # Core domain-specific error definitions
│   │   ├── ports/                      # Interfaces defining what the core needs (driven) and what it offers (driving)
│   │   │   ├── driving/                # Primary ports (application services/use cases)
│   │   │   │   ├── authorization_service.go # Generic authorization service interface
│   │   │   │   ├── acl_enforcer.go     # ACL Enforcer interface
│   │   │   │   ├── rbac_enforcer.go    # RBAC Enforcer interface
│   │   │   │   ├── abac_enforcer.go    # ABAC Enforcer interface
│   │   │   │   └── rebac_enforcer.go   # ReBAC Enforcer interface
│   │   │   └── driven/                 # Secondary ports (repositories, external service interfaces)
│   │   │       ├── acl_policy_repository.go        # ACL policy persistence interface
│   │   │       ├── rbac_policy_repository.go       # RBAC policy persistence interface
│   │   │       ├── abac_policy_repository.go       # ABAC policy and conditions persistence interface
│   │   │       ├── attribute_repository.go         # User/object attributes persistence interface
│   │   │       └── rebac_repository.go             # ReBAC relationship persistence interface
│   │   └── services/                   # Implementations of driving ports (use cases)
│   │       ├── authorization_service_impl.go    # Generic authorization service implementation (composes enforcers)
│   │       ├── acl_enforcer_impl.go             # ACL Enforcer implementation
│   │       │   └── acl_enforcer_impl_test.go    # Unit tests for ACL Enforcer
│   │       ├── rbac_enforcer_impl.go            # RBAC Enforcer implementation
│   │       │   └── rbac_enforcer_impl_test.go   # Unit tests for RBAC Enforcer
│   │       ├── abac_enforcer_impl.go            # ABAC Enforcer implementation
│   │       │   └── abac_enforcer_impl_test.go   # Unit tests for ABAC Enforcer
│   │       └── rebac_enforcer_impl.go           # ReBAC Enforcer implementation
│   │           └── rebac_enforcer_impl_test.go  # Unit tests for ReBAC Enforcer
│   ├── adapters/                       # Implementations of ports (connecting core to external world)
│   │   ├── driving/                    # Primary adapters (drive the core)
│   │   │   ├── http/                   # HTTP REST adapter
│   │   │   │   ├── server.go           # HTTP server interface (HTTPServer)
│   │   │   │   ├── handlers/           # HTTP handlers
│   │   │   │   │   ├── health.go       # Health check endpoint handler
│   │   │   │   │   │   └── health_test.go
│   │   │   │   │   ├── model_info.go   # Supported model information endpoint handler
│   │   │   │   │   │   └── model_info_test.go
│   │   │   │   │   ├── enforcement.go  # General authorization check endpoint handler
│   │   │   │   │   │   └── enforcement_test.go
│   │   │   │   │   ├── acl.go          # ACL-related handlers
│   │   │   │   │   │   └── acl_test.go
│   │   │   │   │   ├── rbac.go         # RBAC-related handlers
│   │   │   │   │   │   └── rbac_test.go
│   │   │   │   │   ├── abac.go         # ABAC-related handlers
│   │   │   │   │   │   └── abac_test.go
│   │   │   │   │   └── rebac.go        # ReBAC-related handlers
│   │   │   │   │       └── rebac_test.go
│   │   │   │   ├── gin_router.go       # Gin implementation of HTTPServer interface
│   │   │   │   │   └── gin_router_test.go
│   │   │   │   ├── chi_router.go       # Chi implementation of HTTPServer interface (example)
│   │   │   │   │   └── chi_router_test.go
│   │   │   │   └── echo_router.go      # Echo implementation of HTTPServer interface (example)
│   │   │   │       └── echo_router_test.go
│   │   │   └── grpc/                   # gRPC adapter
│   │   │       ├── server.go           # Main gRPC server initialization and registration of enabled model services
│   │   │       │   └── server_test.go
│   │   │       ├── authorization_service.go # gRPC implementation for generic authorization (Enforce, GetSupportedModels)
│   │   │       │   └── authorization_service_test.go
│   │   │       ├── health_service.go   # gRPC implementation for health check service
│   │   │       │   └── health_service_test.go
│   │   │       ├── acl_service.go      # gRPC implementation for ACL model-specific service
│   │   │       │   └── acl_service_test.go
│   │   │       ├── rbac_service.go     # gRPC implementation for RBAC model-specific service
│   │   │       │   └── rbac_service_test.go
│   │   │       ├── abac_service.go     # gRPC implementation for ABAC model-specific service
│   │   │       │   └── abac_service_test.go
│   │   │       └── rebac_service.go    # gRPC implementation for ReBAC model-specific service
│   │   │           └── rebac_service_test.go
│   │   └── driven/                     # Secondary adapters (driven by the core)
│   │       ├── persistence/            # Database implementations
│   │       │   ├── sqlite/             # SQLite adapter
│   │       │   │   ├── acl_policy_repository_sqlite.go
│   │       │   │   │   └── acl_policy_repository_sqlite_test.go
│   │       │   │   ├── rbac_policy_repository_sqlite.go
│   │       │   │   │   └── rbac_policy_repository_sqlite_test.go
│   │       │   │   ├── abac_policy_repository_sqlite.go
│   │       │   │   │   └── abac_policy_repository_sqlite_test.go
│   │       │   │   ├── attribute_repository_sqlite.go
│   │       │   │   │   └── attribute_repository_sqlite_test.go
│   │       │   │   └── rebac_repository_sqlite.go
│   │       │   │       └── rebac_repository_sqlite_test.go
│   │       │   ├── postgres/           # PostgreSQL adapter
│   │       │   │   ├── acl_policy_repository_postgres.go
│   │       │   │   │   └── acl_policy_repository_postgres_test.go
│   │       │   │   ├── rbac_policy_repository_postgres.go
│   │       │   │   │   └── rbac_policy_repository_postgres_test.go
│   │       │   │   ├── abac_policy_repository_postgres.go
│   │       │   │   │   └── abac_policy_repository_postgres_test.go
│   │       │   │   ├── attribute_repository_postgres.go
│   │       │   │   │   └── attribute_repository_postgres_test.go
│   │       │   │   └── rebac_repository_postgres.go
│   │       │   │       └── rebac_repository_postgres_test.go
│   │       │   └── common.go           # Common persistence utilities (e.g., GORM models)
│   │       │       └── common_test.go
│   │       └── casbin/                 # Casbin library wrapper
│   │           ├── acl_casbin_adapter.go
│   │           │   └── acl_casbin_adapter_test.go
│   │           └── rbac_casbin_adapter.go
│   │               └── rbac_casbin_adapter_test.go
│   ├── config/                         # Application configuration
│   │   └── config.go
│   │       └── config_test.go
│   ├── shared/                         # Common utilities, DTOs
│   │   ├── dto.go
│   │   │   └── dto_test.go
│   │   └── util.go
│   │       └── util_test.go
│   └── infrastructure/                 # Low-level infrastructure (DB connection, logging)
│       ├── database/                   # Database connection establishment
│       │   └── db.go
│       │       └── db_test.go
│       └── logger/                     # Logging setup
│           └── logger.go
│               └── logger_test.go
├── api/                                # Public API definitions
│   └── proto/                          # Protocol Buffers definitions
│       └── v1/
│           ├── common.proto          # Common messages (e.g., EnforceRequest, EnforceResponse)
│           ├── authorization.proto   # Generic authorization service (Enforce, GetSupportedModels)
│           ├── health.proto          # Health check service
│           ├── acl.proto             # ACL gRPC service and messages
│           ├── rbac.proto            # RBAC gRPC service and messages
│           ├── abac.proto            # ABAC gRPC service and messages
│           └── rebac.proto           # ReBAC gRPC service and messages
├── scripts/                            # Build, run, test scripts
│   ├── build.sh
│   ├── run.sh
│   └── test.sh
├── test/                               # Test files (integration and E2E tests)
│   ├── integration/                    # Integration tests
│   │   ├── auth_integration_test.go
│   │   └── ...
│   └── e2e/                            # End-to-End tests
│       ├── auth_e2e_test.go
│       └── ...
├── Dockerfile
├── go.mod
├── go.sum
├── README.md
├── LICENSE
└── ARCHITECTURE.md
```