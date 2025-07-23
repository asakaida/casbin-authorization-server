# アーキテクチャ概要

このドキュメントは、Ports and Adapters（ヘキサゴナル）アーキテクチャパターンを採用したマルチモデル認可マイクロサービスのアーキテクチャ設計を概説します。このパターンは、関心の強力な分離を重視し、アプリケーションを非常に柔軟でテストしやすく、外部技術から独立したものにします。

## 1. コア原則

このアーキテクチャの主な目標は以下の通りです。

*   **柔軟性**: コアビジネスロジックに影響を与えることなく、外部技術（例：HTTPフレームワーク、データベース、メッセージングシステム）を簡単に交換できます。
*   **テスト容易性**: コンポーネントを分離し、インターフェースを使用することで、包括的な単体テスト、結合テスト、エンドツーエンドテストを可能にします。
*   **関心の分離**: ビジネスロジックとインフラストラクチャ、外部インターフェースを明確に区別します。
*   **技術独立性**: コアビジネスロジックは、特定の外部技術に依存すべきではありません。

## 2. 主要コンポーネントとレイヤー

アプリケーションは、それぞれ特定の責任を持ついくつかの異なるレイヤーに構造化されています。

### 2.1. コア（ヘキサゴン）

これはアプリケーションの心臓部であり、純粋なビジネスロジックを含み、アプリケーションの機能を定義します。外部技術から完全に独立しています。

*   **`internal/core/domain/`**:
    *   基本的なビジネスエンティティ、値オブジェクト、コアタイプ（例：`AccessControlModel`、`EnforceRequest`、`ABACPolicy`、`Relationship`）を含みます。
    *   ドメイン固有のエラーを定義します。
    *   **主な特徴**: 純粋なGoの構造体とインターフェースであり、外部フレームワークやデータベースへの依存はありません。

*   **`internal/core/ports/`**:
    *   コアが外部とやり取りするためのインターフェース（ポート）を定義します。これらは技術に依存しない契約です。
    *   **`driving/`（プライマリポート）**:
        *   アプリケーションが外部アクターに*提供する*ものを定義するインターフェース（例：`AuthorizationService`、`ACLEnforcer`、`RBACEnforcer`、`ABACEnforcer`、`ReBACEnforcer`）。
        *   これらはアプリケーションのユースケースまたはアプリケーションサービスを表します。
    *   **`driven/`（セカンダリポート）**:
        *   アプリケーションが外部システムから*必要とする*ものを定義するインターフェース（例：`ACLPolicyRepository`、`RBACPolicyRepository`、`ABACPolicyRepository`、`AttributeRepository`、`ReBACRepository`）。
        *   これらはデータ永続化、外部サービス、またはその他のインフラストラクチャに関する抽象化を表します。

*   **`internal/core/services/`**:
    *   `driving`ポートの具体的な実装（例：`authorization_service_impl.go`、`acl_enforcer_impl.go`、`rbac_enforcer_impl.go`、`abac_enforcer_impl.go`、`rebac_enforcer_impl.go`）を含みます。
    *   これらのサービスはドメインロジックを調整し、ユースケースを達成するために`driven`ポートとやり取りします。
    *   **主な特徴**: 特定のアダプター実装ではなく、`domain`タイプと`ports`インターフェースにのみ依存します。

### 2.2. アダプター

アダプターは、コアを外部と接続するコンポーネントです。`ports`インターフェースを実装します。

*   **`internal/adapters/driving/`（プライマリアダプター）**:
    *   `driving`ポートを呼び出すことでコアを*駆動する*実装。
    *   **`http/`**: HTTPリクエストを処理し、それらを`AuthorizationService`（または特定のエンフォーサー）への呼び出しに変換し、レスポンスをフォーマットします。ルーター（例：Gin）を使用しますが、コアはこの特定の選択を認識しません。
    *   **`grpc/`**: gRPCリクエストを処理し、それらを`AuthorizationService`（または特定のエンフォーサー）への呼び出しに変換し、レスポンスをフォーマットします。

*   **`internal/adapters/driven/`（セカンダリアダプター）**:
    *   `driven`ポートを実装することでコアによって*駆動される*実装。
    *   **`persistence/`**:
        *   さまざまなデータベースシステム（例：`sqlite/`、`postgres/`）の具体的な実装を提供します。
        *   各サブディレクトリには、それぞれのデータベースドライバー（例：GORM）を使用した`ACLPolicyRepository`、`RBACPolicyRepository`、`ABACPolicyRepository`、`AttributeRepository`、および`ReBACRepository`の実装が含まれます。
    *   **`casbin/`**:
        *   Casbinライブラリをラップして`ACLPolicyRepository`と`RBACPolicyRepository`を実装します。これにより、コアはCasbinの機能を使用できます。

### 2.3. インフラストラクチャ

このレイヤーは、アプリケーションの起動時に一度だけ初期化されるような低レベルの横断的な関心事を処理します。

*   **`internal/infrastructure/database/`**: データベース接続の確立（例：GORMセットアップ）を管理します。
*   **`internal/infrastructure/logger/`**: ロギングユーティリティを設定し、提供します。

### 2.4. 共有

異なるレイヤー間で共通して使用される共通ユーティリティとデータ転送オブジェクト（DTO）を含みます。

*   **`internal/shared/dto.go`**: APIのリクエストおよびレスポンス構造体を定義します。
*   **`internal/shared/util.go`**: 一般的なヘルパー関数。

### 2.5. 設定

*   **`internal/config/`**: アプリケーション設定（例：データベース接続文字列、ポート番号、認可モデルの有効/無効を切り替える機能フラグ）を管理します。

### 2.6. API定義

*   **`api/proto/v1/`**: gRPCサービス定義用のProtocol Buffers（`.proto`）ファイルを含みます。これはgRPC通信の契約を定義します。

### 2.7. コマンドラインインターフェース（CLI）

*   **`cmd/server/`**: アプリケーションのエントリポイントです。設定、インフラストラクチャコンポーネント、アダプター、およびコアサービスの初期化を調整し、駆動アダプター（HTTP/gRPCサーバー）を起動します。

## 3. モデル固有の分離（ACL、RBAC、ABAC、ReBAC）

このアーキテクチャの主要な特徴は、各認可モデル（ACL、RBAC、ABAC、ReBAC）を個別のプラグイン可能なコンポーネントとして扱う能力です。これは以下によって実現されます。

*   **専用ポート**: 各モデルには独自の`driving`ポート（例：`acl_enforcer.go`、`rebac_enforcer.go`）と、対応する`driven`ポート（例：`acl_policy_repository.go`、`rebac_repository.go`）があります。
*   **独立した実装**: 各モデルのエンフォーサー（`acl_enforcer_impl.go`、`rebac_enforcer_impl.go`）とリポジトリ実装（`acl_policy_repository_sqlite.go`、`rebac_repository_postgres.go`）は別々のファイルです。
*   **`AuthorizationServiceImpl`でのコンポジション**: メインの`AuthorizationServiceImpl`は、これらの個々のエンフォーサーをコンポジションします。認可リクエストが来た場合、要求されたモデルに基づいて適切なエンフォーサーに委譲します。
*   **条件付き初期化**: `cmd/server/main.go`では、各モデルのコンポーネント（エンフォーサー、リポジトリ）は、設定で明示的に有効になっている場合にのみ初期化されます。モデルが不要な場合、関連するコードをコードベースから物理的に削除でき、アプリケーションはそれなしで機能します。これにより、最小限のフットプリントと明確な分離が保証されます。

## 4. 技術選択と柔軟性

このアーキテクチャにより、基盤となる技術を簡単に交換できます。

*   **HTTPルーター**: `internal/adapters/driving/http/`ディレクトリはHTTPルーターの選択を抽象化します。標準の`http.ResponseWriter`と`*http.Request`を使用するフレームワーク非依存のハンドラーを、それぞれ専用のファイル（例：`health.go`、`enforcement.go`、`acl.go`）に配置して提供します。特定のルーター実装（例：`gin_router.go`、`chi_router.go`）は共通の`HTTPServer`インターフェースを実装し、フレームワーク固有のコンテキストを標準のGo HTTPタイプに変換してからこれらのハンドラーを呼び出します。これにより、このアダプター内の実装を変更し、`main.go`で新しいアダプターを使用するように更新するだけで、ルーターフレームワークを簡単に交換できます。コアビジネスロジックは影響を受けません。
*   **データベース**: `internal/adapters/driven/persistence/`レイヤーは、SQLiteとPostgreSQLの個別の実装を提供します。`main.go`は、設定に基づいてどのデータベースアダプターを使用するかを決定し、正しいリポジトリ実装をコアサービスに注入します。別のデータベース（例：MySQL）のサポートを追加するには、新しいサブディレクトリ（例：`mysql/`）とそのリポジトリ実装を作成するだけです。
*   **Casbin**: Casbinライブラリは`internal/adapters/driven/casbin/`内にカプセル化されています。ACL/RBACに別の認可ライブラリを使用する場合、このアダプターのみを変更または交換する必要があります。

## 5. テスト戦略

多層的なテスト戦略により、アプリケーションの信頼性と正確性が保証されます。

*   **単体テスト**:
    *   **場所**: テスト対象のコードの隣に配置されます（例：`internal/core/domain/`、`internal/core/services/`、`internal/adapters/`内の`*_test.go`ファイル）。
    *   **目的**: 個々の関数、メソッド、または小さなコンポーネントを分離してテストします。依存関係は通常、モックまたはスタブ化されます。
*   **結合テスト**:
    *   **場所**: `test/integration/`
    *   **目的**: 複数のコンポーネントまたはレイヤー間の相互作用を検証します（例：サービスとリポジトリ間の相互作用、またはアダプターと実際のデータベースなどの外部システム間の相互作用）。これらのテストでは、インメモリデータベースやテストコンテナを外部依存関係に使用する場合があります。
*   **エンドツーエンド（E2E）テスト**:
    *   **場所**: `test/e2e/`
    *   **目的**: HTTPまたはgRPC APIを介して実際のユーザーインタラクションをシミュレートし、外部の視点からシステム全体を検証します。これらのテストは、デプロイされた環境で全てのコンポーネントが期待通りに連携して動作することを確認します。

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
│   │       │   │   │   └── attribute_repository_repository_sqlite_test.go
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
└── ARCHITECTURE_JA.md
```