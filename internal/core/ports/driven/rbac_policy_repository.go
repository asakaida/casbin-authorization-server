package driven

// RBACPolicyRepository defines the interface for RBAC policy and role persistence.
type RBACPolicyRepository interface {
	AddPolicy(subject, object, action string) (bool, error)
	RemovePolicy(subject, object, action string) (bool, error)
	GetPolicy() ([][]string, error)
	AddRoleForUser(user, role string) (bool, error)
	RemoveRoleForUser(user, role string) (bool, error)
	GetRolesForUser(user string) ([]string, error)
	LoadPolicy() error
	SavePolicy() error
}
