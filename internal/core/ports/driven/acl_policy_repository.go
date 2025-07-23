package driven

// ACLPolicyRepository defines the interface for ACL policy persistence.
type ACLPolicyRepository interface {
	AddPolicy(subject, object, action string) (bool, error)
	RemovePolicy(subject, object, action string) (bool, error)
	GetPolicy() ([][]string, error)
	LoadPolicy() error
	SavePolicy() error
}
