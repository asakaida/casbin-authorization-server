package driven

// AttributeRepository defines the interface for user and object attribute persistence.
type AttributeRepository interface {
	SetUserAttribute(userID, attribute, value string) error
	GetUserAttributes(userID string) (map[string]string, error)
	RemoveUserAttribute(userID, attributeKey string) error
	SetObjectAttribute(objectID, attribute, value string) error
	GetObjectAttributes(objectID string) (map[string]string, error)
	RemoveObjectAttribute(objectID, attributeKey string) error
}
