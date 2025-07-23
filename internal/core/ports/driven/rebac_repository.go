package driven

import (
	"your_project/internal/core/domain"
)

// ReBACRepository defines the interface for ReBAC relationship persistence.
type ReBACRepository interface {
	AddRelationship(subject, relationship, object string) error
	RemoveRelationship(subject, relationship, object string) error
	GetRelationships(subject string) ([]domain.Relationship, error)
	LoadAllRelationships() ([]domain.Relationship, error)
}
