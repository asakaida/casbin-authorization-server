package sqlite

import (
	"fmt"
	"time"

	"your_project/internal/core/domain"
	"your_project/internal/core/ports/driven"

	"gorm.io/gorm"
)

// RelationshipRecordDB represents a row in the relationship_records table
type RelationshipRecordDB struct {
	ID           uint   `gorm:"primaryKey"`
	Subject      string `gorm:"index"`
	Relationship string `gorm:"index"`
	Object       string `gorm:"index"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ReBACRepositoryImpl implements driven.ReBACRepository for SQLite.
type ReBACRepositoryImpl struct {
	db *gorm.DB
}

// NewReBACRepository creates a new ReBACRepositoryImpl.
func NewReBACRepository(db *gorm.DB) driven.ReBACRepository {
	// Auto-migrate the table
	err := db.AutoMigrate(&RelationshipRecordDB{})
	if err != nil {
		panic(fmt.Sprintf("failed to migrate RelationshipRecordDB table: %v", err))
	}
	return &ReBACRepositoryImpl{db: db}
}

func (r *ReBACRepositoryImpl) AddRelationship(subject, relationship, object string) error {
	record := RelationshipRecordDB{
		Subject:      subject,
		Relationship: relationship,
		Object:       object,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	result := r.db.Create(&record)
	return result.Error
}

func (r *ReBACRepositoryImpl) RemoveRelationship(subject, relationship, object string) error {
	result := r.db.Where("subject = ? AND relationship = ? AND object = ?", subject, relationship, object).Delete(&RelationshipRecordDB{})
	return result.Error
}

func (r *ReBACRepositoryImpl) GetRelationships(subject string) ([]domain.Relationship, error) {
	var records []RelationshipRecordDB
	result := r.db.Where("subject = ?", subject).Find(&records)
	if result.Error != nil {
		return nil, result.Error
	}

	var relationships []domain.Relationship
	for _, record := range records {
		relationships = append(relationships, domain.Relationship{
			Subject:      record.Subject,
			Relationship: record.Relationship,
			Object:       record.Object,
		})
	}
	return relationships, nil
}

func (r *ReBACRepositoryImpl) LoadAllRelationships() ([]domain.Relationship, error) {
	var records []RelationshipRecordDB
	result := r.db.Find(&records)
	if result.Error != nil {
		return nil, result.Error
	}

	var relationships []domain.Relationship
	for _, record := range records {
		relationships = append(relationships, domain.Relationship{
			Subject:      record.Subject,
			Relationship: record.Relationship,
			Object:       record.Object,
		})
	}
	return relationships, nil
}
