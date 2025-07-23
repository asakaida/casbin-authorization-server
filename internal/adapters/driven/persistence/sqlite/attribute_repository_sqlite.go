package sqlite

import (
	"fmt"
	"time"

	"your_project/internal/core/ports/driven"

	"gorm.io/gorm"
)

// UserAttributeDB represents a row in the user_attributes table
type UserAttributeDB struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    string `gorm:"index"`
	Attribute string `gorm:"index"`
	Value     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ObjectAttributeDB represents a row in the object_attributes table
type ObjectAttributeDB struct {
	ID        uint   `gorm:"primaryKey"`
	ObjectID  string `gorm:"index"`
	Attribute string `gorm:"index"`
	Value     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AttributeRepositoryImpl implements driven.AttributeRepository for SQLite.
type AttributeRepositoryImpl struct {
	db *gorm.DB
}

// NewAttributeRepository creates a new AttributeRepositoryImpl.
func NewAttributeRepository(db *gorm.DB) driven.AttributeRepository {
	// Auto-migrate the tables
	err := db.AutoMigrate(&UserAttributeDB{}, &ObjectAttributeDB{})
	if err != nil {
		panic(fmt.Sprintf("failed to migrate attribute tables: %v", err))
	}
	return &AttributeRepositoryImpl{db: db}
}

func (r *AttributeRepositoryImpl) SetUserAttribute(userID, attribute, value string) error {
	var existingAttr UserAttributeDB
	result := r.db.Where("user_id = ? AND attribute = ?", userID, attribute).First(&existingAttr)

	if result.Error == nil {
		// Update existing attribute
		existingAttr.Value = value
		existingAttr.UpdatedAt = time.Now()
		result = r.db.Save(&existingAttr)
	} else if result.Error == gorm.ErrRecordNotFound {
		// Create new attribute
		newAttr := UserAttributeDB{
			UserID:    userID,
			Attribute: attribute,
			Value:     value,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		result = r.db.Create(&newAttr)
	} else {
		return result.Error
	}

	return result.Error
}

func (r *AttributeRepositoryImpl) GetUserAttributes(userID string) (map[string]string, error) {
	var attrs []UserAttributeDB
	result := r.db.Where("user_id = ?", userID).Find(&attrs)
	if result.Error != nil {
		return nil, result.Error
	}

	attributes := make(map[string]string)
	for _, attr := range attrs {
		attributes[attr.Attribute] = attr.Value
	}

	return attributes, nil
}

func (r *AttributeRepositoryImpl) RemoveUserAttribute(userID, attributeKey string) error {
	result := r.db.Where("user_id = ? AND attribute = ?", userID, attributeKey).Delete(&UserAttributeDB{})
	return result.Error
}

func (r *AttributeRepositoryImpl) SetObjectAttribute(objectID, attribute, value string) error {
	var existingAttr ObjectAttributeDB
	result := r.db.Where("object_id = ? AND attribute = ?", objectID, attribute).First(&existingAttr)

	if result.Error == nil {
		// Update existing attribute
		existingAttr.Value = value
		existingAttr.UpdatedAt = time.Now()
		result = r.db.Save(&existingAttr)
	} else if result.Error == gorm.ErrRecordNotFound {
		// Create new attribute
		newAttr := ObjectAttributeDB{
			ObjectID:  objectID,
			Attribute: attribute,
			Value:     value,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		result = r.db.Create(&newAttr)
	} else {
		return result.Error
	}

	return result.Error
}

func (r *AttributeRepositoryImpl) GetObjectAttributes(objectID string) (map[string]string, error) {
	var attrs []ObjectAttributeDB
	result := r.db.Where("object_id = ?", objectID).Find(&attrs)
	if result.Error != nil {
		return nil, result.Error
	}

	attributes := make(map[string]string)
	for _, attr := range attrs {
		attributes[attr.Attribute] = attr.Value
	}

	return attributes, nil
}

func (r *AttributeRepositoryImpl) RemoveObjectAttribute(objectID, attributeKey string) error {
	result := r.db.Where("object_id = ? AND attribute = ?", objectID, attributeKey).Delete(&ObjectAttributeDB{})
	return result.Error
}
