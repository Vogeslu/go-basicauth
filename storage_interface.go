package basicauth

import "github.com/google/uuid"

type Storage interface {
	CreateUser(user *User) error
	GetUserByUsername(username string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	GetUserByID(id uuid.UUID) (*User, error)
	UpdateUser(user *User) error
	DeleteUser(id uuid.UUID) error

	// Future: API key authentication
	// GetUserByAPIKeyHash(apiKeyHash string) (*User, error)
	// UpdateAPIKey(userID uuid.UUID, apiKeyHash string) error
}
