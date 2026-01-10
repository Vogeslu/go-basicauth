package basicauth

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID `json:"id"`
	Username     *string   `json:"username,omitempty"`
	Email        *string   `json:"email,omitempty"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`

	IsTechnicalUser bool    `json:"isTechnicalUser"` // For future API key support
	APIKeyHash      *string `json:"-"`
}

// UserContextProvider is implemented by applications to receive
// authenticated user information and set up their own context.
type UserContextProvider interface {
	// SetUserContext is called after successful authentication.
	// The application should store the user info in gin.Context
	// for later retrieval in handlers.
	SetUserContext(c *gin.Context, user *User)
}

type RegisterRequest struct {
	Username *string `json:"username" binding:"omitempty,min=3,max=50"`
	Email    *string `json:"email" binding:"omitempty,email"`
	Password string  `json:"password" binding:"required"`
}

type LoginRequest struct {
	Identifier string `json:"identifier" binding:"required"`
	Password   string `json:"password" binding:"required"`
}

type UserResponse struct {
	ID              uuid.UUID `json:"id"`
	Username        *string   `json:"username,omitempty"`
	Email           *string   `json:"email,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
	IsTechnicalUser bool      `json:"isTechnicalUser"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type PasswordRequirements struct {
	MinLength        int  `json:"minLength"`
	RequireUppercase bool `json:"requireUppercase"`
	RequireLowercase bool `json:"requireLowercase"`
	RequireNumbers   bool `json:"requireNumbers"`
	RequireSpecial   bool `json:"requireSpecial"`
}

type PublicPathType string

const (
	PublicPathExact  PublicPathType = "exact"
	PublicPathPrefix PublicPathType = "prefix"
)

type PublicPath struct {
	Type PublicPathType
	Path string
}

type PathAccessType string

const (
	PathAccessPublic  PathAccessType = "public"
	PathAccessPrivate PathAccessType = "private"
)

type PathRule struct {
	Type   PublicPathType
	Path   string
	Access PathAccessType
}

type Messages struct {
	RegistrationSuccess string
	LoginSuccess        string
	LogoutSuccess       string
	InvalidCredentials  string
	UserAlreadyExists   string
	PasswordTooWeak     string
	InternalError       string
	Unauthorized        string
}

type BasicAuthSettings struct {
	EnableUsernameLogin bool
	EnableEmailLogin    bool

	SessionName          string
	SessionExpiration    time.Duration
	SessionSecretKey     []byte // 64 bytes for HMAC-SHA256
	SessionEncryptionKey []byte // 32 bytes for AES-256

	CookieSecure   bool
	CookieHttpOnly bool
	CookieSameSite http.SameSite
	CookiePath     string
	CookieDomain   string

	PublicPaths []PublicPath // Deprecated: use PathRules instead
	PathRules   []PathRule

	PasswordRequirements PasswordRequirements
	Messages             Messages
	HashingParams        Params
}

func DefaultSettings() *BasicAuthSettings {
	return &BasicAuthSettings{
		EnableUsernameLogin: true,
		EnableEmailLogin:    true,
		SessionName:         "basicauth_session",
		SessionExpiration:   24 * time.Hour,
		CookieSecure:        true,
		CookieHttpOnly:      true,
		CookieSameSite:      http.SameSiteLaxMode,
		CookiePath:          "/",
		CookieDomain:        "",
		PasswordRequirements: PasswordRequirements{
			MinLength:        8,
			RequireUppercase: true,
			RequireLowercase: true,
			RequireNumbers:   true,
			RequireSpecial:   false,
		},
		Messages: Messages{
			RegistrationSuccess: "Registration successful",
			LoginSuccess:        "Login successful",
			LogoutSuccess:       "Logout successful",
			InvalidCredentials:  "Invalid credentials",
			UserAlreadyExists:   "User already exists",
			PasswordTooWeak:     "Password does not meet requirements",
			InternalError:       "Internal server error",
			Unauthorized:        "Unauthorized",
		},
		HashingParams: DefaultPasswordHashingParams,
	}
}

var (
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrUserAlreadyExists    = errors.New("user already exists")
	ErrUserNotFound         = errors.New("user not found")
	ErrInvalidEmail         = errors.New("invalid email format")
	ErrInvalidUsername      = errors.New("invalid username format")
	ErrPasswordTooWeak      = errors.New("password does not meet requirements")
	ErrSessionNotFound      = errors.New("session not found")
	ErrUnauthorized         = errors.New("unauthorized")
	ErrInternalServer       = errors.New("internal server error")
	ErrMissingCredentials   = errors.New("username or email required")
	ErrRegistrationDisabled = errors.New("registration method not enabled")
)
