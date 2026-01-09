# go-basicauth

Session-based authentication for Gin applications. Handles user registration, login, and session management with sensible defaults.

## Install

```bash
go get github.com/mxcd/go-basicauth
```

## Quick Start

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/mxcd/go-basicauth"
)

func main() {
    r := gin.Default()

    // Generate session keys (store these securely in production)
    secretKey, _ := basicauth.GenerateSessionSecretKey()
    encryptionKey, _ := basicauth.GenerateSessionEncryptionKey()

    settings := basicauth.DefaultSettings()
    settings.SessionSecretKey = secretKey
    settings.SessionEncryptionKey = encryptionKey

    // You need to provide your own storage implementation
    storage := &MyDatabaseStorage{}

    handler, _ := basicauth.NewHandler(&basicauth.Options{
        Engine:                r,
        AuthenticationBaseUrl: "/auth",
        Storage:               storage,
        Settings:              settings,
    })

    handler.RegisterRoutes()

    // Protected routes
    r.GET("/protected", handler.RequireAuth(), func(c *gin.Context) {
        user, _ := basicauth.GetUserFromContext(c)
        c.JSON(200, gin.H{"user": user.Username})
    })

    r.Run(":8080")
}
```

## Routes

The library sets up these endpoints under your configured base URL (default `/auth`):

- `POST /auth/register` - Create new user
- `POST /auth/login` - Login with username or email
- `POST /auth/logout` - Clear session
- `GET /auth/me` - Get current user info

## Storage

You need to implement the `Storage` interface for your database:

```go
type Storage interface {
    CreateUser(user *User) error
    GetUserByUsername(username string) (*User, error)
    GetUserByEmail(email string) (*User, error)
    GetUserByID(id uuid.UUID) (*User, error)
    UpdateUser(user *User) error
    DeleteUser(id uuid.UUID) error
}
```

An in-memory implementation is provided for testing:

```go
storage := basicauth.NewMemoryStorage()
```

## Configuration

```go
settings := basicauth.DefaultSettings()

// Login methods
settings.EnableUsernameLogin = true
settings.EnableEmailLogin = true

// Session
settings.SessionExpiration = 24 * time.Hour
settings.SessionName = "my_session"

// Password requirements
settings.PasswordRequirements.MinLength = 10
settings.PasswordRequirements.RequireUppercase = true
settings.PasswordRequirements.RequireLowercase = true
settings.PasswordRequirements.RequireNumbers = true
settings.PasswordRequirements.RequireSpecial = false

// Cookie settings
settings.CookieSecure = true  // Set to false for local dev without HTTPS
settings.CookieHttpOnly = true
settings.CookieSameSite = http.SameSiteLaxMode

// Custom messages
settings.Messages.LoginSuccess = "Welcome back"
settings.Messages.InvalidCredentials = "Wrong credentials"
```

## Path-Based Access Control

Configure paths that don't require authentication (public) or explicitly require it (private). Longer paths take precedence, so you can set `/` as public and override specific paths like `/api` as private.

```go
settings.PathRules = []basicauth.PathRule{
    // Make all UI routes public
    {Type: basicauth.PublicPathPrefix, Path: "/", Access: basicauth.PathAccessPublic},

    // But require auth for /api routes
    {Type: basicauth.PublicPathPrefix, Path: "/api", Access: basicauth.PathAccessPrivate},

    // Except for health checks
    {Type: basicauth.PublicPathExact, Path: "/api/v1/health", Access: basicauth.PathAccessPublic},
}
```

**How it works:**
- The middleware finds all matching rules for a request path
- It selects the longest matching path (most specific wins)
- It applies the access control from that rule
- If no rule matches, authentication is required by default

**Example:**
- Request to `/` → matches `/` prefix (public) → allowed
- Request to `/about` → matches `/` prefix (public) → allowed
- Request to `/api/users` → matches both `/` and `/api` prefixes, `/api` is longer (private) → requires auth
- Request to `/api/v1/health` → matches `/`, `/api`, and exact `/api/v1/health`, exact match is longest (public) → allowed

**Backward compatibility:**
The old `PublicPaths` field still works and is treated as public rules. Use `PathRules` for the new precedence-based system.

## Security

Sessions are signed with a 64-byte key and encrypted with a 32-byte key using gorilla/sessions. Generate these keys with:

```go
secretKey, _ := basicauth.GenerateSessionSecretKey()       // 64 bytes
encryptionKey, _ := basicauth.GenerateSessionEncryptionKey() // 32 bytes
```

Store these keys securely. Don't commit them to your repository. Use environment variables or a secrets manager.

Passwords are hashed with Argon2id. The library prevents user enumeration by returning generic error messages for failed logins.

## Example Requests

Register:
```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"SecurePass123"}'
```

Login:
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"alice","password":"SecurePass123"}' \
  -c cookies.txt
```

Access protected route:
```bash
curl http://localhost:8080/protected -b cookies.txt
```

## Testing

```bash
go test ./...
```

Check out `examples/simple/main.go` for a working example with in-memory storage.

## License

MIT
