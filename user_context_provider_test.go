package basicauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// MockUserContextProvider is a test implementation of UserContextProvider
// that tracks all calls to SetUserContext
type MockUserContextProvider struct {
	mu    sync.Mutex
	Calls []MockSetUserContextCall
}

type MockSetUserContextCall struct {
	UserID   uuid.UUID
	Username *string
	Email    *string
}

func NewMockUserContextProvider() *MockUserContextProvider {
	return &MockUserContextProvider{
		Calls: make([]MockSetUserContextCall, 0),
	}
}

func (m *MockUserContextProvider) SetUserContext(c *gin.Context, user *User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = append(m.Calls, MockSetUserContextCall{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
	})
}

func (m *MockUserContextProvider) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Calls)
}

func (m *MockUserContextProvider) LastCall() *MockSetUserContextCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Calls) == 0 {
		return nil
	}
	return &m.Calls[len(m.Calls)-1]
}

func (m *MockUserContextProvider) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = make([]MockSetUserContextCall, 0)
}

// setupTestHandlerWithContextProvider creates a handler with a UserContextProvider
func setupTestHandlerWithContextProvider(provider UserContextProvider) (*Handler, *gin.Engine) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	storage := NewMemoryStorage()

	settings := DefaultSettings()
	secretKey, _ := GenerateSessionSecretKey()
	encryptionKey, _ := GenerateSessionEncryptionKey()
	settings.SessionSecretKey = secretKey
	settings.SessionEncryptionKey = encryptionKey

	handler, err := NewHandler(&Options{
		Engine:                r,
		AuthenticationBaseUrl: "/auth",
		Storage:               storage,
		Settings:              settings,
		UserContextProvider:   provider,
	})

	if err != nil {
		panic(err)
	}

	handler.RegisterRoutes()

	return handler, r
}

func TestUserContextProvider_CalledAfterLogin(t *testing.T) {
	mockProvider := NewMockUserContextProvider()
	_, r := setupTestHandlerWithContextProvider(mockProvider)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// First register a user
	regBody := map[string]interface{}{
		"username": "logintest",
		"email":    "login@test.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)

	// Reset the mock to clear registration call
	mockProvider.Reset()

	// Now login
	loginBody := map[string]interface{}{
		"identifier": "logintest",
		"password":   "Password123",
	}
	loginJSON, _ := json.Marshal(loginBody)
	req, _ = http.NewRequest("POST", server.URL+"/auth/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify SetUserContext was called
	if mockProvider.CallCount() != 1 {
		t.Errorf("expected SetUserContext to be called once, got %d calls", mockProvider.CallCount())
	}

	lastCall := mockProvider.LastCall()
	if lastCall == nil {
		t.Fatal("expected SetUserContext to be called")
	}

	if lastCall.Username == nil || *lastCall.Username != "logintest" {
		t.Errorf("expected username 'logintest', got %v", lastCall.Username)
	}

	if lastCall.Email == nil || *lastCall.Email != "login@test.com" {
		t.Errorf("expected email 'login@test.com', got %v", lastCall.Email)
	}
}

func TestUserContextProvider_CalledAfterRegistration(t *testing.T) {
	mockProvider := NewMockUserContextProvider()
	_, r := setupTestHandlerWithContextProvider(mockProvider)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register a user
	regBody := map[string]interface{}{
		"username": "registertest",
		"email":    "register@test.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("registration request failed: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", resp.StatusCode)
	}

	// Verify SetUserContext was called
	if mockProvider.CallCount() != 1 {
		t.Errorf("expected SetUserContext to be called once, got %d calls", mockProvider.CallCount())
	}

	lastCall := mockProvider.LastCall()
	if lastCall == nil {
		t.Fatal("expected SetUserContext to be called")
	}

	if lastCall.Username == nil || *lastCall.Username != "registertest" {
		t.Errorf("expected username 'registertest', got %v", lastCall.Username)
	}

	if lastCall.Email == nil || *lastCall.Email != "register@test.com" {
		t.Errorf("expected email 'register@test.com', got %v", lastCall.Email)
	}

	// Verify user ID is not empty
	if lastCall.UserID == uuid.Nil {
		t.Error("expected non-nil user ID")
	}
}

func TestUserContextProvider_CalledInRequireAuthMiddleware(t *testing.T) {
	mockProvider := NewMockUserContextProvider()
	handler, r := setupTestHandlerWithContextProvider(mockProvider)

	// Add a protected route
	r.GET("/protected", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "protected"})
	})

	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register and get session cookie
	regBody := map[string]interface{}{
		"username": "middlewaretest",
		"email":    "middleware@test.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)
	cookies := resp.Cookies()

	// Reset the mock to clear registration call
	mockProvider.Reset()

	// Access protected route with session
	req, _ = http.NewRequest("GET", server.URL+"/protected", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("protected request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify SetUserContext was called
	if mockProvider.CallCount() != 1 {
		t.Errorf("expected SetUserContext to be called once, got %d calls", mockProvider.CallCount())
	}

	lastCall := mockProvider.LastCall()
	if lastCall == nil {
		t.Fatal("expected SetUserContext to be called")
	}

	if lastCall.Username == nil || *lastCall.Username != "middlewaretest" {
		t.Errorf("expected username 'middlewaretest', got %v", lastCall.Username)
	}
}

func TestUserContextProvider_NotCalledOnFailedLogin(t *testing.T) {
	mockProvider := NewMockUserContextProvider()
	_, r := setupTestHandlerWithContextProvider(mockProvider)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Try to login with non-existent user
	loginBody := map[string]interface{}{
		"identifier": "nonexistent",
		"password":   "Password123",
	}
	loginJSON, _ := json.Marshal(loginBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", resp.StatusCode)
	}

	// Verify SetUserContext was NOT called
	if mockProvider.CallCount() != 0 {
		t.Errorf("expected SetUserContext not to be called, got %d calls", mockProvider.CallCount())
	}
}

func TestUserContextProvider_NotCalledOnUnauthenticatedRequest(t *testing.T) {
	mockProvider := NewMockUserContextProvider()
	handler, r := setupTestHandlerWithContextProvider(mockProvider)

	// Add a protected route
	r.GET("/protected", handler.RequireAuth(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "protected"})
	})

	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Access protected route without session
	req, _ := http.NewRequest("GET", server.URL+"/protected", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("protected request failed: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", resp.StatusCode)
	}

	// Verify SetUserContext was NOT called
	if mockProvider.CallCount() != 0 {
		t.Errorf("expected SetUserContext not to be called, got %d calls", mockProvider.CallCount())
	}
}

func TestUserContextProvider_NilProviderDoesNotPanic(t *testing.T) {
	// This test verifies backward compatibility - nil provider should not cause panic
	_, r := setupTestHandlerWithContextProvider(nil)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register a user (should not panic)
	regBody := map[string]interface{}{
		"username": "niltest",
		"email":    "nil@test.com",
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("registration request failed: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", resp.StatusCode)
	}

	cookies := resp.Cookies()

	// Login (should not panic)
	loginBody := map[string]interface{}{
		"identifier": "niltest",
		"password":   "Password123",
	}
	loginJSON, _ := json.Marshal(loginBody)
	req, _ = http.NewRequest("POST", server.URL+"/auth/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Access /me with session (should not panic)
	req, _ = http.NewRequest("GET", server.URL+"/auth/me", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("/me request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestUserContextProvider_ReceivesCorrectUserData(t *testing.T) {
	mockProvider := NewMockUserContextProvider()
	_, r := setupTestHandlerWithContextProvider(mockProvider)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}

	// Register with specific data
	username := "datatest"
	email := "data@test.com"
	regBody := map[string]interface{}{
		"username": username,
		"email":    email,
		"password": "Password123",
	}
	regJSON, _ := json.Marshal(regBody)
	req, _ := http.NewRequest("POST", server.URL+"/auth/register", bytes.NewBuffer(regJSON))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("registration request failed: %v", err)
	}

	// Parse response to get user ID
	var successResp SuccessResponse
	json.NewDecoder(resp.Body).Decode(&successResp)

	// Get the user data from response
	dataMap, ok := successResp.Data.(map[string]interface{})
	if !ok {
		t.Fatal("expected data to be a map")
	}
	responseUserID := dataMap["id"].(string)

	// Verify SetUserContext received correct data
	lastCall := mockProvider.LastCall()
	if lastCall == nil {
		t.Fatal("expected SetUserContext to be called")
	}

	if lastCall.UserID.String() != responseUserID {
		t.Errorf("expected user ID %s, got %s", responseUserID, lastCall.UserID.String())
	}

	if lastCall.Username == nil || *lastCall.Username != username {
		t.Errorf("expected username '%s', got %v", username, lastCall.Username)
	}

	if lastCall.Email == nil || *lastCall.Email != email {
		t.Errorf("expected email '%s', got %v", email, lastCall.Email)
	}
}
