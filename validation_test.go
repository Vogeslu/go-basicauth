package basicauth

import (
	"testing"
)

// Email Validation Tests
func TestValidateEmail_Valid(t *testing.T) {
	validEmails := []string{
		"test@example.com",
		"user.name@example.com",
		"user+tag@example.co.uk",
		"123@example.com",
		"test_user@example-domain.com",
	}

	for _, email := range validEmails {
		t.Run(email, func(t *testing.T) {
			if err := validateEmail(email); err != nil {
				t.Errorf("expected valid email %q, got error: %v", email, err)
			}
		})
	}
}

func TestValidateEmail_Invalid(t *testing.T) {
	invalidEmails := []string{
		"",
		"notanemail",
		"@example.com",
		"user@",
		"user @example.com",
		"user@example",
		"user@@example.com",
	}

	for _, email := range invalidEmails {
		t.Run(email, func(t *testing.T) {
			if err := validateEmail(email); err != ErrInvalidEmail {
				t.Errorf("expected ErrInvalidEmail for %q, got: %v", email, err)
			}
		})
	}
}

// Username Validation Tests
func TestValidateUsername_Valid(t *testing.T) {
	// Manually create 50-char string
	fiftyChars := ""
	for i := 0; i < 50; i++ {
		fiftyChars += "a"
	}

	validUsernames := []string{
		"abc",
		"user123",
		"test_user",
		"User_123",
		fiftyChars, // 50 characters
	}

	for _, username := range validUsernames {
		t.Run(username, func(t *testing.T) {
			if err := validateUsername(username); err != nil {
				t.Errorf("expected valid username %q, got error: %v", username, err)
			}
		})
	}
}

func TestValidateUsername_Invalid(t *testing.T) {
	// Manually create 51-char string
	fiftyOneChars := ""
	for i := 0; i < 51; i++ {
		fiftyOneChars += "a"
	}

	invalidTestCases := []struct {
		username string
		reason   string
	}{
		{"ab", "too short"},
		{"", "empty"},
		{fiftyOneChars, "too long"},
		{"user name", "contains space"},
		{"user-name", "contains hyphen"},
		{"user.name", "contains dot"},
		{"user@name", "contains at sign"},
	}

	for _, tc := range invalidTestCases {
		t.Run(tc.reason, func(t *testing.T) {
			if err := validateUsername(tc.username); err == nil {
				t.Errorf("expected error for %q (%s), got nil", tc.username, tc.reason)
			}
		})
	}
}

// Password Validation Tests
func TestValidatePassword_MinLength(t *testing.T) {
	reqs := PasswordRequirements{
		MinLength:        8,
		RequireUppercase: false,
		RequireLowercase: false,
		RequireNumbers:   false,
		RequireSpecial:   false,
	}

	// Valid: meets minimum length
	if err := validatePassword("12345678", reqs); err != nil {
		t.Errorf("expected valid password, got error: %v", err)
	}

	// Invalid: too short
	if err := validatePassword("1234567", reqs); err == nil {
		t.Error("expected error for password too short, got nil")
	}
}

func TestValidatePassword_RequireUppercase(t *testing.T) {
	reqs := PasswordRequirements{
		MinLength:        4,
		RequireUppercase: true,
		RequireLowercase: false,
		RequireNumbers:   false,
		RequireSpecial:   false,
	}

	// Valid: contains uppercase
	if err := validatePassword("testA", reqs); err != nil {
		t.Errorf("expected valid password, got error: %v", err)
	}

	// Invalid: no uppercase
	if err := validatePassword("test1", reqs); err == nil {
		t.Error("expected error for missing uppercase, got nil")
	}
}

func TestValidatePassword_RequireLowercase(t *testing.T) {
	reqs := PasswordRequirements{
		MinLength:        4,
		RequireUppercase: false,
		RequireLowercase: true,
		RequireNumbers:   false,
		RequireSpecial:   false,
	}

	// Valid: contains lowercase
	if err := validatePassword("TESTa", reqs); err != nil {
		t.Errorf("expected valid password, got error: %v", err)
	}

	// Invalid: no lowercase
	if err := validatePassword("TEST1", reqs); err == nil {
		t.Error("expected error for missing lowercase, got nil")
	}
}

func TestValidatePassword_RequireNumbers(t *testing.T) {
	reqs := PasswordRequirements{
		MinLength:        4,
		RequireUppercase: false,
		RequireLowercase: false,
		RequireNumbers:   true,
		RequireSpecial:   false,
	}

	// Valid: contains numbers
	if err := validatePassword("test1", reqs); err != nil {
		t.Errorf("expected valid password, got error: %v", err)
	}

	// Invalid: no numbers
	if err := validatePassword("testA", reqs); err == nil {
		t.Error("expected error for missing numbers, got nil")
	}
}

func TestValidatePassword_RequireSpecial(t *testing.T) {
	reqs := PasswordRequirements{
		MinLength:        4,
		RequireUppercase: false,
		RequireLowercase: false,
		RequireNumbers:   false,
		RequireSpecial:   true,
	}

	// Valid: contains special characters
	specialChars := []string{"!", "@", "#", "$", "%", "^", "&", "*", "(", ")", ",", ".", "?", "\"", ":", "{", "}", "|", "<", ">"}
	for _, char := range specialChars {
		password := "test" + char
		if err := validatePassword(password, reqs); err != nil {
			t.Errorf("expected valid password with special char %q, got error: %v", char, err)
		}
	}

	// Invalid: no special characters
	if err := validatePassword("test1", reqs); err == nil {
		t.Error("expected error for missing special characters, got nil")
	}
}

func TestValidatePassword_AllRequirements(t *testing.T) {
	reqs := PasswordRequirements{
		MinLength:        8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSpecial:   true,
	}

	// Valid: meets all requirements
	validPasswords := []string{
		"Passw0rd!",
		"Test123$Pass",
		"MyP@ssw0rd",
	}

	for _, password := range validPasswords {
		t.Run(password, func(t *testing.T) {
			if err := validatePassword(password, reqs); err != nil {
				t.Errorf("expected valid password %q, got error: %v", password, err)
			}
		})
	}

	// Invalid: missing various requirements
	invalidPasswords := []struct {
		password string
		reason   string
	}{
		{"short1!", "too short"},
		{"password123!", "no uppercase"},
		{"PASSWORD123!", "no lowercase"},
		{"PasswordABC!", "no numbers"},
		{"Password123", "no special"},
	}

	for _, tc := range invalidPasswords {
		t.Run(tc.reason, func(t *testing.T) {
			if err := validatePassword(tc.password, reqs); err == nil {
				t.Errorf("expected error for %q (%s), got nil", tc.password, tc.reason)
			}
		})
	}
}

func TestValidatePassword_DefaultRequirements(t *testing.T) {
	// Test with default settings from types.go
	reqs := PasswordRequirements{
		MinLength:        8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSpecial:   false,
	}

	// Valid passwords
	if err := validatePassword("Password123", reqs); err != nil {
		t.Errorf("expected valid password, got error: %v", err)
	}

	// Invalid: missing uppercase
	if err := validatePassword("password123", reqs); err == nil {
		t.Error("expected error for missing uppercase, got nil")
	}

	// Invalid: missing number
	if err := validatePassword("PasswordABC", reqs); err == nil {
		t.Error("expected error for missing number, got nil")
	}
}
