package basicauth

import (
	"strings"
	"testing"
)

func TestHashPassword_EmptyPassword(t *testing.T) {
	_, err := HashPassword("", DefaultPasswordHashingParams)
	if err == nil {
		t.Error("expected error for empty password, got nil")
	}
	if err.Error() != "password length must be between 1 and 72 characters" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestHashPassword_TooLongPassword(t *testing.T) {
	longPassword := strings.Repeat("a", 73)
	_, err := HashPassword(longPassword, DefaultPasswordHashingParams)
	if err == nil {
		t.Error("expected error for password > 72 characters, got nil")
	}
	if err.Error() != "password length must be between 1 and 72 characters" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestHashPassword_ValidPassword(t *testing.T) {
	password := "validPassword123"
	hash, err := HashPassword(password, DefaultPasswordHashingParams)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}

	// Verify the hash works
	valid, _, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("verification error: %v", err)
	}
	if !valid {
		t.Error("password should verify successfully")
	}
}

func TestVerifyPassword_ShortSalt(t *testing.T) {
	// Create a hash with a 1-byte salt (too short)
	hash := "$argon2id$v=19$m=65536,t=3,p=2$AA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	valid, _, err := VerifyPassword("password", hash)
	if err != ErrInvalidHash {
		t.Errorf("expected ErrInvalidHash for short salt, got: %v", err)
	}
	if valid {
		t.Error("should not verify hash with short salt")
	}
}

func TestVerifyPassword_ShortHash(t *testing.T) {
	// Create a hash with a 1-byte hash (too short)
	hash := "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AA"

	valid, _, err := VerifyPassword("password", hash)
	if err != ErrInvalidHash {
		t.Errorf("expected ErrInvalidHash for short hash, got: %v", err)
	}
	if valid {
		t.Error("should not verify hash with short hash")
	}
}

func TestVerifyPassword_WeakMemory(t *testing.T) {
	// Create a hash with weak memory parameter (1 MiB)
	hash := "$argon2id$v=19$m=1024,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	valid, _, err := VerifyPassword("password", hash)
	if err != ErrParamLimitExceeded {
		t.Errorf("expected ErrParamLimitExceeded for weak memory, got: %v", err)
	}
	if valid {
		t.Error("should not verify hash with weak memory")
	}
}

func TestVerifyPassword_WeakIterations(t *testing.T) {
	// Create a hash with zero iterations (caught by parser's zero-check)
	hash := "$argon2id$v=19$m=65536,t=0,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	valid, _, err := VerifyPassword("password", hash)
	if err != ErrInvalidHash {
		t.Errorf("expected ErrInvalidHash for zero iterations, got: %v", err)
	}
	if valid {
		t.Error("should not verify hash with zero iterations")
	}
}

func TestVerifyPassword_WeakParallelism(t *testing.T) {
	// Create a hash with zero parallelism (caught by parser's zero-check)
	hash := "$argon2id$v=19$m=65536,t=3,p=0$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	valid, _, err := VerifyPassword("password", hash)
	if err != ErrInvalidHash {
		t.Errorf("expected ErrInvalidHash for zero parallelism, got: %v", err)
	}
	if valid {
		t.Error("should not verify hash with zero parallelism")
	}
}

func TestDecodeParams_ParallelismOverflow(t *testing.T) {
	// Test parallelism value > 255 (uint8 overflow)
	_, err := decodeParams("m=65536,t=3,p=256")
	if err == nil {
		t.Error("expected error for parallelism=256, got nil")
	}
	if err.Error() != "parallelism exceeds uint8 range" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDecodeParams_Valid(t *testing.T) {
	p, err := decodeParams("m=65536,t=3,p=2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Memory != 65536 {
		t.Errorf("expected Memory=65536, got %d", p.Memory)
	}
	if p.Iterations != 3 {
		t.Errorf("expected Iterations=3, got %d", p.Iterations)
	}
	if p.Parallelism != 2 {
		t.Errorf("expected Parallelism=2, got %d", p.Parallelism)
	}
}

func TestHashAndVerify_RoundTrip(t *testing.T) {
	testCases := []struct {
		name     string
		password string
	}{
		{"short password", "abc123"},
		{"long password", strings.Repeat("x", 72)},
		{"special characters", "p@ssw0rd!#$%"},
		{"unicode", "пароль密码🔒"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := HashPassword(tc.password, DefaultPasswordHashingParams)
			if err != nil {
				t.Fatalf("hash error: %v", err)
			}

			valid, _, err := VerifyPassword(tc.password, hash)
			if err != nil {
				t.Fatalf("verify error: %v", err)
			}
			if !valid {
				t.Error("password should verify successfully")
			}

			// Verify wrong password fails
			valid, _, err = VerifyPassword(tc.password+"wrong", hash)
			if err != nil {
				t.Fatalf("verify error: %v", err)
			}
			if valid {
				t.Error("wrong password should not verify")
			}
		})
	}
}
