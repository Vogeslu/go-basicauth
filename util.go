package basicauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Security thresholds to prevent DoS attacks via malicious hash strings.
const (
	MaxMemory      = 128 * 1024 // 128 MiB (Hard limit for verification)
	MaxIterations  = 50
	MaxParallelism = 8
)

// Minimum security thresholds to prevent acceptance of weakened hashes.
const (
	MinMemory     = 32 * 1024 // 32 MiB minimum
	MinIterations = 1
	MinSaltLength = 16
	MinKeyLength  = 16
)

var (
	ErrInvalidHash         = errors.New("invalid encoded hash")
	ErrIncompatibleVersion = errors.New("incompatible argon2 version")
	ErrParamLimitExceeded  = errors.New("hash parameters exceed security limits")
)

type Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultPasswordHashingParams = Params{
	Memory:      64 * 1024, // 64 MiB
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

func HashPassword(password string, p Params) (string, error) {
	if len(password) == 0 || len(password) > 72 {
		return "", errors.New("password length must be between 1 and 72 characters")
	}

	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	b64 := base64.RawStdEncoding
	encodedSalt := b64.EncodeToString(salt)
	encodedHash := b64.EncodeToString(hash)

	// Format: $argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, encodedSalt, encodedHash,
	), nil
}

func VerifyPassword(password, encodedHash string) (bool, Params, error) {
	parts := strings.Split(encodedHash, "$")
	// Format: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
	if len(parts) != 6 {
		return false, Params{}, ErrInvalidHash
	}
	if parts[1] != "argon2id" {
		return false, Params{}, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, Params{}, ErrInvalidHash
	}
	if version != argon2.Version {
		return false, Params{}, ErrIncompatibleVersion
	}

	p, err := decodeParams(parts[3])
	if err != nil {
		return false, Params{}, ErrInvalidHash
	}

	if p.Memory > MaxMemory || p.Iterations > MaxIterations || p.Parallelism > MaxParallelism {
		return false, Params{}, ErrParamLimitExceeded
	}

	if p.Memory < MinMemory || p.Iterations < MinIterations || p.Parallelism < 1 {
		return false, Params{}, ErrParamLimitExceeded
	}

	b64 := base64.RawStdEncoding

	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, Params{}, ErrInvalidHash
	}

	hash, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, Params{}, ErrInvalidHash
	}

	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(hash))

	if len(salt) < MinSaltLength || len(hash) < MinKeyLength {
		return false, Params{}, ErrInvalidHash
	}

	otherHash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, p, nil
	}
	return false, p, nil
}

func decodeParams(s string) (Params, error) {
	// Initialize with zero values; Verify() will fill in Lengths from decoded bytes
	p := Params{}

	kv := strings.Split(s, ",")
	if len(kv) != 3 {
		return Params{}, errors.New("bad params format")
	}

	for _, item := range kv {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			return Params{}, errors.New("bad param format")
		}
		key, val := parts[0], parts[1]

		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return Params{}, err
		}

		switch key {
		case "m":
			p.Memory = uint32(n)
		case "t":
			p.Iterations = uint32(n)
		case "p":
			if n > 255 {
				return Params{}, errors.New("parallelism exceeds uint8 range")
			}
			p.Parallelism = uint8(n)
		default:
			return Params{}, errors.New("unknown param")
		}
	}

	if p.Memory == 0 || p.Iterations == 0 || p.Parallelism == 0 {
		return Params{}, errors.New("params cannot be zero")
	}
	return p, nil
}
