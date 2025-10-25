package cryptography

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	// appPepper is a global secret used to augment password hashing.
	// It is loaded from an environment variable at startup.
	appPepper string
)

func init() {
	appPepper = os.Getenv("PEPPER")
	if appPepper == "" {
		appPepper = "testPepper"
		// panic("SECURITY ERROR: PEPPER environment variable not set")
	}
}

// params holds the configuration for Argon2.
type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

// HashPassword creates an Argon2id hash of a password.
// It returns the hash in a format that includes all the parameters needed for verification.
func HashPassword(password string) (string, error) {
	// Recommended parameters for Argon2id.
	// These should be tuned based on your hardware and security requirements.
	p := &params{
		memory:      64 * 1024, // 64 MB
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   32,
	}

	// Generate a cryptographically secure random salt.
	salt := make([]byte, p.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Combine password and pepper before hashing.
	passwordWithPepper := []byte(password + appPepper)

	// Hash the password using Argon2id.
	hash := argon2.IDKey(passwordWithPepper, salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// Encode the salt and hash to Base64.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Create a standard storable format: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memory, p.iterations, p.parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	p, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	passwordWithPepper := []byte(password + appPepper)

	otherHash := argon2.IDKey(passwordWithPepper, salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}

// decodeHash parses an encoded hash string and extracts the Argon2 parameters, salt, and hash.
func decodeHash(encodedHash string) (p *params, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, fmt.Errorf("invalid hash format")
	}

	if vals[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("unsupported hash type: %s", vals[1])
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil || version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("incompatible version: %d", version)
	}

	p = &params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse parameters: %w", err)
	}

	salt, err = base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	hash, err = base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode hash: %w", err)
	}
	p.keyLength = uint32(len(hash))

	return p, salt, hash, nil
}

func Encrypt(input string) string {
	return input
}

func Decrypt(input string) string {
	return input
}
