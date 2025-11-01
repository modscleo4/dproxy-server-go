package auth

import (
	"testing"
)

func TestPasswordHashAndVerify(t *testing.T) {
	// Use deterministic salt for reproducible tests
	salt := []byte("testsalt12345678")
	password := "P@ssw0rd!"
	// use a small cost so tests run fast (scrypt N = 1<<cost)
	cost := 10

	hash, err := PasswordHash(password, salt, cost)
	if err != nil {
		t.Fatalf("PasswordHash returned error: %v", err)
	}

	if hash == "" {
		t.Fatalf("PasswordHash returned empty hash")
	}

	ok, err := PasswordVerify(hash, password)
	if err != nil {
		t.Fatalf("PasswordVerify returned unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("PasswordVerify failed for correct password")
	}

	// Wrong password should not validate
	ok, err = PasswordVerify(hash, "wrongpassword")
	if err == nil && ok {
		t.Fatalf("PasswordVerify returned true for wrong password")
	}
}

func TestPasswordVerifyMalformedHash(t *testing.T) {
	_, err := PasswordVerify("not-a-valid-hash", "password")
	if err == nil {
		t.Fatalf("PasswordVerify expected error for malformed hash, got nil")
	}
}
