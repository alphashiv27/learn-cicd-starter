package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{}
	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected error %q, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKey_MalformedHeader_MissingSpace(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey")
	_, err := GetAPIKey(headers)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected malformed authorization header error, got %v", err)
	}
}

func TestGetAPIKey_MalformedHeader_WrongPrefix(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer sometoken")
	_, err := GetAPIKey(headers)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected malformed authorization header error, got %v", err)
	}
}

func TestGetAPIKey_Valid(t *testing.T) {
	expectedKey := "my-secret-key"
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey "+expectedKey)
	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if apiKey != expectedKey {
		t.Errorf("expected API key %q, got %q", expectedKey, apiKey)
	}
}
