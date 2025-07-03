package medods_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Mocking DB //

type MockDB struct {
    refreshHash []byte
    expiration time.Time
}

func (m *MockDB) SetRefreshToken(guid string, refreshHash []byte, expiration time.Time) error {
    m.refreshHash = refreshHash
    m.expiration = expiration
    return nil
}

func (m MockDB) GetRefreshToken(guid string) (refreshHash []byte, expiration time.Time, err error) {
    return m.refreshHash, m.expiration, nil
}

// The tests //

func TestUseCase(t *testing.T) {
    guid := "123123"

    api := NewAPI(&MockDB{})
    
    // POST /login

    recorder := httptest.NewRecorder()
    request, _ := http.NewRequest("POST", fmt.Sprintf("/login?guid=%s", guid), nil)
    api.ServeHTTP(recorder, request)

    if recorder.Code != 200 {
        t.Errorf("/login %d", recorder.Code)
    }

    var response map[string]string
    if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
        t.Fatalf("JSON decoding failed")
    }

    access := response["access"]
    refresh := response["refresh"]

    // GET /guid

    recorder = httptest.NewRecorder()
    request, _ = http.NewRequest("GET", "/guid", nil)
    request.Header.Add("Authorization", "Bearer " + access)
    api.ServeHTTP(recorder, request)

    if recorder.Code != 200 {
        t.Errorf("/guid %d", recorder.Code)
    }

    // POST /refresh

    recorder = httptest.NewRecorder()
    body := fmt.Sprintf(`{"access": %q, "refresh": %q}`, access, refresh)
    request, _ = http.NewRequest("POST", "/refresh", strings.NewReader(body))
    api.ServeHTTP(recorder, request)

    if recorder.Code != 200 {
        t.Errorf("/refresh %d", recorder.Code)
    }

    if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
        t.Fatalf("JSON decoding failed")
    }

    old_access := access
    old_refresh := refresh

    access = response["access"]
    refresh = response["refresh"]

    // POST /refresh with old token pair

    recorder = httptest.NewRecorder()
    body = fmt.Sprintf(`{"access": %q, "refresh": %q}`, old_access, old_refresh)
    request, _ = http.NewRequest("POST", "/refresh", strings.NewReader(body))
    api.ServeHTTP(recorder, request)

    if recorder.Code != http.StatusBadRequest {
        t.Errorf("/refresh %d", recorder.Code)
    }

    // POST /refresh with mismatched token pair

    recorder = httptest.NewRecorder()
    body = fmt.Sprintf(`{"access": %q, "refresh": %q}`, old_access, refresh)
    request, _ = http.NewRequest("POST", "/refresh", strings.NewReader(body))
    api.ServeHTTP(recorder, request)

    if recorder.Code != http.StatusBadRequest {
        t.Errorf("/refresh %d", recorder.Code)
    }

    // GET /guid with new token pair

    recorder = httptest.NewRecorder()
    request, _ = http.NewRequest("GET", "/guid", nil)
    request.Header.Add("Authorization", "Bearer " + access)
    api.ServeHTTP(recorder, request)

    if recorder.Code != 200 {
        t.Errorf("/guid %d", recorder.Code)
    }
}

func TestGuidRouteProtected(t *testing.T) {
    api := NewAPI(&MockDB{})

    recorder := httptest.NewRecorder()
    request, _ := http.NewRequest("GET", "/guid", nil)
    // no Authorization header
    api.ServeHTTP(recorder, request)

    if recorder.Code != http.StatusUnauthorized {
        t.Errorf("/guid wrong status %d", recorder.Code)
    }
}
