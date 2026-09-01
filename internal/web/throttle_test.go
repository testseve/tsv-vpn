package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginLocksOutAfterRepeatedFailures(t *testing.T) {
	server := testServer(t)

	post := func(password string) *httptest.ResponseRecorder {
		form := "password=" + password
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.7:5555"
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		return rec
	}

	for i := 0; i < maxLoginFailures; i++ {
		if code := post("wrong").Code; code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, code)
		}
	}
	// Locked now: even the correct password is refused.
	rec := post(testPassword)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("after lockout got %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After header on lockout")
	}
}

func TestLoginSuccessClearsFailures(t *testing.T) {
	server := testServer(t)
	ip := "203.0.113.9:5555"

	fail := func() {
		req := httptest.NewRequest("POST", "/login", strings.NewReader("password=wrong"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = ip
		server.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
	for i := 0; i < maxLoginFailures-1; i++ {
		fail()
	}
	// A success resets the counter, so the next wrong password does not lock out.
	ok := httptest.NewRequest("POST", "/login", strings.NewReader("password="+testPassword))
	ok.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ok.RemoteAddr = ip
	server.Handler().ServeHTTP(httptest.NewRecorder(), ok)

	req := httptest.NewRequest("POST", "/login", strings.NewReader("password=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 (counter should have reset)", rec.Code)
	}
}
