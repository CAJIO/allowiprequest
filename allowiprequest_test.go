package allowiprequest_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CAJIO/allowiprequest"
)

func TestDemo(t *testing.T) {
	cfg := allowiprequest.CreateConfig()
	cfg.KnockURL = "/knock-knock"
	cfg.WhitelistDuration = "1s" // Short duration for testing
	cfg.AllowedSubnets = []string{"192.168.0.0/24"}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := allowiprequest.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Block Request from Unknown IP
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = "10.0.0.1:1234" // Blocked IP
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for unknown IP, got %d", recorder.Code)
	}

	// 2. Allow Request from Allowed Subnet
	req = httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = "192.168.0.5:1234" // Allowed Subnet
	recorder = httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Errorf("expected 200 OK for allowed subnet, got %d", recorder.Code)
	}
	if body := recorder.Body.String(); body != "OK" {
		t.Errorf("expected OK body, got %s", body)
	}

	// 3. Knock to Whitelist IP
	knockIP := "10.0.0.2:4321"
	req = httptest.NewRequest(http.MethodGet, "http://localhost/knock-knock", nil)
	req.RemoteAddr = knockIP
	recorder = httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Errorf("expected 200 OK for knock, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "Access Granted") {
		t.Errorf("expected success page, got %s", recorder.Body.String())
	}

	// 4. Access after Knock
	req = httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = knockIP
	recorder = httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Errorf("expected 200 OK after knock, got %d", recorder.Code)
	}

	// 5. Expiration
	time.Sleep(1100 * time.Millisecond) // Wait more than 1s
	req = httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = knockIP
	recorder = httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("expected 403 after expiration, got %d", recorder.Code)
	}

	// 6. Admin View Access (Allowed Subnet)
	req = httptest.NewRequest(http.MethodGet, "http://localhost/view-allow-ips", nil)
	req.RemoteAddr = "192.168.0.10:5678" // Allowed
	recorder = httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Errorf("expected 200 OK for admin view from allowed subnet, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "Current Whitelisted IPs") {
		t.Errorf("expected admin page content, got %s", recorder.Body.String())
	}

	// 7. Admin View Access Blocked (External IP)
	req = httptest.NewRequest(http.MethodGet, "http://localhost/view-allow-ips", nil)
	req.RemoteAddr = "10.10.10.10:1234" // Not allowed
	recorder = httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for admin view from external IP, got %d", recorder.Code)
	}
}
