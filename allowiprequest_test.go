package allowiprequest_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CAJIO/allowiprequest"
)

func TestAllowIpR(t *testing.T) {
	cfg := allowiprequest.CreateConfig()
	cfg.KnockURL = "/knock-knock"
	cfg.WhitelistDuration = "1s" // Short duration for testing
	cfg.AllowedSubnets = []string{"192.168.0.0/24"}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := allowiprequest.New(ctx, next, cfg, "allowiprequest-plugin")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Pass through for any IP (filtering is delegated to Traefik via allowlist file)
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Errorf("expected 200 OK for pass-through, got %d", recorder.Code)
	}
	if body := recorder.Body.String(); body != "OK" {
		t.Errorf("expected OK body, got %s", body)
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

	// 5. Pass through after expiration (filtering is handled by Traefik)
	time.Sleep(1100 * time.Millisecond)
	req = httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = knockIP
	recorder = httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Errorf("expected 200 OK after expiration (pass-through), got %d", recorder.Code)
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

func TestAllowlistFileWrite(t *testing.T) {
	tmpDir := t.TempDir()
	allowlistPath := filepath.Join(tmpDir, "conf.d", "allowlist.yml")

	cfg := allowiprequest.CreateConfig()
	cfg.KnockURL = "/knock-knock"
	cfg.WhitelistDuration = "1s"
	cfg.AllowedSubnets = []string{"192.168.0.0/16"}
	cfg.AllowlistFile = allowlistPath

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := allowiprequest.New(ctx, next, cfg, "allowiprequest-plugin")
	if err != nil {
		t.Fatal(err)
	}

	// File should be created on init with static subnets
	data, err := os.ReadFile(allowlistPath)
	if err != nil {
		t.Fatalf("allowlist file not created on init: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "192.168.0.0/16") {
		t.Errorf("allowlist file missing static subnet, got:\n%s", content)
	}
	if !strings.Contains(content, "IPAllowList") {
		t.Errorf("allowlist file missing IPAllowList key, got:\n%s", content)
	}
	if !strings.Contains(content, "http:") {
		t.Errorf("allowlist file missing http block, got:\n%s", content)
	}
	if !strings.Contains(content, "tcp:") {
		t.Errorf("allowlist file missing tcp block, got:\n%s", content)
	}

	// Knock to add dynamic IP
	req := httptest.NewRequest(http.MethodGet, "http://localhost/knock-knock", nil)
	req.RemoteAddr = "10.0.0.2:4321"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	data, err = os.ReadFile(allowlistPath)
	if err != nil {
		t.Fatalf("failed to read allowlist after knock: %v", err)
	}
	content = string(data)
	if !strings.Contains(content, "10.0.0.2/32") {
		t.Errorf("allowlist file missing knocked IP, got:\n%s", content)
	}
	if !strings.Contains(content, "192.168.0.0/16") {
		t.Errorf("allowlist file lost static subnet after knock, got:\n%s", content)
	}

	// Wait for expiry, then trigger cleanup
	time.Sleep(1100 * time.Millisecond)
	req = httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = "10.0.0.2:4321"
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	data, err = os.ReadFile(allowlistPath)
	if err != nil {
		t.Fatalf("failed to read allowlist after expiry: %v", err)
	}
	content = string(data)
	if strings.Contains(content, "10.0.0.2/32") {
		t.Errorf("allowlist file still contains expired IP, got:\n%s", content)
	}
}

func TestPersistFile(t *testing.T) {
	tmpDir := t.TempDir()
	persistPath := filepath.Join(tmpDir, "whitelist.persist")

	cfg := allowiprequest.CreateConfig()
	cfg.KnockURL = "/knock-knock"
	cfg.WhitelistDuration = "10s"
	cfg.AllowedSubnets = []string{"192.168.0.0/24"}
	cfg.PersistFile = persistPath

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := allowiprequest.New(ctx, next, cfg, "allowiprequest-plugin")
	if err != nil {
		t.Fatal(err)
	}

	// Knock to whitelist an IP
	req := httptest.NewRequest(http.MethodGet, "http://localhost/knock-knock", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for knock, got %d", recorder.Code)
	}

	// Verify persist file was created and contains the IP
	data, err := os.ReadFile(persistPath)
	if err != nil {
		t.Fatalf("persist file not created after knock: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, `"ip": "10.0.0.1"`) {
		t.Errorf("persist file missing knocked IP, got:\n%s", content)
	}

	// Create a new plugin instance with allowlistFile to verify restored IPs appear in the file
	allowlistPath := filepath.Join(tmpDir, "conf.d", "allowlist.yml")
	cfg2 := allowiprequest.CreateConfig()
	cfg2.KnockURL = "/knock-knock"
	cfg2.WhitelistDuration = "10s"
	cfg2.AllowedSubnets = []string{"192.168.0.0/24"}
	cfg2.PersistFile = persistPath

	cfg2.AllowlistFile = allowlistPath

	_, err = allowiprequest.New(ctx, next, cfg2, "allowiprequest-plugin-2")
	if err != nil {
		t.Fatal(err)
	}

	// The allowlist file should contain the restored IP
	data, err = os.ReadFile(allowlistPath)
	if err != nil {
		t.Fatalf("allowlist file not created after restore: %v", err)
	}
	if !strings.Contains(string(data), "10.0.0.1/32") {
		t.Errorf("allowlist file missing restored IP, got:\n%s", string(data))
	}

	// Test that expired entries are not restored
	cfgExpired := allowiprequest.CreateConfig()
	cfgExpired.KnockURL = "/knock-knock"
	cfgExpired.WhitelistDuration = "1s"
	cfgExpired.AllowedSubnets = []string{"192.168.0.0/24"}
	cfgExpired.PersistFile = persistPath

	cfgExpired.AllowlistFile = allowlistPath

	handlerExp, err := allowiprequest.New(ctx, next, cfgExpired, "allowiprequest-plugin-exp")
	if err != nil {
		t.Fatal(err)
	}

	// Knock with short duration
	req = httptest.NewRequest(http.MethodGet, "http://localhost/knock-knock", nil)
	req.RemoteAddr = "10.0.0.50:5678"
	recorder = httptest.NewRecorder()
	handlerExp.ServeHTTP(recorder, req)

	// Wait for expiry
	time.Sleep(1100 * time.Millisecond)

	// Create a new instance — the expired IP should not appear in the allowlist
	_, err = allowiprequest.New(ctx, next, cfgExpired, "allowiprequest-plugin-3")
	if err != nil {
		t.Fatal(err)
	}

	data, err = os.ReadFile(allowlistPath)
	if err != nil {
		t.Fatalf("failed to read allowlist after expired restore: %v", err)
	}
	if strings.Contains(string(data), "10.0.0.50/32") {
		t.Errorf("allowlist file should not contain expired IP, got:\n%s", string(data))
	}
}
