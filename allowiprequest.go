package allowiprequest

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct {
	KnockURL          string   `json:"knockUrl,omitempty"`
	WhitelistDuration string   `json:"whitelistDuration,omitempty"`
	AllowedSubnets    []string `json:"allowedSubnets,omitempty"`
	AllowlistFile     string   `json:"allowlistFile,omitempty"`
	PersistFile       string   `json:"persistFile,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		KnockURL:          "/knock-knock",
		WhitelistDuration: "24h",
		AllowedSubnets:    []string{"192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8"},
	}
}

type AllowIpR struct {
	next              http.Handler
	name              string
	knockURL          string
	whitelistDuration time.Duration
	allowedIPNets     []*net.IPNet
	allowedSubnets    []string
	allowlistFile     string
	persistFile       string
	whitelist         map[string]time.Time
	mu                sync.RWMutex
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.KnockURL == "" {
		return nil, fmt.Errorf("knockUrl cannot be empty")
	}

	duration, err := time.ParseDuration(config.WhitelistDuration)
	if err != nil {
		return nil, fmt.Errorf("invalid whitelistDuration: %w", err)
	}

	var allowedIPNets []*net.IPNet
	for _, cidr := range config.AllowedSubnets {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid subnet %s: %w", cidr, err)
		}
		allowedIPNets = append(allowedIPNets, ipNet)
	}

	d := &AllowIpR{
		next:              next,
		name:              name,
		knockURL:          config.KnockURL,
		whitelistDuration: duration,
		allowedIPNets:     allowedIPNets,
		allowedSubnets:    config.AllowedSubnets,
		allowlistFile:     config.AllowlistFile,
		persistFile:       config.PersistFile,
		whitelist:         make(map[string]time.Time),
	}

	if d.persistFile != "" {
		d.loadWhitelist()
	}

	if d.allowlistFile != "" {
		log.Printf("[allowiprequest] allowlist file: %s", d.allowlistFile)
		d.writeAllowlist()
	}

	return d, nil
}

func (a *AllowIpR) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Extract IP (without port)
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		// Fallback if no port
		host = req.RemoteAddr
	}
	// Strip brackets for IPv6 if present
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")

	userIP := net.ParseIP(host)
	if userIP == nil {
		http.Error(rw, "Invalid Request IP", http.StatusForbidden)
		return
	}

	// 1. Check Allowed Subnets (Static Whitelist)
	for _, ipNet := range a.allowedIPNets {
		if ipNet.Contains(userIP) {
			// Check if it's the admin view page
			if req.URL.Path == "/view-allow-ips" {
				a.serveAdminPage(rw)
				return
			}
			a.next.ServeHTTP(rw, req)
			return
		}
	}

	// 2. Check Knock URL
	if req.URL.Path == a.knockURL {
		a.mu.Lock()
		a.whitelist[host] = time.Now().Add(a.whitelistDuration)
		a.mu.Unlock()
		if a.allowlistFile != "" {
			a.writeAllowlist()
		}
		if a.persistFile != "" {
			a.persistWhitelist()
		}
		a.serveSuccessPage(rw, host)
		return
	}

	// 3. Check Admin View (Forbidden if not in allowed subnets)
	if req.URL.Path == "/view-allow-ips" {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	a.next.ServeHTTP(rw, req)
}

func (a *AllowIpR) serveSuccessPage(rw http.ResponseWriter, ip string) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusOK)
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Granted</title>
    <style>
        body { margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .container { text-align: center; padding: 2rem; border: 1px solid #333; border-radius: 8px; background-color: #1e1e1e; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        h1 { font-size: 1.5rem; color: #4caf50; margin-bottom: 1rem; }
        p { font-size: 1rem; color: #a0a0a0; }
        .ip { color: #fff; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Access Granted</h1>
        <p>You have successfully accessed the network via IP: <span class="ip">%s</span></p>
    </div>
</body>
</html>`, ip)
	rw.Write([]byte(html))
}

func (a *AllowIpR) serveAdminPage(rw http.ResponseWriter) {
	a.mu.RLock()
	// Copy whitelist to avoid holding lock while rendering
	ips := make(map[string]time.Time, len(a.whitelist))
	for k, v := range a.whitelist {
		ips[k] = v
	}
	a.mu.RUnlock()

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusOK)

	// Build admin page
	var rows strings.Builder
	now := time.Now()
	for ip, expiry := range ips {
		status := "Active"
		if now.After(expiry) {
			status = "Expired"
		}
		rows.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>", ip, expiry.Format("02 Jan 2006 15:04:05"), status))
	}

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Allowed IPs</title>
    <style>
        body { margin: 0; padding: 2rem; background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        h1 { color: #bb86fc; margin-bottom: 1.5rem; text-align: center; }
        table { width: 100%%; max-width: 800px; margin: 0 auto; border-collapse: collapse; background-color: #1e1e1e; border-radius: 8px; overflow: hidden; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; }
        th { background-color: #2c2c2c; color: #fff; text-transform: uppercase; font-size: 0.85rem; letter-spacing: 0.05em; }
        tr:hover { background-color: #252525; }
        tr:last-child td { border-bottom: none; }
        .empty { text-align: center; padding: 2rem; color: #666; }
    </style>
</head>
<body>
    <h1>Current Whitelisted IPs</h1>
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Expiration Time</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            %s
        </tbody>
    </table>
</body>
</html>`, rows.String())

	rw.Write([]byte(html))
}

func (a *AllowIpR) writeAllowlist() {
	// Build the sourceRange entries shared by both tcp and http blocks
	var ranges strings.Builder
	for _, subnet := range a.allowedSubnets {
		ranges.WriteString(fmt.Sprintf("          - \"%s\"\n", subnet))
	}

	now := time.Now()
	a.mu.RLock()
	for ip, expiry := range a.whitelist {
		if now.Before(expiry) {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			if parsed.To4() != nil {
				ranges.WriteString(fmt.Sprintf("          - \"%s/32\"\n", ip))
			} else {
				ranges.WriteString(fmt.Sprintf("          - \"%s/128\"\n", ip))
			}
		}
	}
	a.mu.RUnlock()

	rangeStr := ranges.String()

	var sb strings.Builder
	sb.WriteString("http:\n")
	sb.WriteString("  middlewares:\n")
	sb.WriteString("    local-whitelist-http:\n")
	sb.WriteString("      IPAllowList:\n")
	sb.WriteString("        sourceRange:\n")
	sb.WriteString(rangeStr)
	sb.WriteString("\n")
	sb.WriteString("tcp:\n")
	sb.WriteString("  middlewares:\n")
	sb.WriteString("    local-whitelist-tcp:\n")
	sb.WriteString("      IPAllowList:\n")
	sb.WriteString("        sourceRange:\n")
	sb.WriteString(rangeStr)

	dir := filepath.Dir(a.allowlistFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("[allowiprequest] failed to create directory %s: %v", dir, err)
		return
	}

	tmp, err := os.CreateTemp(dir, ".allowlist-*.yml.tmp")
	if err != nil {
		log.Printf("[allowiprequest] failed to create temp file in %s: %v", dir, err)
		return
	}
	tmpName := tmp.Name()

	if _, err := tmp.WriteString(sb.String()); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		log.Printf("[allowiprequest] failed to write temp file: %v", err)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		log.Printf("[allowiprequest] failed to close temp file: %v", err)
		return
	}

	if err := os.Rename(tmpName, a.allowlistFile); err != nil {
		os.Remove(tmpName)
		log.Printf("[allowiprequest] failed to rename %s -> %s: %v", tmpName, a.allowlistFile, err)
		return
	}

	log.Printf("[allowiprequest] allowlist written to %s", a.allowlistFile)
}

type persistEntry struct {
	IP     string    `json:"ip"`
	Expiry time.Time `json:"expiry"`
}

func (a *AllowIpR) persistWhitelist() {
	now := time.Now()
	var entries []persistEntry

	a.mu.RLock()
	for ip, expiry := range a.whitelist {
		if now.Before(expiry) {
			entries = append(entries, persistEntry{IP: ip, Expiry: expiry})
		}
	}
	a.mu.RUnlock()

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		log.Printf("[allowiprequest] failed to marshal whitelist: %v", err)
		return
	}

	dir := filepath.Dir(a.persistFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("[allowiprequest] failed to create directory %s: %v", dir, err)
		return
	}

	tmp, err := os.CreateTemp(dir, ".persist-*.json.tmp")
	if err != nil {
		log.Printf("[allowiprequest] failed to create temp file in %s: %v", dir, err)
		return
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		log.Printf("[allowiprequest] failed to write persist temp file: %v", err)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		log.Printf("[allowiprequest] failed to close persist temp file: %v", err)
		return
	}

	if err := os.Rename(tmpName, a.persistFile); err != nil {
		os.Remove(tmpName)
		log.Printf("[allowiprequest] failed to rename %s -> %s: %v", tmpName, a.persistFile, err)
		return
	}

	log.Printf("[allowiprequest] whitelist persisted to %s", a.persistFile)
}

func (a *AllowIpR) loadWhitelist() {
	data, err := os.ReadFile(a.persistFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[allowiprequest] no persist file found at %s, starting fresh", a.persistFile)
			return
		}
		log.Printf("[allowiprequest] failed to read persist file %s: %v", a.persistFile, err)
		return
	}

	var entries []persistEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		log.Printf("[allowiprequest] failed to parse persist file %s: %v", a.persistFile, err)
		return
	}

	now := time.Now()
	restored := 0
	for _, e := range entries {
		if now.Before(e.Expiry) {
			a.whitelist[e.IP] = e.Expiry
			restored++
		}
	}

	log.Printf("[allowiprequest] restored %d IPs from %s", restored, a.persistFile)
}
