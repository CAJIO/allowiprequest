# Allow IP Request Plugin

[![Go Report Card](https://goreportcard.com/badge/github.com/CAJIO/allowiprequest)](https://goreportcard.com/report/github.com/CAJIO/allowiprequest)
[![CodeQL](https://github.com/CAJIO/allowiprequest/actions/workflows/codeql.yml/badge.svg)](https://github.com/CAJIO/allowiprequest/actions/workflows/codeql.yml)

A **Traefik middleware plugin** that implements dynamic IP whitelisting. Users self-whitelist their IP by visiting a secret "knock" URL. The plugin generates a Traefik-compatible allowlist file (`IPAllowList`) that is picked up by Traefik's file provider, so actual traffic filtering is handled natively by Traefik for both HTTP and TCP routers.

## Features

- **Dynamic "Knock" Whitelisting**: Users grant themselves temporary access by visiting a configurable URL (default: `/knock-knock`).
- **Allowlist File Generation**: Automatically generates a YAML file with `http` and `tcp` `IPAllowList` middleware definitions. Traefik's file provider watches the file and applies filtering natively.
- **Static Trusted Subnets**: Define CIDR ranges (e.g., local networks, VPNs) that are always included in the generated allowlist.
- **Admin Dashboard**: Trusted subnets can access a dashboard at `/view-allow-ips` to monitor active whitelisted IPs and their expiration times.
- **Configurable Duration**: Control how long a dynamic whitelist entry remains valid.
- **Persist Whitelist**: Save the whitelist to a JSON file to survive Traefik restarts.

## Configuration

### Configuration Options

| Option | Type | Default | Description |
|:--- |:--- |:--- |:--- |
| `knockUrl` | `string` | `"/knock-knock"` | The URL path users must visit to whitelist their IP. |
| `whitelistDuration` | `string` | `"24h"` | How long the IP remains whitelisted (e.g., `"1h"`, `"30m"`). |
| `allowedSubnets` | `[]string` | `["192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8"]` | CIDR ranges always included in the allowlist and permitted to view the admin page. |
| `allowlistFile` | `string` | `""` | Path to the generated YAML file. When set, the plugin writes and maintains the allowlist automatically. |
| `persistFile` | `string` | `""` | Path to the JSON file used to persist the whitelist across restarts. |

### Add the plugin to Traefik

```yaml
experimental:
  plugins:
    allowiprequest:
      moduleName: github.com/CAJIO/allowiprequest
      version: v1.2.0
```

### Middleware Configuration

```yaml
http:
  middlewares:
    my-ip-allowlist:
      plugin:
        allowiprequest:
          KnockURL: "/knock-knock"
          WhitelistDuration: "24h"
          AllowlistFile: "/etc/traefik/conf.d/allowlist.yml"
          PersistFile: "/etc/traefik/ips.json"
          AllowedSubnets:
            - "192.168.0.0/16"
            - "127.0.0.0/8"
```

### Router Configuration

```yaml
http:
  routers:
    mydomain:
      rule: "Host(`example.com`)"
      middlewares:
        - my-ip-allowlist
```

## Generated Allowlist File

When `allowlistFile` is set, the plugin writes a YAML file containing both `http` and `tcp` middleware definitions. The file is updated atomically on every change (knock / restart).

```yaml
http:
  middlewares:
    local-whitelist-http:
      IPAllowList:
        sourceRange:
          - "192.168.0.0/16"
          - "127.0.0.0/8"
          - "1.2.3.4/32"       # dynamically added via knock

tcp:
  middlewares:
    local-whitelist-tcp:
      IPAllowList:
        sourceRange:
          - "192.168.0.0/16"
          - "127.0.0.0/8"
          - "1.2.3.4/32"       # dynamically added via knock
```

Configure Traefik's file provider to watch the output directory:

```yaml
# traefik.yml (static config)
providers:
  file:
    directory: /etc/traefik/conf.d
    watch: true
```

Then reference the generated middleware in your routers:

```yaml
# HTTP router example
http:
  routers:
    my-http-service:
      rule: "Host(`example.com`)"
      middlewares:
        - local-whitelist-http
      service: my-http-backend

# TCP router example
tcp:
  routers:
    my-tcp-service:
      rule: "HostSNI(`*`)"
      middlewares:
        - local-whitelist-tcp
      service: my-tcp-backend
```

## How It Works

1. **Knock**: The user visits the configured `knockUrl` (e.g., `https://example.com/knock-knock`).
2. **Confirmation**: The plugin displays an "Access Granted" page and records the user's IP with an expiration time.
3. **File Update**: The allowlist YAML file is regenerated, adding the new IP as a `/32` (IPv4) or `/128` (IPv6) entry.
4. **Traefik Picks Up Changes**: Traefik's file provider detects the updated file and applies the new `IPAllowList` rules to both HTTP and TCP routers.
5. **Access**: The user can now reach the service until `whitelistDuration` expires.
6. **Monitoring**: Administrators connecting from an IP in `allowedSubnets` can visit `/view-allow-ips` to see the table of currently allowed IPs.
