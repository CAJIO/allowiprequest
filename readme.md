# Allow IP Request Plugin

[![Go Report Card](https://goreportcard.com/badge/github.com/CAJIO/allowiprequest)](https://goreportcard.com/report/github.com/CAJIO/allowiprequest)
[![CodeQL](https://github.com/CAJIO/allowiprequest/actions/workflows/codeql.yml/badge.svg)](https://github.com/CAJIO/allowiprequest/actions/workflows/codeql.yml)


This is a **Traefik middleware plugin** that implements a dynamic IP whitelisting mechanism. It protects your services by blocking all requests by default while allowing users to self-whitelist their IP address by visiting a specific "knock" URL.

## Features

- **Block by Default**: Denies access to all unauthorized requests with a `403 Forbidden` status.
- **Dynamic "Knock" Whitelisting**: Users can grant themselves temporary access by visiting a specific URL (default: `/knock-knock`).
- **Static Trusted Subnets**: Define a list of CIDR ranges (e.g., local networks, VPNs) that always have access.
- **Admin Dashboard**: Trusted subnets can access a dashboard (at `/view-allow-ips`) to monitor active whitelisted IPs and their expiration times.
- **Configurable Duration**: Control how long a dynamic whitelist entry remains valid.

## Configuration

To use this plugin, you must configure it in your Traefik dynamic configuration.

### Configuration Options

| Option | Type | Default | Description |
|:--- |:--- |:--- |:--- |
| `knockUrl` | `string` | `"/knock-knock"` | The specific URL path users must visit to whitelist their IP. |
| `whitelistDuration` | `string` | `"24h"` | How long the IP remains whitelisted (e.g., "1h", "30m"). |
| `allowedSubnets` | `[]string` | `["192.168.0.0/16", ...]` | List of CIDR ranges that bypass the knock check and can view the admin page. |
| `syncAllowlist` | `bool` | `false` | Enable writing the current allowlist to a YAML file for use as a Traefik TCP middleware. |
| `allowlistFile` | `string` | `""` | Path to the YAML file (required when `syncAllowlist` is `true`). |

### Add the plugin to Traefik
```yaml
experimental:
  plugins:
    allowiprequest:
      moduleName: github.com/CAJIO/allowiprequest
      version: v1.0.0
```

### Middleware Configuration
```yaml
http:
  middlewares:
    my-ip-allowlist:
      plugin:
        allowiprequest:
          knockUrl: "/knock-knock"
          whitelistDuration: "24h"
          allowedSubnets:
            - "127.0.0.1/32"
            - "192.168.1.0/24"
```

### TCP Allowlist Sync

The plugin can write a YAML file that Traefik's [file provider](https://doc.traefik.io/traefik/providers/file/) picks up as a TCP `IPAllowList` middleware. This lets you reuse the same dynamic allowlist for TCP routers (e.g. databases, mail servers) that don't support HTTP middleware plugins.

Enable it by setting `syncAllowlist: true` and providing the output path:

```yaml
http:
  middlewares:
    my-ip-allowlist:
      plugin:
        allowiprequest:
          knockUrl: "/knock-knock"
          whitelistDuration: "24h"
          allowedSubnets:
            - "127.0.0.1/32"
            - "192.168.1.0/24"
          syncAllowlist: true
          allowlistFile: "/etc/traefik/conf.d/allowlist.yml"
```

The generated file has the following structure and is updated atomically on every change (knock / expiry):

```yaml
tcp:
  middlewares:
    local-whitelist:
      IPAllowList:
        sourceRange:
          - "127.0.0.1/32"
          - "192.168.1.0/24"
          - "1.2.3.4/32"   # dynamically added via knock
```

To use it, configure Traefik's file provider to watch the output directory and reference the middleware in a TCP router:

```yaml
# traefik.yml (static config)
providers:
  file:
    directory: /etc/traefik/conf.d
    watch: true
```

```yaml
# TCP router example
tcp:
  routers:
    my-tcp-service:
      rule: "HostSNI(`*`)"
      middlewares:
        - local-whitelist
      service: my-tcp-backend
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

## How It Works

1.  **Initial Access**: When an unknown user tries to access your service, they receive a `403 Forbidden` error.
2.  **Whitelisting**: The user visits the configured `knockUrl` (e.g., `https://your-service.com/secret-knock`).
3.  **Confirmation**: The plugin displays an "Access Granted" page and records the user's IP.
4.  **Access**: The user can now access the service normally until the `whitelistDuration` expires.
5.  **Monitoring**: Administrators connecting from an IP in `allowedSubnets` can visit `/view-allow-ips` to see the table of currently allowed IPs.
