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

### Example Middleware Configuration

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

## How It Works

1.  **Initial Access**: When an unknown user tries to access your service, they receive a `403 Forbidden` error.
2.  **Whitelisting**: The user visits the configured `knockUrl` (e.g., `https://your-service.com/secret-knock`).
3.  **Confirmation**: The plugin displays an "Access Granted" page and records the user's IP.
4.  **Access**: The user can now access the service normally until the `whitelistDuration` expires.
5.  **Monitoring**: Administrators connecting from an IP in `allowedSubnets` can visit `/view-allow-ips` to see the table of currently allowed IPs.
