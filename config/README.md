# Hanabi Configuration

This directory contains YAML configuration for the Hanabi BFF server.

## Files

- `example.yaml` - Example configuration with all options documented

## Getting Started

Copy the example and customize for your environment:

```bash
cp config/example.yaml config/my-env.yaml
# Edit config/my-env.yaml with your values
```

## Kubernetes / FluxCD Integration

### ConfigMap Creation

Create a ConfigMap from your YAML file:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: hanabi-config
  namespace: your-product-staging
data:
  config.yaml: |
    # Content from your customized config YAML
```

### Deployment Configuration

Mount the ConfigMap in the Deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hanabi
spec:
  template:
    spec:
      containers:
      - name: hanabi
        image: ghcr.io/pleme-io/hanabi:latest
        volumeMounts:
        - name: config
          mountPath: /etc/hanabi
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: hanabi-config
```

## Configuration Structure

### Security Settings

**CSP (Content Security Policy)**
- `api_domains` - GraphQL API endpoints allowed in `connect-src`
- `ws_domains` - WebSocket endpoints allowed in `connect-src`
- `additional_connect_src` - External APIs (e.g., ViaCEP for Brazilian postal codes)
- `font_sources` - Font CDNs (e.g., Google Fonts)
- `style_sources` - Stylesheet sources (e.g., Google Fonts CSS)

**CORS (Cross-Origin Resource Sharing)**
- `allowed_origins` - Domains allowed to make requests
- `allow_credentials` - Whether to allow credentials (cookies, auth headers)

**HSTS (HTTP Strict Transport Security)**
- `max_age` - How long browsers should enforce HTTPS (seconds)
- `include_subdomains` - Apply to all subdomains
- `preload` - Enable HSTS preload (submit to browser preload lists)

**Security Headers**
- `x_frame_options` - Clickjacking protection (`DENY` or `SAMEORIGIN`)
- `referrer_policy` - Controls Referer header behavior
- `permissions_policy` - Browser feature permissions

### API Settings

- `graphql_url` - GraphQL HTTP endpoint
- `ws_url` - GraphQL WebSocket endpoint (subscriptions)

### Server Settings

- `static_dir` - Directory containing React build artifacts
- `http_port` - HTTP server port (default: 80)
- `health_port` - Health check endpoint port (default: 8080)

## Security Best Practices

1. **Least Privilege CSP**: Only allow necessary domains in CSP directives
2. **Strict CORS**: Limit `allowed_origins` to known frontend domains
3. **Long HSTS**: Use maximum `max_age` (31536000 = 1 year) for production
4. **Frame Denial**: Always use `x_frame_options: "DENY"` unless iframes needed
5. **Minimal Permissions**: Deny all browser features not explicitly needed

## Troubleshooting

### CSP Violations

If you see CSP errors in browser console:

1. Check browser DevTools Console for exact violation
2. Identify the blocked resource domain
3. Add to appropriate CSP array in config YAML
4. Update ConfigMap
5. Restart pods to apply changes

### Common Issues

**"Refused to connect to API"**
- Verify `api_domains` includes correct API URL
- Check `connect-src` CSP directive in browser DevTools

**"Refused to load fonts"**
- Ensure `font_sources` includes `https://fonts.gstatic.com`
- Ensure `style_sources` includes `https://fonts.googleapis.com`

**CORS errors**
- Verify frontend domain in `allowed_origins`
- Confirm `allow_credentials: true` if using auth cookies

## Deployment Workflow

1. **Update Config**: Edit your environment YAML
2. **Commit Changes**: Push to Git (FluxCD watches this repo)
3. **FluxCD Sync**: FluxCD automatically updates ConfigMap
4. **Restart Pods**: Either automatic or manual pod restart
5. **Verify**: Check logs for "Configuration loaded successfully"

## Security Hardening Checklist

- [ ] CSP allows only necessary domains (no wildcards)
- [ ] HSTS enabled with 1-year max-age
- [ ] X-Frame-Options set to DENY
- [ ] Permissions-Policy denies unused browser features
- [ ] CORS limited to known frontend origins
- [ ] All external APIs documented and justified
- [ ] Configuration reviewed by security team

## References

- [MDN: Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [MDN: HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
- [OWASP: Secure Headers](https://owasp.org/www-project-secure-headers/)
