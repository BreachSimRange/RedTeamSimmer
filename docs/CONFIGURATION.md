[← Back to README](../README.md)

# Configuration

### Server Configuration

**Environment Variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `RTS_SECRET_KEY` | Flask session secret key | Random |
| `RTS_PORT` | Server port | `5000` |
| `RTS_DEBUG` | Enable debug mode | `false` |
| `RTS_ATOMIC_ROOT` | Path to atomics folder | `./atomics` |

### Agent Configuration

Edit these constants in `agent.go` before building:

```go
const (
    ServerURL              = "http://192.168.1.100:5000"  // Server address
    AdminToken             = "ChangeThisAdminToken!"       // Authentication token
    AtomicsDir             = "./atomics"                   // Local atomics path
    PollInterval           = 7 * time.Second              // Task poll interval
    FiledropPoll           = 5 * time.Second              // File poll interval
    InvokeAtomicModuleDir  = "./Invoke-AtomicRedTeam"     // Module directory
)
```
### Production Deployment with SSL

#### Option 1: Self-Signed Certificate (Internal Use)

```bash
# Create SSL directory
mkdir -p ssl

# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/server.key \
  -out ssl/server.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=redteamsimmer.local"

# Run with SSL
python app.py --ssl --cert ssl/server.crt --key ssl/server.key --port 443
```

**Update agent.go for HTTPS:**

```go
ServerURL = "https://redteamsimmer.local"
```

> **Note:** For self-signed certificates, you may need to add certificate verification bypass in the agent or install the CA certificate on target systems.

#### Option 2: Let's Encrypt (Public Facing)

```bash
# Install certbot
sudo apt install certbot

# Obtain certificate (ensure port 80 is accessible)
sudo certbot certonly --standalone -d yourdomain.com

# Run with Let's Encrypt certificate
python app.py --ssl \
  --cert /etc/letsencrypt/live/yourdomain.com/fullchain.pem \
  --key /etc/letsencrypt/live/yourdomain.com/privkey.pem \
  --port 443
```

**Auto-renewal:**

```bash
# Add to crontab
0 0 1 * * certbot renew --quiet && systemctl restart redteamsimmer
```

#### Option 3: Reverse Proxy with Nginx (Recommended)

**Install Nginx:**

```bash
sudo apt install nginx
```

**Configure Nginx (`/etc/nginx/sites-available/redteamsimmer`):**

```nginx
server {
    listen 443 ssl http2;
    server_name redteamsimmer.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeout settings for long-running tests
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }
}

server {
    listen 80;
    server_name redteamsimmer.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

**Enable the site:**

```bash
sudo ln -s /etc/nginx/sites-available/redteamsimmer /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```
