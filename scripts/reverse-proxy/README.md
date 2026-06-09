# Reverse Proxy

A lightweight reverse proxy that sits between Arize and a customer's LLM
gateway, handling upstream token acquisition and refresh automatically.

## Architecture

```
┌──────────────────────────────────────────────┐   ┌───────────────────────┐
│  Cloud                                       │   │  Customer network     │
│                                              │   │                       │
│  ┌───────────┐  Auth   ┌────────────────┐    │   │   ┌──────────────┐    │
│  │ Arize host│───────► │ Reverse Proxy  │───────────►│  AI gateway  │    │
│  └───────────┘         │ (this service) │    │   │   └──────────────┘    │
│                        └───────┬────────┘    │   │                       │
│                                │             │   └───────────────────────┘
│                                ▼             │
│                        ┌───────────────┐     │
│                        │  Identity     │     │
│                        │  provider     │     │
│                        │  (OAuth2)     │     │
│                        └───────────────┘     │
│                                              │
│                        k8s secrets /         │
│                        certificates          │
└──────────────────────────────────────────────┘
```

1. Arize sends an LLM request (Prompt Playground, Evaluations) to the proxy.
2. The proxy validates the request (optional `PROXY_AUTH_TOKEN`).
3. The proxy obtains a fresh bearer token from the identity provider (cached
   until near expiry).
4. The proxy replaces the `Authorization` header and forwards the request
   transparently to the AI gateway -- body, query params, and all other
   headers pass through unchanged.
5. The response (including streaming/SSE) is forwarded back to Arize.

Arize never sees or stores the rotating upstream token.

## Files

```
reverse-proxy/
├── proxy.py              # The reverse proxy application
├── requirements.txt      # Python dependencies
├── Dockerfile            # Production container (gunicorn, non-root)
├── docker-compose.yml    # Docker Compose for quick deploy
├── .dockerignore         # Keep build context small
├── .env.example          # Example environment config
└── README.md             # This file
```

## Configuration Reference

### Core

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TARGET_BASE_URL` | **Yes** | -- | The upstream AI gateway URL |
| `AUTH_TYPE` | No | `none` | Token provider: `oauth2`, `azure`, `static`, `none` |
| `PROXY_AUTH_TOKEN` | No | -- | If set, validates incoming `Authorization: Bearer` from Arize |
| `PORT` | No | `8000` | Listen port |
| `REQUEST_TIMEOUT` | No | `120` | Upstream timeout in seconds |
| `LOG_LEVEL` | No | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `DUMP_REQUESTS` | No | -- | `1` logs every incoming request (method, path, headers, body) and flags 4xx/5xx upstream responses |
| `DUMP_REQUESTS_FILE` | No | -- | If set, also appends each request as a JSON line to this file |

> ⚠️ **`DUMP_REQUESTS` / `DUMP_REQUESTS_FILE` log full request bodies**, which may
> contain prompts, dataset values, or other sensitive data (the `Authorization`
> header is redacted, but bodies are not). Enable them only for short-lived
> debugging during onboarding — never leave them on in production. Captured files
> (`captured*.jsonl`) are gitignored; delete them when you're done.

### OAuth2 (`AUTH_TYPE=oauth2`)

Uses the client-credentials grant. Works with any standards-compliant identity
provider (Okta, Auth0, Keycloak, etc.). Tokens are cached and refreshed
automatically 60 seconds before expiry.

| Variable | Required | Description |
|----------|----------|-------------|
| `OAUTH2_TOKEN_URL` | **Yes** | OAuth2 token endpoint |
| `OAUTH2_CLIENT_ID` | **Yes** | Client ID |
| `OAUTH2_CLIENT_SECRET` | **Yes** | Client secret |
| `OAUTH2_SCOPE` | No | Scope for the token request |

### Azure (`AUTH_TYPE=azure`)

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_TENANT_ID` | **Yes** | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | **Yes** | Service principal client ID |
| `AZURE_CLIENT_SECRET` | **Yes** | Service principal secret |
| `AZURE_SCOPE` | No | Default: `https://cognitiveservices.azure.com/.default` |

### Static (`AUTH_TYPE=static`)

| Variable | Required | Description |
|----------|----------|-------------|
| `STATIC_BEARER_TOKEN` | **Yes** | Fixed bearer token attached to every upstream request |

### TLS / mTLS

| Variable | Description |
|----------|-------------|
| `REQUESTS_CA_BUNDLE` | Path to CA cert bundle (for internal/private CAs) |
| `CLIENT_CERT_PATH` | Path to client certificate (for mTLS) |
| `CLIENT_KEY_PATH` | Path to client private key (for mTLS) |

Mount certificates into the container via `CERTS_DIR` in docker-compose
(default: `./certs` -> `/app/certs`).

---

## Deploy to Production (Kubernetes)

### 1. Build and push the image

```bash
docker build -t your-registry/reverse-proxy:v1 .
docker push your-registry/reverse-proxy:v1
```

### 2. Create secrets

```bash
kubectl create secret generic reverse-proxy-secrets \
  --from-literal=token-url="https://auth.internal.example.com/oauth2/token" \
  --from-literal=client-id="YOUR_CLIENT_ID" \
  --from-literal=client-secret="YOUR_CLIENT_SECRET" \
  --from-literal=proxy-auth-token="TOKEN_FOR_ARIZE"
```

### 3. Apply the manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: reverse-proxy
spec:
  replicas: 2
  selector:
    matchLabels:
      app: reverse-proxy
  template:
    metadata:
      labels:
        app: reverse-proxy
    spec:
      containers:
        - name: proxy
          image: your-registry/reverse-proxy:v1
          ports:
            - containerPort: 8000
          env:
            - name: TARGET_BASE_URL
              value: "https://ai-gateway.internal.example.com"
            - name: AUTH_TYPE
              value: "oauth2"
            - name: OAUTH2_TOKEN_URL
              valueFrom:
                secretKeyRef:
                  name: reverse-proxy-secrets
                  key: token-url
            - name: OAUTH2_CLIENT_ID
              valueFrom:
                secretKeyRef:
                  name: reverse-proxy-secrets
                  key: client-id
            - name: OAUTH2_CLIENT_SECRET
              valueFrom:
                secretKeyRef:
                  name: reverse-proxy-secrets
                  key: client-secret
            - name: PROXY_AUTH_TOKEN
              valueFrom:
                secretKeyRef:
                  name: reverse-proxy-secrets
                  key: proxy-auth-token
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8000
            periodSeconds: 15
          readinessProbe:
            httpGet:
              path: /ready
              port: 8000
            periodSeconds: 10
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
---
apiVersion: v1
kind: Service
metadata:
  name: reverse-proxy
spec:
  selector:
    app: reverse-proxy
  ports:
    - port: 8000
      targetPort: 8000
```

### 4. Configure Arize

In Arize, set the custom model endpoint to:
- **Base URL**: `http://reverse-proxy.your-namespace.svc:8000`
- **API Key / Bearer Token**: the value of `PROXY_AUTH_TOKEN` (if set)

---

## Test Locally

### Option A: Docker Compose with a mock upstream

This spins up the proxy and a tiny echo server that acts as a fake AI gateway.

**1. Start the mock upstream and proxy:**

```bash
# Terminal 1 -- mock upstream (echoes back whatever it receives)
python3 -c "
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/', defaults={'path': ''}, methods=['GET','POST','PUT','DELETE'])
@app.route('/<path:path>', methods=['GET','POST','PUT','DELETE'])
def echo(path):
    return jsonify({
        'echo': True,
        'path': '/' + path,
        'method': request.method,
        'headers': dict(request.headers),
        'body': request.get_json(silent=True),
    })

app.run(host='0.0.0.0', port=9999)
" &

# Terminal 2 -- start the proxy pointing at the mock
TARGET_BASE_URL=http://localhost:9999 \
AUTH_TYPE=static \
STATIC_BEARER_TOKEN=test-token-123 \
PROXY_AUTH_TOKEN=arize-secret \
LOG_LEVEL=DEBUG \
  python3 proxy.py
```

**2. Send a test request:**

```bash
# Simple POST (like what Arize sends for chat completions)
curl -s http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer arize-secret" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}' | python3 -m json.tool
```

You should see the echo response showing:
- `path: /v1/chat/completions`
- `headers.Authorization: Bearer test-token-123` (the static token, not the Arize token)
- `body` with the original payload passed through unchanged

**3. Verify health endpoint:**

```bash
curl -s http://localhost:8000/healthz | python3 -m json.tool
# {"status": "ok"}
```

**4. Verify auth rejection:**

```bash
curl -s http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer wrong-token" \
  -H "Content-Type: application/json" \
  -d '{}' -w "\nHTTP %{http_code}\n"
# {"error": "Invalid proxy auth token"}
# HTTP 401
```

### Option B: Docker Compose

```bash
# Copy and edit the env file
cp .env.example .env
# Edit .env: set TARGET_BASE_URL=http://host.docker.internal:9999
#            set AUTH_TYPE=static, STATIC_BEARER_TOKEN=test-token-123

# Start mock upstream on host (same python one-liner from Option A)
# Then start the proxy container
docker-compose up --build

# Test
curl -s http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}' | python3 -m json.tool
```

### Option C: Against a real upstream (with static token)

If you have a real LLM endpoint and a valid token:

```bash
TARGET_BASE_URL=https://api.openai.com/v1 \
AUTH_TYPE=static \
STATIC_BEARER_TOKEN=sk-your-openai-key \
LOG_LEVEL=DEBUG \
  python3 proxy.py

# In another terminal
curl -s http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"say hi"}]}' | python3 -m json.tool
```

### Verifying streaming (SSE)

LLM endpoints often return streaming responses. Test that they pass through:

```bash
# With Option C running, add stream:true
curl -N http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"count to 5"}],"stream":true}'
```

You should see `data: {...}` lines arriving incrementally, not buffered.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `503 TARGET_BASE_URL not configured` | Missing env var | Set `TARGET_BASE_URL` |
| `502 Cannot connect to upstream` | Wrong URL / firewall / DNS | Check `TARGET_BASE_URL` is reachable from the proxy pod |
| `504 Upstream request timed out` | Slow upstream / network | Increase `REQUEST_TIMEOUT` |
| `401 Invalid proxy auth token` | Arize sending wrong token | Check the token in Arize's custom endpoint config matches `PROXY_AUTH_TOKEN` |
| Token fetch fails on startup | Wrong OAuth2 credentials | Verify `OAUTH2_TOKEN_URL`, `CLIENT_ID`, `CLIENT_SECRET` |
| SSL/TLS handshake error | Missing CA cert or client cert | Mount certs and set `REQUESTS_CA_BUNDLE` / `CLIENT_CERT_PATH` / `CLIENT_KEY_PATH` |
| Container exits immediately | Invalid `AUTH_TYPE` or missing required env | Check container logs: `docker-compose logs proxy` |
| Streaming responses arrive all at once | Intermediate buffering (nginx, LB) | Ensure no buffering proxy sits between Arize and this service |

### Useful debug commands

```bash
# Check proxy health
curl http://PROXY_HOST:8000/healthz

# Watch proxy logs in real time
docker-compose logs -f proxy

# Enable debug logging (shows every request URL)
LOG_LEVEL=DEBUG docker-compose up

# Test connectivity from inside the container
docker-compose exec proxy python -c "import requests; print(requests.get('https://TARGET_URL').status_code)"
```
