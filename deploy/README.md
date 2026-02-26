# Corvid Deployment Guide

Deploy Corvid to DigitalOcean App Platform with managed PostgreSQL and Redis.

## Prerequisites

1. **DigitalOcean Account** with billing enabled
2. **doctl CLI** installed and authenticated
   ```bash
   # Install doctl
   brew install doctl  # macOS
   # or download from https://docs.digitalocean.com/reference/doctl/

   # Authenticate
   doctl auth init
   ```
3. **GitHub Repository** with Corvid code pushed
4. **API Keys** ready:
   - AbuseIPDB: https://www.abuseipdb.com/api (free tier available)
   - Gradient AI API Key: Get from [Gradient AI Console](https://cloud.digitalocean.com/gradient-ai-platform)
   - NVD: https://nvd.nist.gov/developers/request-an-api-key (optional, for higher rate limits)

## Gradient AI Setup

### Option A: Use Gradient as External API (Current Implementation)

The current code calls Gradient's API directly. This is the simplest setup:

1. Go to [Gradient AI Console](https://cloud.digitalocean.com/gradient-ai-platform/serverless-inference)
2. Create a Model Access Key (or use existing)
3. Copy the key - this becomes your `CORVID_GRADIENT_API_KEY`

No additional setup needed - the code handles everything via REST API calls.

### Option B: Deploy Agent as DigitalOcean Service (Alternative)

If you want to deploy the agent as a managed DigitalOcean Agent:

1. Enable "Agent Development Kit (ADK)" in [Feature Preview](https://cloud.digitalocean.com/account/feature-preview)
2. Create a workspace and agent in the Gradient console
3. Get the agent endpoint URL
4. Update `corvid/agent/agent.py` to call the agent endpoint instead of direct API

For ADK deployment instructions, see: https://docs.digitalocean.com/products/gradient-ai-platform/how-to/build-agents-using-adk/

## Quick Start

### 1. Provision Infrastructure

```bash
# Make the script executable
chmod +x deploy/provision.sh

# Run provisioning (creates Postgres + Redis)
./deploy/provision.sh --region nyc1

# Or dry-run first to see what will be created
./deploy/provision.sh --region nyc1 --dry-run
```

This creates:
- Managed PostgreSQL database (`db-s-1vcpu-1gb`, ~$15/month)
- Managed Redis OR use Upstash/free Redis service

### 2. Configure App Platform Secrets

After provisioning, you'll see connection strings. Add these as secrets in DigitalOcean:

**Via Console:**
1. Go to App Platform > Your App > Settings > App-Level Environment Variables
2. Add each secret with type "Secret"

**Via doctl:**
```bash
doctl apps update <app-id> --spec deploy/do-app-spec.yaml
```

Required secrets:
| Variable | Description |
|----------|-------------|
| `CORVID_DATABASE_URL` | PostgreSQL connection string (use `postgresql+asyncpg://` prefix) |
| `CORVID_REDIS_URL` | Redis connection string |
| `CORVID_GRADIENT_API_KEY` | Gradient AI API key (from Gradient console) |
| `CORVID_GRADIENT_MODEL` | Gradient model name (default: `gradient-large`) |
| `CORVID_ABUSEIPDB_API_KEY` | AbuseIPDB API key |
| `CORVID_NVD_API_KEY` | NVD API key (optional) |

Optional:
| Variable | Description |
|----------|-------------|
| `CORVID_GRADIENT_KB_ID` | Gradient Knowledge Base ID (for CVE context in analysis) |

### 3. Create a Redis Droplet (if not using managed Redis)

If managed Redis is not available in your region, you can run Redis in a Docker container on a Droplet:

```bash
# Create a droplet (minimum $4/mo)
doctl compute droplet create corvid-redis \
  --image docker-20-04 \
  --region sfo3 \
  --size s-1vcpu-1gb \
  --ssh-keys <your-ssh-key-id>

# After creation, SSH in and run Redis:
# 1. Create droplet with Docker app
# 2. SSH in and run:
docker run -d --name corvid-redis \
  -p 6379:6379 \
  redis:latest

# Get the droplet IP and use as: redis://:@<droplet-ip>:6379
```

Or use **Upstash** (recommended - free serverless Redis):
1. Sign up at https://upstash.com
2. Create a free Redis database
3. Copy the connection URL (format: `redis://default:pass@host:port`)

### 4. Update App Spec

Edit `deploy/do-app-spec.yaml`:
```yaml
github:
  repo: your-username/your-repo  # Update this
  branch: main
```

### 5. Deploy the App

```bash
# Create the app
doctl apps create --spec deploy/do-app-spec.yaml

# Or update existing app
doctl apps update <app-id> --spec deploy/do-app-spec.yaml
```

### 6. Run Database Migrations

After deployment, run migrations against the production database:

```bash
# Set the production database URL
export CORVID_DATABASE_URL="postgresql+asyncpg://user:pass@host:port/dbname?sslmode=require"

# Run migrations
alembic upgrade head
```

### 7. (Optional) Populate Knowledge Base

If using Gradient AI for full analysis with CVE context:

1. First, create a Knowledge Base in the [Gradient AI Console](https://cloud.digitalocean.com/gradient-ai-platform/knowledge-bases)
2. Get the Knowledge Base ID
3. Uncomment the `CORVID_GRADIENT_KB_ID` secret in `do-app-spec.yaml`
4. Redeploy: `doctl apps update <app-id> --spec deploy/do-app-spec.yaml`
5. Load CVEs:
```bash
python -m corvid.ingestion.loader --cve-file=path/to/cvelistV5/cves --years=2
```

Or use the API to populate the KB after deployment.

### 7. Verify Deployment

```bash
# Get app URL
APP_URL=$(doctl apps list --format DefaultIngress --no-header | head -1)
echo "App URL: https://$APP_URL"

# Health check
curl "https://$APP_URL/health" | jq

# Run smoke tests
CORVID_TEST_URL="https://$APP_URL" pytest tests/smoke/ -v
```

## Managing the Deployment

### View Logs

```bash
# List apps
doctl apps list

# Get logs
doctl apps logs <app-id> --follow
```

### Scale the App

Edit `deploy/do-app-spec.yaml`:
```yaml
instance_count: 2  # Increase replicas
instance_size_slug: basic-xs  # Upgrade instance size
```

Then apply:
```bash
doctl apps update <app-id> --spec deploy/do-app-spec.yaml
```

### Environment Variables

Update environment variables:
```bash
# Via console
# App Platform > Settings > App-Level Environment Variables

# Via doctl (update spec and redeploy)
doctl apps update <app-id> --spec deploy/do-app-spec.yaml
```

### Database Migrations

For schema changes:
```bash
# 1. Generate migration locally
alembic revision --autogenerate -m "description of change"

# 2. Review the generated migration in corvid/db/migrations/versions/

# 3. Apply to production
CORVID_DATABASE_URL="<production-url>" alembic upgrade head
```

### Rollback

```bash
# List deployments
doctl apps list-deployments <app-id>

# Rollback to previous deployment
doctl apps create-deployment <app-id> --force-rebuild
```

## Troubleshooting

### App Won't Start

1. Check logs:
   ```bash
   doctl apps logs <app-id>
   ```

2. Verify environment variables are set:
   ```bash
   doctl apps spec get <app-id>
   ```

3. Test database connectivity:
   ```bash
   psql "<database-url>"
   ```

### Health Check Failing

1. Check individual component status:
   ```bash
   curl "https://$APP_URL/health" | jq '.checks'
   ```

2. Common issues:
   - **db: false** - Database URL incorrect or firewall blocking
   - **redis: false** - Redis URL incorrect or not running
   - **gradient: false** - API key invalid (optional, app still works)

### Slow Response Times

1. Check instance size - upgrade if needed
2. Check database connection pooling
3. Enable Redis caching for enrichments

### Database Connection Issues

DigitalOcean managed databases require SSL:
```bash
# Ensure your connection string includes sslmode
postgresql+asyncpg://user:pass@host:port/db?sslmode=require
```

## Cost Estimate

| Resource | Size | Monthly Cost |
|----------|------|-------------|
| App Platform | basic-xxs | ~$5 |
| PostgreSQL | db-s-1vcpu-1gb | ~$15 |
| Redis | db-s-1vcpu-1gb | ~$15 |
| **Total** | | **~$35/month** |

## Architecture

```
                    ┌─────────────────────┐
                    │   DigitalOcean      │
                    │   App Platform      │
                    │   (Corvid API)      │
                    └─────────┬───────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
    ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
    │  Managed    │   │  Managed    │   │  Gradient   │
    │  PostgreSQL │   │  Redis      │   │  AI API     │
    └─────────────┘   └─────────────┘   └─────────────┘
```

## Security Considerations

1. **Secrets**: All API keys stored as DO secrets (encrypted at rest)
2. **Database**: Managed DB with automatic backups, SSL required
3. **Network**: App runs in isolated DO network
4. **Non-root**: Container runs as non-root user
5. **Health checks**: Automatic container restarts on failure
