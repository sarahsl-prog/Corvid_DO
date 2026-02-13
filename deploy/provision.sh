#!/bin/bash
# Corvid Infrastructure Provisioning Script for DigitalOcean
#
# Prerequisites:
#   - doctl CLI installed and authenticated: https://docs.digitalocean.com/reference/doctl/
#   - GitHub repo set up with Corvid code
#   - API keys ready: AbuseIPDB, Gradient AI (optional), NVD (optional)
#
# Usage:
#   ./deploy/provision.sh [--region REGION] [--skip-db] [--skip-redis] [--dry-run]
#
# Default region: sfo3 (San Francisco 3)
# Run with --region=nyc1 if you want New York
#
# This script will:
#   1. Create a managed PostgreSQL database
#   2. Create a managed Redis instance
#   3. Display connection strings for App Platform secrets
#   4. Optionally deploy the app (requires secrets to be set first)
#
# Note: If Redis is not available in your region, sign up for free at
#       https://upstash.com and use Upstash Redis instead (drop-in replacement)

set -euo pipefail

# Configuration
REGION="${REGION:-sfo3}"
DB_NAME="corvid-db"
DB_SIZE="db-s-1vcpu-1gb"
REDIS_NAME="corvid-redis"
REDIS_SIZE="db-s-1vcpu-1gb"
APP_NAME="corvid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse arguments
SKIP_DB=false
SKIP_REDIS=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --region)
            REGION="$2"
            shift 2
            ;;
        --skip-db)
            SKIP_DB=true
            shift
            ;;
        --skip-redis)
            SKIP_REDIS=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_info "Corvid Infrastructure Provisioning"
log_info "Region: $REGION"
log_info "Dry run: $DRY_RUN"
echo ""

# Check doctl is installed
if ! command -v doctl &> /dev/null; then
    log_error "doctl CLI is not installed. Install from: https://docs.digitalocean.com/reference/doctl/"
    exit 1
fi

# Check doctl is authenticated
if ! doctl account get &> /dev/null; then
    log_error "doctl is not authenticated. Run: doctl auth init"
    exit 1
fi

log_info "doctl authenticated successfully"
echo ""

# ============================================
# Step 1: Create PostgreSQL Database
# ============================================
if [ "$SKIP_DB" = false ]; then
    log_info "Creating PostgreSQL database: $DB_NAME"

    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY RUN] Would create: doctl databases create $DB_NAME --engine pg --size $DB_SIZE --region $REGION --num-nodes 1"
    else
        # Check if database already exists
        if doctl databases list --format Name --no-header | grep -q "^${DB_NAME}$"; then
            log_warn "Database $DB_NAME already exists, skipping creation"
        else
            doctl databases create "$DB_NAME" \
                --engine pg \
                --version 15 \
                --size "$DB_SIZE" \
                --region "$REGION" \
                --num-nodes 1 \
                --wait
            log_info "PostgreSQL database created successfully"
        fi

        # Get connection string
        DB_ID=$(doctl databases list --format ID,Name --no-header | grep "$DB_NAME" | awk '{print $1}')
        if [ -n "$DB_ID" ]; then
            DB_URI=$(doctl databases connection "$DB_ID" --format URI --no-header)
            # Convert to asyncpg format
            ASYNC_DB_URI=$(echo "$DB_URI" | sed 's|postgresql://|postgresql+asyncpg://|')
            echo ""
            log_info "Database connection string (add to App Platform secrets):"
            echo "  CORVID_DATABASE_URL=$ASYNC_DB_URI"
        fi
    fi
else
    log_info "Skipping database creation (--skip-db)"
fi
echo ""

# ============================================
# Step 2: Create Redis Instance
# ============================================
if [ "$SKIP_REDIS" = false ]; then
    log_info "Creating Redis instance: $REDIS_NAME"

    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY RUN] Would create: doctl databases create $REDIS_NAME --engine redis --size $DB_SIZE --region $REGION --num-nodes 1"
    else
        # Check if Redis already exists
        if doctl databases list --format Name --no-header | grep -q "^${REDIS_NAME}$"; then
            log_warn "Redis $REDIS_NAME already exists, skipping creation"
        else
            doctl databases create "$REDIS_NAME" \
                --engine redis \
                --version 7 \
                --size "$DB_SIZE" \
                --region "$REGION" \
                --num-nodes 1 \
                --wait
            log_info "Redis instance created successfully"
        fi

        # Get connection string
        REDIS_ID=$(doctl databases list --format ID,Name --no-header | grep "$REDIS_NAME" | awk '{print $1}')
        if [ -n "$REDIS_ID" ]; then
            REDIS_URI=$(doctl databases connection "$REDIS_ID" --format URI --no-header)
            echo ""
            log_info "Redis connection string (add to App Platform secrets):"
            echo "  CORVID_REDIS_URL=$REDIS_URI"
        fi
    fi
else
    log_info "Skipping Redis creation (--skip-redis)"
fi
echo ""

# ============================================
# Step 3: Display Next Steps
# ============================================
echo "============================================"
log_info "Next Steps:"
echo ""
echo "1. Add the following secrets to DigitalOcean App Platform:"
echo "   - CORVID_DATABASE_URL (from above)"
echo "   - CORVID_REDIS_URL (from above)"
echo "   - CORVID_GRADIENT_API_KEY (your Gradient AI key)"
echo "   - CORVID_GRADIENT_KB_ID (your Gradient KB ID)"
echo "   - CORVID_ABUSEIPDB_API_KEY (your AbuseIPDB key)"
echo "   - CORVID_NVD_API_KEY (optional, for higher rate limits)"
echo ""
echo "2. Update deploy/do-app-spec.yaml with your GitHub repo"
echo ""
echo "3. Deploy the app:"
echo "   doctl apps create --spec deploy/do-app-spec.yaml"
echo ""
echo "4. After deployment, run database migrations:"
echo "   # Get the app URL first"
echo "   APP_URL=\$(doctl apps list --format DefaultIngress --no-header | head -1)"
echo "   "
echo "   # Run migrations (from local machine with DB access)"
echo "   CORVID_DATABASE_URL=<production-db-url> alembic upgrade head"
echo ""
echo "5. Optionally, run knowledge base ingestion:"
echo "   CORVID_DATABASE_URL=<production-db-url> python -m corvid.ingestion.loader --years=2"
echo ""
echo "6. Run smoke tests:"
echo "   CORVID_TEST_URL=\$APP_URL pytest tests/smoke/ -v"
echo ""
echo "============================================"
