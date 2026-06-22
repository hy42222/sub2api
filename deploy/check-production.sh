#!/bin/bash
# =============================================================================
# Sub2API Production Health Check Script
# 用法: SUB2API_KEY=sk-xxx ./check-production.sh
# API Key 从环境变量读取，不硬编码
# =============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "[INFO] $1"; }

COMPOSE_FILE="docker-compose.prod.yml"
DOMAIN="${SUB2API_DOMAIN:-api.hyailocalai.com}"
API_KEY="${SUB2API_KEY:-}"

echo "============================================"
echo " Sub2API Production Check — $(date '+%F %T')"
echo "============================================"

# --- 1. Docker service status ---
echo ""
echo "--- 1. Docker Service Status ---"
cd "$(dirname "$0")"
if sudo docker compose -f "$COMPOSE_FILE" ps 2>/dev/null | grep -q "sub2api.*healthy"; then
    pass "Sub2API container healthy"
else
    fail "Sub2API container not healthy"
fi
if sudo docker compose -f "$COMPOSE_FILE" ps 2>/dev/null | grep -q "sub2api-caddy.*healthy"; then
    pass "Caddy container healthy"
else
    fail "Caddy container not healthy"
fi
if sudo docker compose -f "$COMPOSE_FILE" ps 2>/dev/null | grep -q "sub2api-postgres.*healthy"; then
    pass "PostgreSQL container healthy"
else
    fail "PostgreSQL container not healthy"
fi
if sudo docker compose -f "$COMPOSE_FILE" ps 2>/dev/null | grep -q "sub2api-redis.*healthy"; then
    pass "Redis container healthy"
else
    fail "Redis container not healthy"
fi

# --- 2. Port status ---
echo ""
echo "--- 2. Port Status ---"
PORTS=$(sudo ss -tulpen 2>/dev/null)
if echo "$PORTS" | grep -q ':80 '; then
    pass "Port 80 listening"
else
    warn "Port 80 not listening"
fi
if echo "$PORTS" | grep -q ':443 '; then
    pass "Port 443 listening"
else
    warn "Port 443 not listening"
fi
if echo "$PORTS" | grep -q ':8080 '; then
    fail "Port 8080 exposed to public — should not be!"
else
    pass "Port 8080 NOT exposed to host (secure)"
fi

# --- 3. Host egress IP ---
echo ""
echo "--- 3. Egress IP ---"
HOST_IP=$(curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "FAILED")
if [ "$HOST_IP" != "FAILED" ]; then
    info "Host egress IP: $HOST_IP"
else
    fail "Cannot determine host egress IP"
fi

# --- 4. Container egress IP ---
CONTAINER_IP=$(sudo docker compose -f "$COMPOSE_FILE" exec -T sub2api sh -c 'curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "FAILED"' 2>/dev/null)
if [ "$CONTAINER_IP" != "FAILED" ] && [ -n "$CONTAINER_IP" ]; then
    info "Container egress IP: $CONTAINER_IP"
    if [ "$HOST_IP" = "$CONTAINER_IP" ]; then
        pass "Egress IP consistent: host == container"
    else
        warn "Egress IP differs: host=$HOST_IP container=$CONTAINER_IP"
    fi
else
    fail "Cannot determine container egress IP"
fi

# --- 5. Proxy env ---
echo ""
echo "--- 5. Proxy Environment ---"
PROXY_ENV=$(sudo docker compose -f "$COMPOSE_FILE" exec -T sub2api env 2>/dev/null | grep -Ei '^HTTP_PROXY=|^HTTPS_PROXY=|^ALL_PROXY=|^http_proxy=|^https_proxy=|^all_proxy=' || true)
if [ -z "$PROXY_ENV" ]; then
    pass "No proxy env vars — using direct egress"
else
    warn "Proxy env detected: $PROXY_ENV"
fi

# --- 6. HTTPS health ---
echo ""
echo "--- 6. HTTPS Health ---"
HEALTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://${DOMAIN}/health" 2>/dev/null || echo "FAILED")
if [ "$HEALTH_CODE" = "200" ]; then
    pass "Health endpoint: 200 OK"
else
    fail "Health endpoint: $HEALTH_CODE"
fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://${DOMAIN}/" 2>/dev/null || echo "FAILED")
if [ "$HTTP_CODE" = "200" ]; then
    pass "Web UI: 200 OK"
else
    fail "Web UI: $HTTP_CODE"
fi

# --- 7. API /v1/models ---
echo ""
echo "--- 7. API /v1/models ---"
if [ -n "$API_KEY" ]; then
    API_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -H "Authorization: Bearer ${API_KEY}" \
        "https://${DOMAIN}/v1/models" 2>/dev/null || echo "FAILED")
    if [ "$API_CODE" = "200" ]; then
        pass "/v1/models: 200 OK (authenticated)"
    elif [ "$API_CODE" = "401" ]; then
        fail "/v1/models: 401 — API Key invalid or expired"
    elif [ "$API_CODE" = "403" ]; then
        fail "/v1/models: 403 — insufficient balance or access denied"
    else
        warn "/v1/models: HTTP $API_CODE"
    fi
else
    warn "SUB2API_KEY not set — skipping authenticated API test"
    info "Usage: SUB2API_KEY=sk-xxx $0"
fi

# --- 8. HTTP→HTTPS redirect ---
echo ""
echo "--- 8. HTTP to HTTPS redirect ---"
REDIRECT=$(curl -s -o /dev/null -w "%{redirect_url}" --max-time 5 "http://${DOMAIN}/" 2>/dev/null || echo "FAILED")
if echo "$REDIRECT" | grep -q "https"; then
    pass "HTTP redirects to HTTPS"
else
    info "HTTP redirect: $REDIRECT (may be expected if Caddy handles this)"
fi

echo ""
echo "============================================"
echo " Check Complete — $(date '+%F %T')"
echo "============================================"
