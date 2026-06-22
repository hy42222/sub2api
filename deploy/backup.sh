#!/bin/bash
# =============================================================================
# Sub2API 数据库自动备份脚本
# 每天凌晨 3 点执行，保留最近 7 天的备份
# =============================================================================
set -e

BACKUP_DIR="/home/dev/openai_io/sub2api/deploy/backups"
RETENTION_DAYS=7
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CONTAINER="sub2api-postgres"
DB_NAME="sub2api"
DB_USER="sub2api"

mkdir -p "$BACKUP_DIR"

# 执行备份
docker exec "$CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" \
    --no-owner --no-acl --clean --if-exists \
    | gzip > "$BACKUP_DIR/sub2api_${TIMESTAMP}.sql.gz"

echo "[$(date)] Backup created: sub2api_${TIMESTAMP}.sql.gz"

# 清理旧备份
find "$BACKUP_DIR" -name "sub2api_*.sql.gz" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true

# 显示备份大小和数量
BACKUP_COUNT=$(find "$BACKUP_DIR" -name "sub2api_*.sql.gz" | wc -l)
TOTAL_SIZE=$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)
echo "[$(date)] Backups: $BACKUP_COUNT files, $TOTAL_SIZE total"
