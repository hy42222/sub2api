package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
)

const (
	keyIPAuditProjectionSafetyDelay = 2 * time.Minute
	// Keep the requested 30-day window plus its equally long comparison window
	// and a small late-write cushion.
	keyIPAuditProjectionRetention = 65 * 24 * time.Hour
)

type keyIPAuditAggregationRepository struct {
	db *sql.DB
}

func NewKeyIPAuditAggregationRepository(db *sql.DB) service.KeyIPAuditAggregationRepository {
	return &keyIPAuditAggregationRepository{db: db}
}

type keyIPAuditProjectionCursor struct {
	liveSince          time.Time
	processedID        int64
	processedCreatedAt time.Time
}

type normalizedSecurityActivity struct {
	id          int64
	apiKeyID    int64
	userID      int64
	createdAt   time.Time
	bucketStart time.Time
	clientIP    string
	userAgent   string
}

type securityActivityAggregate struct {
	bucketStart    time.Time
	apiKeyID       int64
	userID         int64
	clientIP       string
	userAgent      string
	requestCount   int64
	missingIPCount int64
	missingUACount int64
	firstSeen      time.Time
	lastSeen       time.Time
}

type securityActivityAggregateKey struct {
	bucketStart time.Time
	apiKeyID    int64
	userID      int64
	clientIP    string
	userAgent   string
}

type securityActivityRollupAggregate struct {
	bucketMinutes  int16
	bucketStart    time.Time
	apiKeyID       int64
	userID         int64
	clientIP       string
	userAgent      string
	requestCount   int64
	missingIPCount int64
	missingUACount int64
	firstSeen      time.Time
	lastSeen       time.Time
}

type securityActivityRollupAggregateKey struct {
	bucketMinutes int16
	bucketStart   time.Time
	apiKeyID      int64
	userID        int64
	clientIP      string
	userAgent     string
}

func (r *keyIPAuditAggregationRepository) ProcessKeyIPAuditBatch(ctx context.Context, batchSize int) (service.KeyIPAuditAggregationResult, error) {
	if r == nil || r.db == nil {
		return service.KeyIPAuditAggregationResult{}, errors.New("nil key/ip audit aggregation repository")
	}
	if batchSize <= 0 {
		batchSize = 1000
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return service.KeyIPAuditAggregationResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	cursor, err := readKeyIPAuditProjectionCursor(ctx, tx)
	if err != nil {
		return service.KeyIPAuditAggregationResult{}, err
	}
	now := time.Now().UTC()
	safeThrough := now.Add(-keyIPAuditProjectionSafetyDelay)
	if safeThrough.Before(cursor.liveSince) {
		safeThrough = cursor.liveSince
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT q.projection_id, q.user_id, q.api_key_id, q.created_at,
		       COALESCE(host(try_inet(NULLIF(BTRIM(q.ip_address), ''))), ''),
		       LEFT(COALESCE(NULLIF(BTRIM(q.user_agent), ''), ''), 512)
		FROM security_activity_projection_queue q
		JOIN api_keys k ON k.id = q.api_key_id
		WHERE q.enqueued_at >= $1
		  AND q.created_at < $2
			AND NOT EXISTS (
				SELECT 1 FROM security_activity_projection_events e
				WHERE e.projection_id = q.projection_id
			)
		ORDER BY q.created_at, q.projection_id
		LIMIT $3`, cursor.liveSince, safeThrough, batchSize)
	if err != nil {
		return service.KeyIPAuditAggregationResult{}, err
	}
	defer rows.Close()

	sources := make([]normalizedSecurityActivity, 0, batchSize)
	var maxSeenAt time.Time
	var maxSeenID int64
	for rows.Next() {
		var item normalizedSecurityActivity
		if err := rows.Scan(&item.id, &item.userID, &item.apiKeyID, &item.createdAt, &item.clientIP, &item.userAgent); err != nil {
			return service.KeyIPAuditAggregationResult{}, err
		}
		item.createdAt = item.createdAt.UTC()
		item.bucketStart = item.createdAt.Truncate(time.Minute)
		sources = append(sources, item)
		if item.createdAt.After(maxSeenAt) || (item.createdAt.Equal(maxSeenAt) && item.id > maxSeenID) {
			maxSeenAt, maxSeenID = item.createdAt, item.id
		}
	}
	if err := rows.Err(); err != nil {
		return service.KeyIPAuditAggregationResult{}, err
	}
	if err := rows.Close(); err != nil {
		return service.KeyIPAuditAggregationResult{}, err
	}

	if len(sources) > 0 {
		ids := make([]int64, 0, len(sources))
		for _, item := range sources {
			ids = append(ids, item.id)
		}
		acceptedRows, err := tx.QueryContext(ctx, `
			INSERT INTO security_activity_projection_events (projection_id)
			SELECT value FROM unnest($1::bigint[]) AS value
			ON CONFLICT (projection_id) DO NOTHING
			RETURNING projection_id`, pq.Array(ids))
		if err != nil {
			return service.KeyIPAuditAggregationResult{}, err
		}
		acceptedIDs := make(map[int64]struct{}, len(sources))
		for acceptedRows.Next() {
			var id int64
			if err := acceptedRows.Scan(&id); err != nil {
				_ = acceptedRows.Close()
				return service.KeyIPAuditAggregationResult{}, err
			}
			acceptedIDs[id] = struct{}{}
		}
		if err := acceptedRows.Err(); err != nil {
			_ = acceptedRows.Close()
			return service.KeyIPAuditAggregationResult{}, err
		}
		if err := acceptedRows.Close(); err != nil {
			return service.KeyIPAuditAggregationResult{}, err
		}
		accepted := make([]int64, 0, len(acceptedIDs))
		for id := range acceptedIDs {
			accepted = append(accepted, id)
		}
		if len(accepted) > 0 {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO security_activity_events
					(projection_id, source_relation, usage_log_id, created_at, api_key_id, user_id, client_ip, user_agent)
				SELECT q.projection_id, q.source_relation, q.usage_log_id, q.created_at, q.api_key_id, q.user_id,
				       COALESCE(host(try_inet(NULLIF(BTRIM(q.ip_address), ''))), ''),
				       LEFT(COALESCE(NULLIF(BTRIM(q.user_agent), ''), ''), 512)
				FROM security_activity_projection_queue q
				WHERE q.projection_id = ANY($1::bigint[])
				ON CONFLICT (projection_id) DO NOTHING`, pq.Array(accepted)); err != nil {
				return service.KeyIPAuditAggregationResult{}, err
			}
		}

		aggregates := make(map[securityActivityAggregateKey]*securityActivityAggregate, len(acceptedIDs))
		for _, item := range sources {
			if _, ok := acceptedIDs[item.id]; !ok {
				continue
			}
			key := securityActivityAggregateKey{
				bucketStart: item.bucketStart,
				apiKeyID:    item.apiKeyID,
				userID:      item.userID,
				clientIP:    item.clientIP,
				userAgent:   item.userAgent,
			}
			aggregate := aggregates[key]
			if aggregate == nil {
				aggregate = &securityActivityAggregate{
					bucketStart: item.bucketStart,
					apiKeyID:    item.apiKeyID,
					userID:      item.userID,
					clientIP:    item.clientIP,
					userAgent:   item.userAgent,
					firstSeen:   item.createdAt,
					lastSeen:    item.createdAt,
				}
				aggregates[key] = aggregate
			}
			aggregate.requestCount++
			if item.clientIP == "" {
				aggregate.missingIPCount++
			}
			if item.userAgent == "" {
				aggregate.missingUACount++
			}
			if item.createdAt.Before(aggregate.firstSeen) {
				aggregate.firstSeen = item.createdAt
			}
			if item.createdAt.After(aggregate.lastSeen) {
				aggregate.lastSeen = item.createdAt
			}
		}
		if len(aggregates) > 0 {
			if err := insertSecurityActivityAggregates(ctx, tx, aggregates); err != nil {
				return service.KeyIPAuditAggregationResult{}, err
			}
			if err := insertSecurityActivityRollups(ctx, tx, aggregates); err != nil {
				return service.KeyIPAuditAggregationResult{}, err
			}
			keys, ips, minBucket, maxBucket := projectionAffectedDimensions(aggregates)
			if err := rebuildKeyIPAuditRollups(ctx, tx, keys, ips, minBucket, maxBucket); err != nil {
				return service.KeyIPAuditAggregationResult{}, err
			}
			if err := refreshKeyIPAuditState(ctx, tx, keys); err != nil {
				return service.KeyIPAuditAggregationResult{}, err
			}
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM security_activity_projection_queue
			WHERE projection_id = ANY($1::bigint[])`, pq.Array(ids)); err != nil {
			return service.KeyIPAuditAggregationResult{}, err
		}
	}

	if maxSeenAt.IsZero() {
		maxSeenAt = cursor.processedCreatedAt
		maxSeenID = cursor.processedID
	}
	if maxSeenAt.After(cursor.processedCreatedAt) || (maxSeenAt.Equal(cursor.processedCreatedAt) && maxSeenID > cursor.processedID) {
		cursor.processedCreatedAt, cursor.processedID = maxSeenAt, maxSeenID
	}
	var oldestPending sql.NullTime
	if err := scanSingleRow(ctx, tx, `
		SELECT MIN(q.created_at)
			FROM security_activity_projection_queue q
			JOIN api_keys k ON k.id = q.api_key_id
				WHERE q.enqueued_at >= $1
				  AND q.created_at < $2
				  AND NOT EXISTS (
					SELECT 1 FROM security_activity_projection_events e
						WHERE e.projection_id = q.projection_id
				  )
		`, []any{cursor.liveSince, safeThrough}, &oldestPending); err != nil {
		return service.KeyIPAuditAggregationResult{}, err
	}
	dataThrough := safeThrough
	if oldestPending.Valid && oldestPending.Time.Before(dataThrough) {
		dataThrough = oldestPending.Time
	}
	if dataThrough.Before(cursor.liveSince) {
		dataThrough = cursor.liveSince
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE key_ip_audit_projection_state
		SET processed_usage_log_id = $1,
		    processed_created_at = $2,
		    data_through = $3,
		    last_successful_at = $4,
		    updated_at = $4
		WHERE id = 1`, cursor.processedID, nullableTime(cursor.processedCreatedAt), dataThrough, now); err != nil {
		return service.KeyIPAuditAggregationResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return service.KeyIPAuditAggregationResult{}, err
	}
	return service.KeyIPAuditAggregationResult{Processed: len(sources), DataThrough: dataThrough}, nil
}

func readKeyIPAuditProjectionCursor(ctx context.Context, q sqlQueryer) (keyIPAuditProjectionCursor, error) {
	var cursor keyIPAuditProjectionCursor
	var processedAt sql.NullTime
	err := scanSingleRow(ctx, q, `
		SELECT live_since, processed_usage_log_id, processed_created_at
		FROM key_ip_audit_projection_state
		WHERE id = 1`, nil, &cursor.liveSince, &cursor.processedID, &processedAt)
	if err != nil {
		return cursor, err
	}
	if processedAt.Valid {
		cursor.processedCreatedAt = processedAt.Time.UTC()
	}
	return cursor, nil
}

func (r *keyIPAuditAggregationRepository) GetKeyIPAuditProjectionState(ctx context.Context) (*service.KeyIPAuditProjectionState, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("nil key/ip audit aggregation repository")
	}
	var state service.KeyIPAuditProjectionState
	var processedAt, through, successfulAt sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		SELECT live_since, processed_usage_log_id, processed_created_at,
		       data_through, last_successful_at
		FROM key_ip_audit_projection_state
		WHERE id = 1`).Scan(&state.LiveSince, &state.ProcessedUsageLogID, &processedAt, &through, &successfulAt)
	if err != nil {
		return nil, err
	}
	if processedAt.Valid {
		state.ProcessedCreatedAt = processedAt.Time.UTC()
	}
	if through.Valid {
		state.DataThrough = through.Time.UTC()
	}
	if successfulAt.Valid {
		state.LastSuccessfulAt = successfulAt.Time.UTC()
	}
	return &state, nil
}

func (r *keyIPAuditAggregationRepository) PruneKeyIPAuditProjection(ctx context.Context, batchSize int) error {
	if r == nil || r.db == nil {
		return errors.New("nil key/ip audit aggregation repository")
	}
	if batchSize <= 0 {
		batchSize = 1000
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	cutoff := now.Add(-keyIPAuditProjectionRetention)
	for _, table := range []string{"security_activity_1m", "key_ip_audit_ip_1m", "key_ip_audit_key_1m"} {
		query := fmt.Sprintf(`
			WITH doomed AS (
				SELECT ctid FROM %s
				WHERE bucket_start <= $1::timestamptz - INTERVAL '1 minute'
				LIMIT $2
			)
			DELETE FROM %s t USING doomed
			WHERE t.ctid = doomed.ctid`, table, table)
		if _, err := tx.ExecContext(ctx, query, cutoff, batchSize); err != nil {
			return err
		}
	}
	for _, table := range []string{"security_activity_rollups", "key_ip_audit_key_rollups"} {
		for _, resolution := range []struct {
			minutes  int16
			interval string
		}{{minutes: 60, interval: "60 minutes"}, {minutes: 1440, interval: "1440 minutes"}} {
			query := fmt.Sprintf(`
				WITH doomed AS (
					SELECT ctid FROM %s
					WHERE bucket_minutes = $1
					  AND bucket_start <= $2::timestamptz - INTERVAL '%s'
					LIMIT $3
				)
				DELETE FROM %s t USING doomed
				WHERE t.ctid = doomed.ctid`, table, resolution.interval, table)
			if _, err := tx.ExecContext(ctx, query, resolution.minutes, cutoff, batchSize); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `
		WITH doomed AS (
			SELECT projection_id FROM security_activity_events
			WHERE created_at < $1 LIMIT $2
		)
		DELETE FROM security_activity_events e USING doomed
		WHERE e.projection_id = doomed.projection_id`, cutoff, batchSize); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		WITH doomed AS (
			SELECT ctid FROM key_ip_audit_ip_state
			WHERE NOT is_baseline AND last_seen < $1
			LIMIT $2
		)
		DELETE FROM key_ip_audit_ip_state s USING doomed
		WHERE s.ctid = doomed.ctid`, cutoff, batchSize); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		WITH doomed AS (
			SELECT ctid
			FROM security_activity_projection_events
			WHERE projected_at < $1
			LIMIT $2
		)
		DELETE FROM security_activity_projection_events e USING doomed
		WHERE e.ctid = doomed.ctid`, cutoff, batchSize); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		WITH doomed AS (
			SELECT q.ctid
			FROM security_activity_projection_queue q
			CROSS JOIN key_ip_audit_projection_state p
			WHERE p.id = 1 AND (q.enqueued_at < p.live_since
				OR NOT EXISTS (SELECT 1 FROM api_keys k WHERE k.id = q.api_key_id))
			LIMIT $1
		)
		DELETE FROM security_activity_projection_queue q USING doomed
		WHERE q.ctid = doomed.ctid`, batchSize); err != nil {
		return err
	}
	return tx.Commit()
}

func insertSecurityActivityAggregates(ctx context.Context, tx *sql.Tx, aggregates map[securityActivityAggregateKey]*securityActivityAggregate) error {
	items := make([]*securityActivityAggregate, 0, len(aggregates))
	for _, item := range aggregates {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].bucketStart.Equal(items[j].bucketStart) {
			return items[i].apiKeyID < items[j].apiKeyID
		}
		return items[i].bucketStart.Before(items[j].bucketStart)
	})
	var query strings.Builder
	query.WriteString(`INSERT INTO security_activity_1m (
		bucket_start, api_key_id, user_id, client_ip, user_agent,
		request_count, missing_ip_count, missing_user_agent_count, first_seen, last_seen
	) VALUES `)
	args := make([]any, 0, len(items)*10)
	for i, item := range items {
		if i > 0 {
			query.WriteString(",")
		}
		base := i*10 + 1
		query.WriteString(fmt.Sprintf("($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)", base, base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8, base+9))
		args = append(args, item.bucketStart, item.apiKeyID, item.userID, item.clientIP, item.userAgent, item.requestCount, item.missingIPCount, item.missingUACount, item.firstSeen, item.lastSeen)
	}
	query.WriteString(`
	ON CONFLICT (bucket_start, api_key_id, user_id, client_ip, user_agent) DO UPDATE SET
		request_count = security_activity_1m.request_count + EXCLUDED.request_count,
		missing_ip_count = security_activity_1m.missing_ip_count + EXCLUDED.missing_ip_count,
		missing_user_agent_count = security_activity_1m.missing_user_agent_count + EXCLUDED.missing_user_agent_count,
		first_seen = LEAST(security_activity_1m.first_seen, EXCLUDED.first_seen),
		last_seen = GREATEST(security_activity_1m.last_seen, EXCLUDED.last_seen)`)
	_, err := tx.ExecContext(ctx, query.String(), args...)
	return err
}

func insertSecurityActivityRollups(ctx context.Context, tx *sql.Tx, aggregates map[securityActivityAggregateKey]*securityActivityAggregate) error {
	rollups := make(map[securityActivityRollupAggregateKey]*securityActivityRollupAggregate, len(aggregates)*2)
	for _, item := range aggregates {
		utc := item.bucketStart.UTC()
		for _, bucketMinutes := range []int16{60, 1440} {
			bucketStart := utc.Truncate(time.Hour)
			if bucketMinutes == 1440 {
				bucketStart = time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
			}
			key := securityActivityRollupAggregateKey{
				bucketMinutes: bucketMinutes,
				bucketStart:   bucketStart,
				apiKeyID:      item.apiKeyID,
				userID:        item.userID,
				clientIP:      item.clientIP,
				userAgent:     item.userAgent,
			}
			rollup := rollups[key]
			if rollup == nil {
				rollup = &securityActivityRollupAggregate{
					bucketMinutes: bucketMinutes,
					bucketStart:   bucketStart,
					apiKeyID:      item.apiKeyID,
					userID:        item.userID,
					clientIP:      item.clientIP,
					userAgent:     item.userAgent,
					firstSeen:     item.firstSeen,
					lastSeen:      item.lastSeen,
				}
				rollups[key] = rollup
			}
			rollup.requestCount += item.requestCount
			rollup.missingIPCount += item.missingIPCount
			rollup.missingUACount += item.missingUACount
			if item.firstSeen.Before(rollup.firstSeen) {
				rollup.firstSeen = item.firstSeen
			}
			if item.lastSeen.After(rollup.lastSeen) {
				rollup.lastSeen = item.lastSeen
			}
		}
	}

	items := make([]*securityActivityRollupAggregate, 0, len(rollups))
	for _, item := range rollups {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].bucketMinutes != items[j].bucketMinutes {
			return items[i].bucketMinutes < items[j].bucketMinutes
		}
		if !items[i].bucketStart.Equal(items[j].bucketStart) {
			return items[i].bucketStart.Before(items[j].bucketStart)
		}
		if items[i].apiKeyID != items[j].apiKeyID {
			return items[i].apiKeyID < items[j].apiKeyID
		}
		if items[i].userID != items[j].userID {
			return items[i].userID < items[j].userID
		}
		if items[i].clientIP != items[j].clientIP {
			return items[i].clientIP < items[j].clientIP
		}
		return items[i].userAgent < items[j].userAgent
	})

	var query strings.Builder
	query.WriteString(`INSERT INTO security_activity_rollups (
		bucket_minutes, bucket_start, api_key_id, user_id, client_ip, user_agent,
		request_count, missing_ip_count, missing_user_agent_count, first_seen, last_seen
	) VALUES `)
	args := make([]any, 0, len(items)*11)
	for i, item := range items {
		if i > 0 {
			query.WriteString(",")
		}
		base := i*11 + 1
		query.WriteString(fmt.Sprintf("($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			base, base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8, base+9, base+10))
		args = append(args, item.bucketMinutes, item.bucketStart, item.apiKeyID, item.userID,
			item.clientIP, item.userAgent, item.requestCount, item.missingIPCount,
			item.missingUACount, item.firstSeen, item.lastSeen)
	}
	query.WriteString(`
	ON CONFLICT (bucket_minutes, bucket_start, api_key_id, user_id, client_ip, user_agent) DO UPDATE SET
		request_count = security_activity_rollups.request_count + EXCLUDED.request_count,
		missing_ip_count = security_activity_rollups.missing_ip_count + EXCLUDED.missing_ip_count,
		missing_user_agent_count = security_activity_rollups.missing_user_agent_count + EXCLUDED.missing_user_agent_count,
		first_seen = LEAST(security_activity_rollups.first_seen, EXCLUDED.first_seen),
		last_seen = GREATEST(security_activity_rollups.last_seen, EXCLUDED.last_seen)`)
	_, err := tx.ExecContext(ctx, query.String(), args...)
	return err
}

func projectionAffectedDimensions(aggregates map[securityActivityAggregateKey]*securityActivityAggregate) ([]int64, []string, time.Time, time.Time) {
	keySet := make(map[int64]struct{})
	ipSet := make(map[string]struct{})
	var minBucket, maxBucket time.Time
	for _, item := range aggregates {
		keySet[item.apiKeyID] = struct{}{}
		if item.clientIP != "" {
			ipSet[item.clientIP] = struct{}{}
		}
		if minBucket.IsZero() || item.bucketStart.Before(minBucket) {
			minBucket = item.bucketStart
		}
		if maxBucket.IsZero() || item.bucketStart.After(maxBucket) {
			maxBucket = item.bucketStart
		}
	}
	keys := make([]int64, 0, len(keySet))
	for key := range keySet {
		keys = append(keys, key)
	}
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	sort.Strings(ips)
	return keys, ips, minBucket, maxBucket
}

func rebuildKeyIPAuditRollups(ctx context.Context, tx *sql.Tx, keys []int64, ips []string, minBucket, maxBucket time.Time) error {
	if len(keys) == 0 || minBucket.IsZero() || maxBucket.IsZero() {
		return nil
	}
	from := minBucket.Add(-10 * time.Minute)
	to := maxBucket.Add(10*time.Minute + time.Minute)
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM key_ip_audit_ip_1m
		WHERE bucket_start >= $3 AND bucket_start < $4
		  AND (api_key_id = ANY($1::bigint[]) OR client_ip = ANY($2::text[]))`, pq.Array(keys), pq.Array(ips), from, to); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		WITH anchors AS (
			SELECT DISTINCT bucket_start, client_ip
			FROM security_activity_1m
			WHERE bucket_start >= $3 AND bucket_start < $4
			  AND client_ip <> ''
			  AND (api_key_id = ANY($1::bigint[]) OR client_ip = ANY($2::text[]))
		), shared AS (
			SELECT DISTINCT a.bucket_start, a.client_ip
			FROM anchors a
			JOIN security_activity_events anchor
			  ON anchor.client_ip=a.client_ip
			 AND anchor.created_at >= a.bucket_start
			 AND anchor.created_at < a.bucket_start + INTERVAL '1 minute'
			 AND anchor.user_id <> 0
			JOIN security_activity_1m f
			  ON f.client_ip = a.client_ip
				 AND f.bucket_start >= a.bucket_start - INTERVAL '10 minutes'
				 AND f.bucket_start <= a.bucket_start
				 AND f.last_seen >= anchor.created_at - INTERVAL '10 minutes'
				 AND f.user_id <> 0 AND f.user_id <> anchor.user_id
				 AND f.api_key_id <> anchor.api_key_id
		)
		INSERT INTO key_ip_audit_ip_1m (
			bucket_start, api_key_id, client_ip, first_seen, last_seen,
			request_count, user_agent_count, user_agent, shared_ip
		)
		SELECT f.bucket_start, f.api_key_id, f.client_ip,
		       MIN(f.first_seen), MAX(f.last_seen), SUM(f.request_count),
		       COUNT(DISTINCT NULLIF(f.user_agent, '')),
		       COALESCE(MIN(NULLIF(f.user_agent, '')), ''),
		       (COUNT(s.client_ip) > 0)
		FROM security_activity_1m f
		LEFT JOIN shared s ON s.bucket_start = f.bucket_start AND s.client_ip = f.client_ip
		WHERE f.bucket_start >= $3 AND f.bucket_start < $4
		  AND f.client_ip <> ''
		  AND (f.api_key_id = ANY($1::bigint[]) OR f.client_ip = ANY($2::text[]))
		GROUP BY f.bucket_start, f.api_key_id, f.client_ip`, pq.Array(keys), pq.Array(ips), from, to); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM key_ip_audit_key_1m
		WHERE bucket_start >= $2 AND bucket_start < $3
		  AND api_key_id IN (
			SELECT DISTINCT api_key_id
			FROM security_activity_1m
			WHERE bucket_start >= $2 AND bucket_start < $3
			  AND (api_key_id = ANY($1::bigint[]) OR client_ip = ANY($4::text[]))
		  )`, pq.Array(keys), from, to, pq.Array(ips)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
			WITH affected AS (
			SELECT DISTINCT api_key_id
			FROM security_activity_1m
			WHERE bucket_start >= $2 AND bucket_start < $3
			  AND (api_key_id = ANY($1::bigint[]) OR client_ip = ANY($4::text[]))
		), anchors AS (
			SELECT DISTINCT f.bucket_start, f.api_key_id
			FROM security_activity_1m f
			JOIN affected a ON a.api_key_id = f.api_key_id
			WHERE f.bucket_start >= $2 AND f.bucket_start < $3
		), rapid_per_anchor AS (
			SELECT a.bucket_start, a.api_key_id, anchor.projection_id,
			       COUNT(DISTINCT f.client_ip) AS rapid_ip_count
			FROM anchors a
			JOIN security_activity_events anchor
			  ON anchor.api_key_id=a.api_key_id
			 AND anchor.created_at >= a.bucket_start
			 AND anchor.created_at < a.bucket_start + INTERVAL '1 minute'
			JOIN security_activity_1m f
			  ON f.api_key_id = a.api_key_id
				 AND f.bucket_start >= a.bucket_start - INTERVAL '10 minutes'
				 AND f.bucket_start <= a.bucket_start
				 AND f.client_ip <> ''
				 AND f.last_seen >= anchor.created_at - INTERVAL '10 minutes'
				 AND f.first_seen <= anchor.created_at
			GROUP BY a.bucket_start, a.api_key_id, anchor.projection_id
		), rapid AS (
			SELECT bucket_start, api_key_id, MAX(rapid_ip_count) AS rapid_ip_count
			FROM rapid_per_anchor GROUP BY bucket_start, api_key_id
		), stats AS (
			SELECT f.bucket_start, f.api_key_id,
			       MIN(f.first_seen) AS first_seen, MAX(f.last_seen) AS last_seen,
			       SUM(f.request_count) AS request_count,
			       SUM(f.missing_ip_count) AS missing_ip_count,
			       SUM(f.missing_user_agent_count) AS missing_user_agent_count
			FROM security_activity_1m f
			JOIN affected a ON a.api_key_id = f.api_key_id
			WHERE f.bucket_start >= $2 AND f.bucket_start < $3
			GROUP BY f.bucket_start, f.api_key_id
		), shared AS (
			SELECT i.bucket_start, i.api_key_id, COUNT(*) FILTER (WHERE i.shared_ip)::bigint AS shared_ip_count
			FROM key_ip_audit_ip_1m i
			JOIN affected a ON a.api_key_id = i.api_key_id
			WHERE i.bucket_start >= $2 AND i.bucket_start < $3
			GROUP BY i.bucket_start, i.api_key_id
		)
		INSERT INTO key_ip_audit_key_1m (
			bucket_start, api_key_id, first_seen, last_seen, request_count,
			missing_ip_count, missing_user_agent_count, raw_rapid_ip_count, raw_shared_ip_count
		)
		SELECT s.bucket_start, s.api_key_id, s.first_seen, s.last_seen, s.request_count,
		       s.missing_ip_count, s.missing_user_agent_count,
		       COALESCE(r.rapid_ip_count, 0), COALESCE(sh.shared_ip_count, 0)
		FROM stats s
		LEFT JOIN rapid r ON r.bucket_start = s.bucket_start AND r.api_key_id = s.api_key_id
			LEFT JOIN shared sh ON sh.bucket_start = s.bucket_start AND sh.api_key_id = s.api_key_id`, pq.Array(keys), from, to, pq.Array(ips)); err != nil {
		return err
	}
	return refreshKeyIPAuditRawRapidRollups(ctx, tx, keys, from, to)
}

func refreshKeyIPAuditRawRapidRollups(ctx context.Context, tx *sql.Tx, keys []int64, from, to time.Time) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO key_ip_audit_key_rollups (
			bucket_minutes, bucket_start, api_key_id, raw_rapid_ip_count
		)
		SELECT resolution.bucket_minutes,
		       CASE resolution.bucket_minutes
		         WHEN 60 THEN date_trunc('hour', m.bucket_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
		         ELSE date_trunc('day', m.bucket_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
		       END AS bucket_start,
		       m.api_key_id, MAX(m.raw_rapid_ip_count)::bigint
		FROM key_ip_audit_key_1m m
		CROSS JOIN (VALUES (60::smallint), (1440::smallint)) AS resolution(bucket_minutes)
		WHERE m.api_key_id = ANY($1::bigint[])
		  AND m.bucket_start >= $2 AND m.bucket_start < $3
		GROUP BY resolution.bucket_minutes, 2, m.api_key_id
		ON CONFLICT (bucket_minutes, bucket_start, api_key_id) DO UPDATE SET
			raw_rapid_ip_count = GREATEST(key_ip_audit_key_rollups.raw_rapid_ip_count,
			                              EXCLUDED.raw_rapid_ip_count)`, pq.Array(keys), from, to)
	return err
}

func refreshKeyIPAuditState(ctx context.Context, tx *sql.Tx, keys []int64) error {
	if len(keys) == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO key_ip_audit_key_state (api_key_id, first_seen, last_seen, latest_ip, request_count, updated_at)
		WITH stats AS (
			SELECT api_key_id, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen,
			       SUM(request_count)::bigint AS request_count
			FROM security_activity_1m
			WHERE api_key_id = ANY($1::bigint[])
			GROUP BY api_key_id
		), latest AS (
			SELECT DISTINCT ON (api_key_id) api_key_id, client_ip
			FROM security_activity_1m
			WHERE api_key_id = ANY($1::bigint[]) AND client_ip <> ''
			ORDER BY api_key_id, last_seen DESC, bucket_start DESC
		)
		SELECT s.api_key_id, s.first_seen, s.last_seen, l.client_ip, s.request_count, NOW()
		FROM stats s LEFT JOIN latest l ON l.api_key_id = s.api_key_id
		ON CONFLICT (api_key_id) DO UPDATE SET
			first_seen = LEAST(key_ip_audit_key_state.first_seen, EXCLUDED.first_seen),
			last_seen = GREATEST(key_ip_audit_key_state.last_seen, EXCLUDED.last_seen),
			latest_ip = EXCLUDED.latest_ip, request_count = EXCLUDED.request_count,
			updated_at = NOW()`, pq.Array(keys)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		WITH grouped AS (
			SELECT api_key_id, client_ip, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen,
			       SUM(request_count) AS request_count,
			       COUNT(DISTINCT NULLIF(user_agent, '')) AS user_agent_count,
			       COALESCE(MIN(NULLIF(user_agent, '')), '') AS user_agent
			FROM security_activity_1m
			WHERE api_key_id = ANY($1::bigint[]) AND client_ip <> ''
			GROUP BY api_key_id, client_ip
		), state_candidates AS (
			SELECT api_key_id, client_ip, first_seen
			FROM key_ip_audit_ip_state
			WHERE api_key_id = ANY($1::bigint[])
			UNION ALL
			SELECT api_key_id, client_ip, first_seen FROM grouped
		), baselines AS (
			SELECT DISTINCT ON (api_key_id) api_key_id, client_ip
			FROM state_candidates
			ORDER BY api_key_id, first_seen, client_ip
		)
		UPDATE key_ip_audit_ip_state s
		SET is_baseline = (s.client_ip = b.client_ip), updated_at = NOW()
		FROM baselines b
		WHERE s.api_key_id = b.api_key_id`, pq.Array(keys)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO key_ip_audit_ip_state (
			api_key_id, client_ip, first_seen, last_seen, request_count,
			user_agent_count, user_agent, is_baseline, updated_at
		)
		WITH grouped AS (
			SELECT api_key_id, client_ip, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen,
			       SUM(request_count) AS request_count,
			       COUNT(DISTINCT NULLIF(user_agent, '')) AS user_agent_count,
			       COALESCE(MIN(NULLIF(user_agent, '')), '') AS user_agent
			FROM security_activity_1m
			WHERE api_key_id = ANY($1::bigint[]) AND client_ip <> ''
			GROUP BY api_key_id, client_ip
		), state_candidates AS (
			SELECT api_key_id, client_ip, first_seen
			FROM key_ip_audit_ip_state
			WHERE api_key_id = ANY($1::bigint[])
			UNION ALL
			SELECT api_key_id, client_ip, first_seen FROM grouped
		), baselines AS (
			SELECT DISTINCT ON (api_key_id) api_key_id, client_ip
			FROM state_candidates
			ORDER BY api_key_id, first_seen, client_ip
		)
		SELECT g.api_key_id, g.client_ip, g.first_seen, g.last_seen, g.request_count,
		       g.user_agent_count, g.user_agent, (g.client_ip = b.client_ip),
		       NOW()
		FROM grouped g JOIN baselines b ON b.api_key_id = g.api_key_id
		ON CONFLICT (api_key_id, client_ip) DO UPDATE SET
			first_seen = LEAST(key_ip_audit_ip_state.first_seen, EXCLUDED.first_seen),
			last_seen = GREATEST(key_ip_audit_ip_state.last_seen, EXCLUDED.last_seen),
			request_count = EXCLUDED.request_count, user_agent_count = EXCLUDED.user_agent_count,
			user_agent = EXCLUDED.user_agent, is_baseline = EXCLUDED.is_baseline, updated_at = NOW()`, pq.Array(keys)); err != nil {
		return err
	}
	return nil
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
