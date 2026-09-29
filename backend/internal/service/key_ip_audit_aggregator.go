package service

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/google/uuid"
)

const (
	keyIPAuditAggregationInterval      = 30 * time.Second
	keyIPAuditAggregationTimeout       = 20 * time.Second
	keyIPAuditAggregationBatchSize     = 1000
	keyIPAuditProjectionPruneBatchSize = 5000
	keyIPAuditAggregationMaxBatches    = 10
	keyIPAuditAggregationLockKey       = "security:key_ip_audit_projection:leader"
	keyIPAuditAggregationLockTTL       = 2 * time.Minute
)

// KeyIPAuditProjectionState describes the future-only coverage boundary exposed
// by the audit read model. LiveSince is intentionally not the deployment's
// historical usage-log boundary: the migration initializes it when the feature
// is enabled.
type KeyIPAuditProjectionState struct {
	LiveSince           time.Time
	ProcessedUsageLogID int64
	ProcessedCreatedAt  time.Time
	DataThrough         time.Time
	LastSuccessfulAt    time.Time
}

type KeyIPAuditAggregationResult struct {
	Processed   int
	DataThrough time.Time
}

// KeyIPAuditAggregationRepository is the durable projection boundary. Keeping
// this separate from KeyIPAuditRepository lets the API remain read-only over
// materialized state and leaves the normalized activity fact reusable by later
// security analyses.
type KeyIPAuditAggregationRepository interface {
	ProcessKeyIPAuditBatch(ctx context.Context, batchSize int) (KeyIPAuditAggregationResult, error)
	GetKeyIPAuditProjectionState(ctx context.Context) (*KeyIPAuditProjectionState, error)
	PruneKeyIPAuditProjection(ctx context.Context, batchSize int) error
}

type KeyIPAuditAggregator struct {
	repo       KeyIPAuditAggregationRepository
	db         *sql.DB
	lockCache  LeaderLockCache
	instanceID string
	stopCh     chan struct{}
	startOnce  sync.Once
	stopOnce   sync.Once
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	started    bool
	stopped    bool
	loopDone   chan struct{}
	activeRuns sync.WaitGroup
}

func NewKeyIPAuditAggregator(repo KeyIPAuditAggregationRepository, db *sql.DB, lockCache LeaderLockCache) *KeyIPAuditAggregator {
	return &KeyIPAuditAggregator{
		repo:       repo,
		db:         db,
		lockCache:  lockCache,
		instanceID: uuid.NewString(),
		stopCh:     make(chan struct{}),
		loopDone:   make(chan struct{}),
	}
}

func (a *KeyIPAuditAggregator) Start() {
	if a == nil || a.repo == nil {
		return
	}
	a.startOnce.Do(func() {
		a.mu.Lock()
		if a.stopped {
			a.mu.Unlock()
			return
		}
		a.ctx, a.cancel = context.WithCancel(context.Background())
		a.started = true
		loopDone := a.loopDone
		a.mu.Unlock()
		go func() {
			defer close(loopDone)
			a.loop()
		}()
	})
}

func (a *KeyIPAuditAggregator) Stop() {
	if a == nil {
		return
	}
	a.stopOnce.Do(func() {
		a.mu.Lock()
		a.stopped = true
		cancel := a.cancel
		a.cancel = nil
		started := a.started
		loopDone := a.loopDone
		a.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		close(a.stopCh)
		if started {
			<-loopDone
		}
	})
	a.activeRuns.Wait()
}

// RunOnce is exported for bounded integration tests and operational probes.
// Each batch commits its source ledger, facts, derived rollups, state and
// watermark together, so a crash can only cause a safe replay.
func (a *KeyIPAuditAggregator) RunOnce(ctx context.Context) error {
	if a == nil || a.repo == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return nil
	}
	a.activeRuns.Add(1)
	parent := a.ctx
	a.mu.Unlock()
	defer a.activeRuns.Done()
	if parent == nil {
		parent = ctx
	}
	runCtx, cancel := context.WithTimeout(parent, keyIPAuditAggregationTimeout)
	defer cancel()
	release, acquired, err := tryAcquireSingletonLeaderLockFailClosed(runCtx, a.lockCache, a.db, keyIPAuditAggregationLockKey, a.instanceID, keyIPAuditAggregationLockTTL)
	if err != nil {
		return fmt.Errorf("acquire key/ip audit aggregation leader lock: %w", err)
	}
	if !acquired {
		return nil
	}
	if release != nil {
		defer release()
	}

	for i := 0; i < keyIPAuditAggregationMaxBatches; i++ {
		result, err := a.repo.ProcessKeyIPAuditBatch(runCtx, keyIPAuditAggregationBatchSize)
		if err != nil {
			return err
		}
		if result.Processed == 0 {
			break
		}
	}
	return a.repo.PruneKeyIPAuditProjection(runCtx, keyIPAuditProjectionPruneBatchSize)
}

func (a *KeyIPAuditAggregator) loop() {
	// Process the first post-migration batch immediately, then keep the cache
	// bounded in freshness without putting projection work on request goroutines.
	if err := a.RunOnce(context.Background()); err != nil {
		logger.LegacyPrintf("service.key_ip_audit_aggregator", "initial projection failed: %v", err)
	}
	ticker := time.NewTicker(keyIPAuditAggregationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := a.RunOnce(context.Background()); err != nil {
				logger.LegacyPrintf("service.key_ip_audit_aggregator", "projection failed: %v", err)
			}
		case <-a.stopCh:
			return
		}
	}
}

// ProvideKeyIPAuditAggregator starts the shared normalized security projection.
func ProvideKeyIPAuditAggregator(repo KeyIPAuditAggregationRepository, db *sql.DB, lockCache LeaderLockCache) *KeyIPAuditAggregator {
	aggregator := NewKeyIPAuditAggregator(repo, db, lockCache)
	aggregator.Start()
	return aggregator
}
