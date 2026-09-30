import { describe, expect, it } from 'vitest'
import type { KeyAuditMetadata } from '../types'
import { keyAuditCoverageNotice } from '../viewModel'

function metadata(overrides: Partial<KeyAuditMetadata['coverage']> = {}): KeyAuditMetadata {
  return {
    from: '2026-09-01T00:00:00Z',
    to: '2026-09-02T00:00:00Z',
    coverage: {
      source: 'security_activity_projection',
      reason: 'complete',
      usage_log_count: 1,
      missing_ip_count: 0,
      missing_user_agent_count: 0,
      ip_coverage_percent: 100,
      live_since: '2026-08-01T00:00:00Z',
      data_through: '2026-09-02T00:00:00Z',
      aggregation_lag_seconds: 0,
      coverage_complete: true,
      risk_context_complete: true,
      ...overrides
    }
  }
}

describe('keyAuditCoverageNotice', () => {
  it('distinguishes unavailable history from projection lag', () => {
    expect(keyAuditCoverageNotice(metadata({ coverage_complete: false, reason: 'history_unavailable' })))
      .toBe('historyUncovered')
    expect(keyAuditCoverageNotice(metadata({ coverage_complete: false, reason: 'projection_pending' })))
      .toBe('pendingCoverage')
  })

  it('reports limited risk context only after activity coverage is complete', () => {
    expect(keyAuditCoverageNotice(metadata({ risk_context_complete: false })))
      .toBe('riskContextIncomplete')
    expect(keyAuditCoverageNotice(metadata())).toBeNull()
  })
})
