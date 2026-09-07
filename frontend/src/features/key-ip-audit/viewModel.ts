import type {
  KeyAuditDetailQuery,
  KeyAuditFilters,
  KeyAuditListQuery,
  KeyAuditSignal,
  KeyAuditTimeRange,
  KeyId
} from './types'

export const DEFAULT_KEY_AUDIT_PAGE_SIZE = 20
export const DEFAULT_KEY_AUDIT_IP_PAGE_SIZE = 10
export const DEFAULT_KEY_AUDIT_RELATED_PAGE_SIZE = 10
export const DEFAULT_KEY_AUDIT_TRUSTED_PAGE_SIZE = 10
export const KEY_AUDIT_MAX_RANGE_MS = 30 * 24 * 60 * 60 * 1000

export interface KeyAuditWindow {
  from: string
  to: string
}

export type KeyAuditRangeError = 'required' | 'invalid' | 'future' | 'too_long'

export function createDefaultKeyAuditFilters(): KeyAuditFilters {
  return {
    time_range: '24h',
    from: '',
    to: '',
    user: '',
    key: '',
    ip: '',
    risk: '',
    status: '',
    signal: ''
  }
}

export function validateCustomKeyAuditRange(
  filters: Pick<KeyAuditFilters, 'time_range' | 'from' | 'to'>,
  now = new Date()
): KeyAuditRangeError | null {
  if (filters.time_range !== 'custom') return null
  if (!filters.from || !filters.to) return 'required'

  const from = new Date(filters.from)
  const to = new Date(filters.to)
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime()) || from >= to) return 'invalid'
  if (to.getTime() > now.getTime()) return 'future'
  if (to.getTime() - from.getTime() > KEY_AUDIT_MAX_RANGE_MS) return 'too_long'
  return null
}

export function resolveKeyAuditWindow(
  filters: Pick<KeyAuditFilters, 'time_range' | 'from' | 'to'>,
  now = new Date()
): KeyAuditWindow {
  const rangeError = validateCustomKeyAuditRange(filters, now)
  if (rangeError) throw new Error(`KEY_AUDIT_RANGE_${rangeError.toUpperCase()}`)

  const toDate = filters.time_range === 'custom' ? new Date(filters.to) : now
  const duration = durationForRange(filters.time_range)
  const fromDate = filters.time_range === 'custom'
    ? new Date(filters.from)
    : new Date(toDate.getTime() - duration)

  return {
    from: fromDate.toISOString(),
    to: toDate.toISOString()
  }
}

export function buildKeyAuditQuery(
  filters: KeyAuditFilters,
  page: number,
  pageSize: number,
  now = new Date()
): KeyAuditListQuery {
  const window = resolveKeyAuditWindow(filters, now)
  const query: KeyAuditListQuery = {
    ...window,
    page,
    page_size: pageSize
  }

  const key = filters.key.trim()
  const user = filters.user.trim()
  const keyId = parsePositiveInteger(key)
  const userId = parsePositiveInteger(user)

  if (keyId != null) query.key_id = keyId
  else if (key) query.key = key

  if (userId != null) query.user_id = userId
  else if (user) query.user = user

  if (filters.ip.trim()) query.ip = filters.ip.trim()
  if (filters.risk) query.risk = filters.risk
  if (filters.status.trim()) query.status = filters.status.trim()
  if (filters.signal) query.signal = filters.signal

  return query
}

export function buildKeyAuditDetailQuery(
  window: KeyAuditWindow,
  ipPage: number,
  ipPageSize: number,
  relatedPage: number,
  relatedPageSize: number,
  relatedIp?: string
): KeyAuditDetailQuery {
  return {
    ...window,
    ip_page: ipPage,
    ip_page_size: ipPageSize,
    related_ip: relatedIp || undefined,
    related_page: relatedPage,
    related_page_size: relatedPageSize
  }
}

export function parsePositiveInteger(value: string): KeyId | null {
  if (!/^\d+$/.test(value)) return null
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null
}

export function isKeyAuditSignal(value: string): value is KeyAuditSignal {
  return ['new_ip', 'multi_ip_burst', 'shared_ip_cross_users', 'volume_spike'].includes(value)
}

export function isKeyAuditTimeRange(value: string): value is KeyAuditTimeRange {
  return ['24h', '7d', '30d', 'custom'].includes(value)
}

export function isAbortError(error: unknown): boolean {
  const candidate = error as { name?: string; code?: string } | null
  return candidate?.name === 'AbortError' || candidate?.code === 'ERR_CANCELED'
}

export function formatUnknown(value: string | null | undefined, fallback = '—'): string {
  const normalized = String(value ?? '').trim()
  return normalized || fallback
}

function durationForRange(range: KeyAuditTimeRange): number {
  if (range === '7d') return 7 * 24 * 60 * 60 * 1000
  if (range === '30d') return KEY_AUDIT_MAX_RANGE_MS
  return 24 * 60 * 60 * 1000
}
