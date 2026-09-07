export type KeyId = number

export type KeyRiskLevel = 'none' | 'low' | 'medium' | 'high'

export type KeyAuditDisposition = 'open' | 'dismissed' | 'normal'

export type KeyAuditTimeRange = '24h' | '7d' | '30d' | 'custom'

export type KeyAuditSignal =
  | 'new_ip'
  | 'multi_ip_burst'
  | 'shared_ip_cross_users'
  | 'volume_spike'

/** The backend's actual API-key status is intentionally open-ended. */
export type KeyStatus = string

export interface KeyAuditKeyRow {
  key_id: KeyId
  key_name: string
  key_prefix: string
  key_status: KeyStatus
  user_id: number
  user_email: string
  latest_ip: string | null
  ip_count: number
  new_ip_count: number
  first_seen: string
  last_seen: string
  request_count: number
  prior_request_count: number
  request_count_change_pct: number | null
  risk_level: KeyRiskLevel
  risk_reasons: string[]
  risk_evidence: Record<string, unknown>
  status: KeyAuditDisposition
}

export interface KeyAuditSummary {
  total_keys: number
  high_risk_keys: number
  new_ip_keys: number
  multi_ip_keys: number
  shared_ips: number
  pending_keys: number
}

export interface KeyAuditTrendPoint {
  bucket_start: string
  request_count: number
  risky_keys: number
}

export interface KeyAuditCoverage {
  source: 'usage_logs' | string
  usage_log_count: number
  missing_ip_count: number
  missing_user_agent_count: number
  ip_coverage_percent: number
}

export interface KeyAuditMetadata {
  from: string
  to: string
  coverage: KeyAuditCoverage
}

export interface KeyAuditListResponse {
  items: KeyAuditKeyRow[]
  total: number
  page: number
  page_size: number
  summary: KeyAuditSummary
  trend: KeyAuditTrendPoint[]
  metadata: KeyAuditMetadata
}

export interface KeyAuditIpRecord {
  ip: string
  first_seen: string
  last_seen: string
  request_count: number
  user_agent: string
  user_agent_count: number
  new_ip: boolean
  trusted: boolean
  geo: null
  asn: null
}

export interface KeyAuditTrustedRule {
  id: KeyId
  key_id: KeyId
  cidr: string
  note?: string | null
  expires_at?: string | null
  created_at: string
}

export interface KeyAuditDetailResponse {
  key: KeyAuditKeyRow
  ips: KeyAuditIpRecord[]
  ips_total: number
  ips_page: number
  ips_page_size: number
  related_keys: KeyAuditKeyRow[]
  related_total: number
  related_page: number
  related_page_size: number
  related_ip: string
  trusted_rules: KeyAuditTrustedRule[]
  trusted_total: number
  trend: KeyAuditTrendPoint[]
  metadata: KeyAuditMetadata
}

export interface KeyAuditTrustedListResponse {
  items: KeyAuditTrustedRule[]
  total: number
}

export interface KeyAuditDisableResponse {
  key_id: KeyId
  key_status: KeyStatus
}

export interface KeyAuditRotateResponse {
  key_id: KeyId
  secret: string
}

export interface KeyAuditDismissalInput {
  key_id: KeyId
  ip: string
  risk_code: string
  event_start: string
  event_end: string
  note?: string
}

export interface KeyAuditDismissalResponse extends KeyAuditDismissalInput {
  id: KeyId
}

export interface KeyAuditFilters {
  time_range: KeyAuditTimeRange
  from: string
  to: string
  user: string
  key: string
  ip: string
  risk: '' | KeyRiskLevel
  status: string
  signal: '' | KeyAuditSignal
}

export interface KeyAuditListQuery {
  from: string
  to: string
  key_id?: KeyId
  user_id?: KeyId
  key?: string
  user?: string
  ip?: string
  risk?: KeyRiskLevel
  status?: string
  signal?: KeyAuditSignal
  page: number
  page_size: number
}

export interface KeyAuditDetailQuery {
  from: string
  to: string
  ip_page: number
  ip_page_size: number
  related_ip?: string
  related_page: number
  related_page_size: number
}

export interface KeyAuditTrustedInput {
  key_id: KeyId
  cidr: string
  note?: string
  expires_at?: string
}

export interface KeyAuditTrustedListQuery {
  key_id: KeyId
  page: number
  page_size: number
}
