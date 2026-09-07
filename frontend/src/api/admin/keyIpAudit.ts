import { apiClient } from '../client'
import type {
  KeyAuditDetailResponse,
  KeyAuditDisableResponse,
  KeyAuditDismissalInput,
  KeyAuditDismissalResponse,
  KeyAuditListQuery,
  KeyAuditListResponse,
  KeyAuditRotateResponse,
  KeyAuditTrustedInput,
  KeyAuditTrustedListQuery,
  KeyAuditTrustedListResponse,
  KeyAuditTrustedRule,
  KeyId
} from '@/features/key-ip-audit/types'
import type { KeyAuditDetailQuery } from '@/features/key-ip-audit/types'

const API_PREFIX = '/admin/key-ip-audit'
const operationKeys = new Map<string, string>()

export interface KeyAuditRequestOptions {
  signal?: AbortSignal
}

export async function list(
  params: KeyAuditListQuery,
  options?: KeyAuditRequestOptions
): Promise<KeyAuditListResponse> {
  const { data } = await apiClient.get<KeyAuditListResponse>(`${API_PREFIX}/keys`, {
    params,
    signal: options?.signal
  })
  return data
}

export async function detail(
  keyId: KeyId,
  params: KeyAuditDetailQuery,
  options?: KeyAuditRequestOptions
): Promise<KeyAuditDetailResponse> {
  const { data } = await apiClient.get<KeyAuditDetailResponse>(`${API_PREFIX}/keys/${keyId}`, {
    params,
    signal: options?.signal
  })
  return data
}

export async function disable(
  keyId: KeyId,
  options?: KeyAuditRequestOptions
): Promise<KeyAuditDisableResponse> {
  return runIdempotent(`disable:${keyId}`, operationKey => apiClient.post<KeyAuditDisableResponse>(
    `${API_PREFIX}/keys/${keyId}/disable`,
    {},
    {
      headers: { 'Idempotency-Key': operationKey },
      signal: options?.signal
    }
  ))
}

export async function rotate(
  keyId: KeyId,
  options?: KeyAuditRequestOptions
): Promise<KeyAuditRotateResponse> {
  return runIdempotent(`rotate:${keyId}`, operationKey => apiClient.post<KeyAuditRotateResponse>(
      `${API_PREFIX}/keys/${keyId}/rotate`,
      {},
      {
        headers: { 'Idempotency-Key': operationKey },
        signal: options?.signal
      }
    ))
}

export async function listTrusted(
  params: KeyAuditTrustedListQuery,
  options?: KeyAuditRequestOptions
): Promise<KeyAuditTrustedListResponse> {
  const { data } = await apiClient.get<KeyAuditTrustedListResponse>(`${API_PREFIX}/trusted`, {
    params,
    signal: options?.signal
  })
  return data
}

export async function addTrusted(
  input: KeyAuditTrustedInput,
  options?: KeyAuditRequestOptions
): Promise<KeyAuditTrustedRule> {
  const body: KeyAuditTrustedInput = {
    key_id: input.key_id,
    cidr: input.cidr
  }
  if (input.note) body.note = input.note
  if (input.expires_at) body.expires_at = input.expires_at

  return runIdempotent(
    `trusted-add:${input.key_id}:${input.cidr}:${input.note ?? ''}:${input.expires_at ?? ''}`,
    operationKey => apiClient.post<KeyAuditTrustedRule>(`${API_PREFIX}/trusted`, body, {
      headers: { 'Idempotency-Key': operationKey },
      signal: options?.signal
    })
  )
}

export async function removeTrusted(
  ruleId: KeyId,
  options?: KeyAuditRequestOptions
): Promise<void> {
  await runIdempotent(`trusted-delete:${ruleId}`, operationKey => apiClient.delete(`${API_PREFIX}/trusted/${ruleId}`, {
    headers: { 'Idempotency-Key': operationKey },
    signal: options?.signal
  }))
}

export async function createDismissal(
  input: KeyAuditDismissalInput,
  options?: KeyAuditRequestOptions
): Promise<KeyAuditDismissalResponse> {
  return runIdempotent(
    `dismissal-create:${input.key_id}:${input.ip}:${input.risk_code}:${input.event_start}:${input.event_end}`,
    operationKey => apiClient.post<KeyAuditDismissalResponse>(`${API_PREFIX}/dismissals`, input, {
      headers: { 'Idempotency-Key': operationKey },
      signal: options?.signal
    })
  )
}

export async function removeDismissal(
  dismissalId: KeyId,
  options?: KeyAuditRequestOptions
): Promise<void> {
  await runIdempotent(`dismissal-delete:${dismissalId}`, operationKey => apiClient.delete(`${API_PREFIX}/dismissals/${dismissalId}`, {
    headers: { 'Idempotency-Key': operationKey },
    signal: options?.signal
  }))
}

function getCurrentAdminId(): string | null {
  try {
    const raw = globalThis.localStorage?.getItem('auth_user')
    if (!raw) return null
    const user = JSON.parse(raw) as { id?: unknown }
    return typeof user.id === 'number' && Number.isSafeInteger(user.id) && user.id > 0
      ? String(user.id)
      : null
  } catch {
    return null
  }
}

function operationStorageKey(slot: string): string | null {
  const adminId = getCurrentAdminId()
  return adminId ? `sub2api:key-ip-audit:${adminId}:${encodeURIComponent(slot)}` : null
}

function getStoredOperationKey(storageKey: string): string | null {
  try {
    return globalThis.sessionStorage?.getItem(storageKey) ?? null
  } catch {
    return null
  }
}

function storeOperationKey(storageKey: string, value: string | null): void {
  try {
    if (value) globalThis.sessionStorage?.setItem(storageKey, value)
    else globalThis.sessionStorage?.removeItem(storageKey)
  } catch {
    // The in-memory map still protects retries when browser storage is unavailable.
  }
}

async function runIdempotent<T>(
  slot: string,
  request: (operationKey: string) => Promise<{ data: T }>
): Promise<T> {
  const storageKey = operationStorageKey(slot)
  let operationKey = operationKeys.get(slot)
    ?? (storageKey ? getStoredOperationKey(storageKey) : null)

  if (!operationKey) {
    const requestId = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`
    operationKey = `key-ip-audit-${slot}-${requestId}`
  }

  operationKeys.set(slot, operationKey)
  if (storageKey) storeOperationKey(storageKey, operationKey)

  try {
    const { data } = await request(operationKey)
    clearOperationKey(slot, storageKey)
    return data
  } catch (error: unknown) {
    // A local cancellation does not prove that the server did not receive the
    // request. Keep the key so a retry can safely replay the same operation.
    if (isDefinitelyNotExecutedError(error)) clearOperationKey(slot, storageKey)
    throw error
  }
}

function clearOperationKey(slot: string, storageKey: string | null): void {
  operationKeys.delete(slot)
  if (storageKey) storeOperationKey(storageKey, null)
}

function isDefinitelyNotExecutedError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false
  const candidate = error as { name?: string; code?: string; status?: number }
  if (candidate.name === 'AbortError' || candidate.code === 'ERR_CANCELED') return false

  // 5xx, timeouts, transport failures, conflicts, and throttling are all
  // ambiguous for a mutating request. Only validation/auth/routing responses
  // that arrive before execution may discard the replay key.
  return candidate.status != null && [400, 401, 403, 404, 405, 415, 422].includes(candidate.status)
}

export const keyIpAuditAPI = {
  list,
  detail,
  disable,
  rotate,
  listTrusted,
  addTrusted,
  removeTrusted,
  createDismissal,
  removeDismissal
}

export default keyIpAuditAPI
