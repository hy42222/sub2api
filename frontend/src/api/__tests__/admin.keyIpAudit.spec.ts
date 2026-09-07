import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const { post, delete: deleteRequest } = vi.hoisted(() => ({
  post: vi.fn(),
  delete: vi.fn()
}))

vi.mock('@/api/client', () => ({
  apiClient: { post, delete: deleteRequest }
}))

import {
  addTrusted,
  createDismissal,
  disable,
  rotate
} from '@/api/admin/keyIpAudit'

describe('admin key/IP audit rotate API', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    localStorage.setItem('auth_user', JSON.stringify({ id: 42 }))
    post.mockReset()
    deleteRequest.mockReset()
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('11111111-1111-4111-8111-111111111111')
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('reuses the same idempotency header after a network failure', async () => {
    post.mockRejectedValueOnce(new Error('network timeout'))

    await expect(rotate(7)).rejects.toThrow('network timeout')
    const firstHeaders = post.mock.calls[0][2].headers

    post.mockResolvedValueOnce({ data: { key_id: 7, secret: 'sk-new' } })
    await rotate(7)

    expect(post).toHaveBeenNthCalledWith(2, '/admin/key-ip-audit/keys/7/rotate', {}, {
      headers: firstHeaders,
      signal: undefined
    })
    expect(firstHeaders).toEqual({
      'Idempotency-Key': 'key-ip-audit-rotate:7-11111111-1111-4111-8111-111111111111'
    })
    expect(sessionStorage.length).toBe(0)
  })

  it('keeps the operation key when the user cancels locally', async () => {
    post.mockRejectedValueOnce({ code: 'ERR_CANCELED', name: 'CanceledError' })

    await expect(rotate(8, { signal: new AbortController().signal })).rejects.toMatchObject({ code: 'ERR_CANCELED' })
    expect(sessionStorage.getItem('sub2api:key-ip-audit:42:rotate%3A8')).toContain('key-ip-audit-rotate:8-')
  })

  it('clears the operation key after a definite validation failure', async () => {
    post.mockRejectedValueOnce({ status: 422, message: 'invalid key' })

    await expect(rotate(9)).rejects.toMatchObject({ status: 422 })
    expect(sessionStorage.getItem('sub2api:key-ip-audit:42:rotate%3A9')).toBeNull()
  })

  it('sends an idempotency header for disable', async () => {
    post.mockResolvedValueOnce({ data: { key_id: 10, key_status: 'inactive' } })

    await disable(10)

    expect(post).toHaveBeenCalledWith('/admin/key-ip-audit/keys/10/disable', {}, {
      headers: {
        'Idempotency-Key': 'key-ip-audit-disable:10-11111111-1111-4111-8111-111111111111'
      },
      signal: undefined
    })
  })

  it('sends an idempotency header for trusted network creation', async () => {
    post.mockResolvedValueOnce({ data: {
      id: 11,
      key_id: 7,
      cidr: '203.0.113.0/24',
      note: 'office',
      created_at: '2026-09-07T00:00:00Z'
    } })

    await addTrusted({ key_id: 7, cidr: '203.0.113.0/24', note: 'office' })

    expect(post).toHaveBeenCalledWith('/admin/key-ip-audit/trusted', {
      key_id: 7,
      cidr: '203.0.113.0/24',
      note: 'office'
    }, {
      headers: {
        'Idempotency-Key': 'key-ip-audit-trusted-add:7:203.0.113.0/24:office:-11111111-1111-4111-8111-111111111111'
      },
      signal: undefined
    })
  })

  it('sends an idempotency header for dismissal creation', async () => {
    post.mockResolvedValueOnce({ data: {
      id: 12,
      key_id: 7,
      ip: '203.0.113.10',
      risk_code: 'new_ip',
      event_start: '2026-09-06T00:00:00Z',
      event_end: '2026-09-07T00:00:00Z'
    } })

    await createDismissal({
      key_id: 7,
      ip: '203.0.113.10',
      risk_code: 'new_ip',
      event_start: '2026-09-06T00:00:00Z',
      event_end: '2026-09-07T00:00:00Z'
    })

    expect(post).toHaveBeenCalledWith('/admin/key-ip-audit/dismissals', {
      key_id: 7,
      ip: '203.0.113.10',
      risk_code: 'new_ip',
      event_start: '2026-09-06T00:00:00Z',
      event_end: '2026-09-07T00:00:00Z'
    }, {
      headers: {
        'Idempotency-Key': 'key-ip-audit-dismissal-create:7:203.0.113.10:new_ip:2026-09-06T00:00:00Z:2026-09-07T00:00:00Z-11111111-1111-4111-8111-111111111111'
      },
      signal: undefined
    })
  })
})
