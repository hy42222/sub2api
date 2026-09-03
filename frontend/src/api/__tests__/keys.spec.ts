import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const { post } = vi.hoisted(() => ({
  post: vi.fn()
}))

vi.mock('@/api/client', () => ({
  apiClient: { post }
}))

import { regenerate } from '@/api/keys'

describe('API key regenerate API', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    localStorage.setItem('auth_user', JSON.stringify({ id: 42 }))
    post.mockReset()
    post.mockResolvedValue({ data: { id: 7, key: 'sk-new-credential' } })
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('11111111-1111-4111-8111-111111111111')
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('sends a stable idempotency key and returns the regenerated key', async () => {
    const key = await regenerate(7)

    expect(post).toHaveBeenCalledWith('/keys/7/regenerate', undefined, {
      headers: {
        'Idempotency-Key': 'api-key-regenerate-7-11111111-1111-4111-8111-111111111111'
      }
    })
    expect(key).toEqual({ id: 7, key: 'sk-new-credential' })
    expect(sessionStorage.length).toBe(0)
  })

  it('reuses the operation key after an ambiguous failure', async () => {
    post.mockRejectedValueOnce(new Error('network timeout'))
    await expect(regenerate(7)).rejects.toThrow('network timeout')

    post.mockResolvedValueOnce({ data: { id: 7, key: 'sk-new-credential' } })
    await regenerate(7)

    expect(post).toHaveBeenCalledTimes(2)
    expect(post.mock.calls[1][2].headers).toEqual(post.mock.calls[0][2].headers)
    expect(sessionStorage.length).toBe(0)
  })
})
