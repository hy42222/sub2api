import { describe, expect, it } from 'vitest'
import { getUsageTps } from '../usageTps'

describe('getUsageTps', () => {
  it('uses output tokens and the full request duration', () => {
    const row = { output_tokens: 120, duration_ms: 6000, first_token_ms: 2000, input_tokens: 8000 }
    expect(getUsageTps(row)).toBe(20)
  })

  it('keeps fractional TPS for sub-second and slow requests', () => {
    expect(getUsageTps({ output_tokens: 7, duration_ms: 250 })).toBe(28)
    expect(getUsageTps({ output_tokens: 1, duration_ms: 6000 })).toBeCloseTo(1 / 6)
  })

  it.each([null, undefined, 0, -1, NaN, Infinity, -Infinity])(
    'returns null for invalid duration %s',
    (durationMs) => {
      expect(getUsageTps({ output_tokens: 120, duration_ms: durationMs as number | null })).toBeNull()
    },
  )

  it.each([0, -1, NaN, Infinity, -Infinity])('returns null for invalid output tokens %s', (outputTokens) => {
    expect(getUsageTps({ output_tokens: outputTokens, duration_ms: 6000 })).toBeNull()
  })

  it.each([
    { billing_mode: 'image' },
    { billing_mode: 'video' },
    { image_count: 1 },
    { image_count: 1, billing_mode: 'token' },
    { image_output_tokens: 120, billing_mode: 'token' },
  ])('does not treat media generation as text TPS: %o', (media) => {
    expect(getUsageTps({ output_tokens: 120, duration_ms: 6000, ...media })).toBeNull()
  })

  it('supports historical billing modes and text requests billed per request', () => {
    expect(getUsageTps({ output_tokens: 120, duration_ms: 6000, billing_mode: null })).toBe(20)
    expect(getUsageTps({ output_tokens: 120, duration_ms: 6000, billing_mode: 'per_request' })).toBe(20)
  })
})
