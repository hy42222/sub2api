import type { UsageLog } from '@/types'
import { BILLING_MODE_IMAGE, BILLING_MODE_VIDEO } from '@/utils/billingMode'

type UsageTpsRow = Pick<UsageLog, 'output_tokens' | 'duration_ms'> & Partial<
  Pick<UsageLog, 'image_count' | 'image_output_tokens' | 'billing_mode'>
>

/** Average output tokens per second over the full request, including first-token wait. */
export function getUsageTps(row: UsageTpsRow): number | null {
  const durationMs = row.duration_ms
  const outputTokens = row.output_tokens
  if (durationMs == null || !Number.isFinite(durationMs) || durationMs <= 0
    || !Number.isFinite(outputTokens) || outputTokens <= 0) {
    return null
  }
  if ((row.image_count ?? 0) > 0 || (row.image_output_tokens ?? 0) > 0
    || row.billing_mode === BILLING_MODE_IMAGE || row.billing_mode === BILLING_MODE_VIDEO) {
    return null
  }
  const tps = outputTokens / durationMs * 1000
  return Number.isFinite(tps) ? tps : null
}
