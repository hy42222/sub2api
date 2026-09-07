<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="fixed inset-0 z-[45] flex bg-black/40" role="presentation" @click.self="close">
        <aside
          ref="panelRef"
          class="ml-auto flex h-full w-full max-w-4xl flex-col border-l border-gray-200 bg-white outline-none dark:border-dark-700 dark:bg-dark-900"
          role="dialog"
          aria-modal="true"
          :aria-labelledby="titleId"
          tabindex="-1"
          :inert="suspended || undefined"
          @click.stop
        >
          <header class="flex shrink-0 items-start justify-between gap-4 border-b border-gray-200 px-4 py-4 dark:border-dark-700 sm:px-6">
            <div class="min-w-0">
              <p class="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-dark-400">{{ t('admin.keyIpAudit.drawer.title') }}</p>
              <h2 :id="titleId" class="mt-1 truncate text-lg font-semibold text-gray-900 dark:text-white">
                {{ detail?.key.key_name || t('admin.keyIpAudit.drawer.loadingTitle') }}
              </h2>
              <p v-if="detail" class="mt-1 flex flex-wrap gap-x-2 gap-y-1 text-xs text-gray-500 dark:text-dark-400">
                <span class="font-mono">{{ detail.key.key_prefix }}</span>
                <span>#{{ detail.key.key_id }}</span>
                <span>{{ detail.key.user_email }} ({{ detail.key.user_id }})</span>
              </p>
            </div>
            <button type="button" class="icon-btn shrink-0" :title="t('common.close')" :aria-label="t('common.close')" @click="close">
              <Icon name="x" size="md" />
            </button>
          </header>

          <div v-if="loading" class="flex flex-1 items-center justify-center p-8" role="status">
            <div class="flex flex-col items-center gap-3 text-sm text-gray-500 dark:text-dark-400">
              <LoadingSpinner size="lg" />
              <span>{{ t('common.loading') }}</span>
            </div>
          </div>

          <div v-else-if="error" class="flex flex-1 items-center justify-center p-8">
            <div class="max-w-sm text-center">
              <Icon name="exclamationTriangle" size="lg" class="mx-auto mb-3 text-amber-500" />
              <p class="text-sm text-gray-600 dark:text-dark-300">{{ error }}</p>
              <button type="button" class="btn btn-secondary mt-4" @click="$emit('retry')">
                <Icon name="refresh" size="sm" />
                {{ t('common.refresh') }}
              </button>
            </div>
          </div>

          <div v-else-if="detail" class="min-h-0 flex-1 overflow-y-auto">
            <div class="space-y-7 p-4 sm:p-6">
              <section class="flex flex-wrap items-start justify-between gap-3 border-b border-gray-100 pb-5 dark:border-dark-800">
                <div class="flex flex-wrap items-center gap-2">
                  <span :class="riskBadgeClass(detail.key.risk_level)">{{ riskLabel(detail.key.risk_level) }}</span>
                  <span :class="auditStatusBadgeClass(detail.key.status)">{{ auditStatusLabel(detail.key.status) }}</span>
                  <span :class="keyStatusBadgeClass(detail.key.key_status)">{{ detail.key.key_status }}</span>
                </div>
                <div class="flex flex-wrap gap-2">
                  <button v-if="detail.key.key_status === 'active'" type="button" class="btn btn-secondary btn-sm" :disabled="busy" @click="$emit('disable')">
                    <Icon name="ban" size="sm" />
                    {{ t('admin.keyIpAudit.actions.disable') }}
                  </button>
                  <button type="button" class="btn btn-secondary btn-sm" :disabled="busy" @click="$emit('rotate')">
                    <Icon name="swap" size="sm" />
                    {{ t('admin.keyIpAudit.actions.rotate') }}
                  </button>
                </div>
              </section>

              <dl class="grid grid-cols-2 gap-x-5 gap-y-4 sm:grid-cols-4">
                <div>
                  <dt class="audit-label">{{ t('admin.keyIpAudit.columns.ipCount') }}</dt>
                  <dd class="audit-value">{{ formatNumber(detail.key.ip_count) }} <span class="text-xs text-amber-600 dark:text-amber-400">+{{ formatNumber(detail.key.new_ip_count) }}</span></dd>
                </div>
                <div>
                  <dt class="audit-label">{{ t('admin.keyIpAudit.columns.requests') }}</dt>
                  <dd class="audit-value">{{ formatNumber(detail.key.request_count) }}</dd>
                </div>
                <div>
                  <dt class="audit-label">{{ t('admin.keyIpAudit.columns.lastUsed') }}</dt>
                  <dd class="audit-value">{{ formatTime(detail.key.last_seen) }}</dd>
                </div>
                <div>
                  <dt class="audit-label">{{ t('admin.keyIpAudit.columns.requestChange') }}</dt>
                  <dd class="audit-value">{{ formatPercent(detail.key.request_count_change_pct) }}</dd>
                </div>
              </dl>

              <section>
                <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 class="section-title">{{ t('admin.keyIpAudit.drawer.ipHistory') }}</h3>
                    <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.keyIpAudit.drawer.window', { from: formatTime(detail.metadata.from), to: formatTime(detail.metadata.to) }) }}</p>
                  </div>
                  <span class="text-xs text-gray-500 dark:text-dark-400">{{ formatNumber(detail.ips_total) }}</span>
                </div>

                <div v-if="detail.ips.length" class="overflow-x-auto border border-gray-200 dark:border-dark-700">
                  <table class="min-w-[760px] divide-y divide-gray-200 text-left text-sm dark:divide-dark-700">
                    <thead class="bg-gray-50 text-xs text-gray-500 dark:bg-dark-800 dark:text-dark-400">
                      <tr>
                        <th class="px-3 py-2.5 font-medium">{{ t('admin.keyIpAudit.drawer.ip') }}</th>
                        <th class="px-3 py-2.5 font-medium">{{ t('admin.keyIpAudit.drawer.firstSeen') }}</th>
                        <th class="px-3 py-2.5 font-medium">{{ t('admin.keyIpAudit.drawer.lastSeen') }}</th>
                        <th class="px-3 py-2.5 text-right font-medium">{{ t('admin.keyIpAudit.drawer.requests') }}</th>
                        <th class="px-3 py-2.5 font-medium">{{ t('admin.keyIpAudit.drawer.userAgent') }}</th>
                        <th class="px-3 py-2.5 text-right font-medium">{{ t('common.actions') }}</th>
                      </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-100 dark:divide-dark-800">
                      <tr v-for="ipRecord in detail.ips" :key="ipRecord.ip" class="align-top">
                        <td class="px-3 py-3 font-mono text-xs text-gray-900 dark:text-gray-100">
                          <div class="flex flex-wrap items-center gap-2">
                            <span>{{ ipRecord.ip }}</span>
                            <span v-if="ipRecord.new_ip" class="font-sans text-[10px] text-amber-600 dark:text-amber-400">{{ t('admin.keyIpAudit.drawer.newIp') }}</span>
                            <span v-if="ipRecord.trusted" class="font-sans text-[10px] text-emerald-600 dark:text-emerald-400">{{ t('admin.keyIpAudit.drawer.trusted') }}</span>
                          </div>
                          <p class="mt-1 font-sans text-[11px] text-gray-500 dark:text-dark-400">{{ locationLabel(ipRecord) }}</p>
                        </td>
                        <td class="whitespace-nowrap px-3 py-3 text-xs text-gray-600 dark:text-dark-300">{{ formatTime(ipRecord.first_seen) }}</td>
                        <td class="whitespace-nowrap px-3 py-3 text-xs text-gray-600 dark:text-dark-300">{{ formatTime(ipRecord.last_seen) }}</td>
                        <td class="whitespace-nowrap px-3 py-3 text-right text-xs text-gray-700 dark:text-dark-200">{{ formatNumber(ipRecord.request_count) }}</td>
                        <td class="max-w-[240px] px-3 py-3 text-xs text-gray-500 dark:text-dark-400">
                          <span class="block truncate" :title="ipRecord.user_agent">{{ formatUnknown(ipRecord.user_agent) }}</span>
                          <span class="mt-1 block">{{ t('admin.keyIpAudit.drawer.userAgentCount', { count: ipRecord.user_agent_count }) }}</span>
                        </td>
                        <td class="whitespace-nowrap px-3 py-3 text-right">
                          <button type="button" class="icon-btn icon-btn-sm" :title="t('admin.keyIpAudit.actions.lookupIp')" :aria-label="t('admin.keyIpAudit.actions.lookupIp')" @click="$emit('lookup-ip', ipRecord.ip)">
                            <Icon name="search" size="sm" />
                          </button>
                          <button type="button" class="icon-btn icon-btn-sm ml-1" :title="t('admin.keyIpAudit.actions.relatedForIp')" :aria-label="t('admin.keyIpAudit.actions.relatedForIp')" @click="$emit('select-related-ip', ipRecord.ip)">
                            <Icon name="users" size="sm" />
                          </button>
                          <button type="button" class="icon-btn icon-btn-sm ml-1" :title="t('admin.keyIpAudit.actions.openUsage')" :aria-label="t('admin.keyIpAudit.actions.openUsage')" @click="$emit('open-usage', ipRecord.ip)">
                            <Icon name="externalLink" size="sm" />
                          </button>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                <p v-else class="empty-inline">{{ t('admin.keyIpAudit.drawer.noIpHistory') }}</p>
                <Pagination
                  v-if="detail.ips_total > 0"
                  class="mt-3"
                  :total="detail.ips_total"
                  :page="detail.ips_page"
                  :page-size="detail.ips_page_size"
                  @update:page="$emit('ip-page-change', $event)"
                  @update:pageSize="$emit('ip-page-size-change', $event)"
                />
              </section>

              <section>
                <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 class="section-title">{{ t('admin.keyIpAudit.drawer.relatedKeys') }}</h3>
                    <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.keyIpAudit.drawer.relatedFor', { ip: detail.related_ip || t('common.unknown') }) }}</p>
                  </div>
                  <span class="text-xs text-gray-500 dark:text-dark-400">{{ formatNumber(detail.related_total) }}</span>
                </div>
                <ul v-if="detail.related_keys.length" class="divide-y divide-gray-100 border-y border-gray-100 dark:divide-dark-800 dark:border-dark-800">
                  <li v-for="related in detail.related_keys" :key="related.key_id" class="flex flex-wrap items-center justify-between gap-3 py-3">
                    <div class="min-w-0">
                      <button type="button" class="truncate text-left text-sm font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400" @click="$emit('open-related-key', related.key_id)">{{ related.key_name }}</button>
                      <p class="mt-0.5 truncate text-xs text-gray-500 dark:text-dark-400"><span class="font-mono">{{ related.key_prefix }}</span> · {{ related.user_email }} ({{ related.user_id }})</p>
                    </div>
                    <div class="flex items-center gap-2 text-xs">
                      <span :class="keyStatusBadgeClass(related.key_status)">{{ related.key_status }}</span>
                      <span :class="auditStatusBadgeClass(related.status)">{{ auditStatusLabel(related.status) }}</span>
                    </div>
                  </li>
                </ul>
                <p v-else class="empty-inline">{{ t('admin.keyIpAudit.drawer.noRelatedKeys') }}</p>
                <Pagination
                  v-if="detail.related_total > 0"
                  class="mt-3"
                  :total="detail.related_total"
                  :page="detail.related_page"
                  :page-size="detail.related_page_size"
                  @update:page="$emit('related-page-change', $event)"
                  @update:pageSize="$emit('related-page-size-change', $event)"
                />
              </section>

              <section>
                <h3 class="section-title mb-3">{{ t('admin.keyIpAudit.drawer.evidence') }}</h3>
                <div class="border-y border-gray-100 dark:border-dark-800">
                  <div v-if="detail.key.risk_reasons.length" class="divide-y divide-gray-100 dark:divide-dark-800">
                    <div v-for="reason in detail.key.risk_reasons" :key="reason" class="flex flex-wrap items-center justify-between gap-3 py-3">
                      <div class="flex min-w-0 items-start gap-2">
                        <Icon name="exclamationCircle" size="sm" class="mt-0.5 shrink-0" :class="riskTextClass(detail.key.risk_level)" />
                        <span class="break-words text-sm text-gray-800 dark:text-gray-200">{{ reason }}</span>
                      </div>
                      <button type="button" class="btn btn-secondary btn-sm shrink-0" :disabled="busy || !dismissalIp" @click="$emit('dismiss', { ip: dismissalIp, riskCode: reason })">
                        <Icon name="checkCircle" size="sm" />
                        {{ t('admin.keyIpAudit.actions.markFalsePositive') }}
                      </button>
                    </div>
                  </div>
                  <p v-else class="py-4 text-sm text-gray-500 dark:text-dark-400">{{ t('admin.keyIpAudit.drawer.noEvidence') }}</p>
                </div>
                <div v-if="detail.key.risk_reasons.length" class="mt-3 flex flex-col gap-2 sm:flex-row sm:items-center">
                  <label class="text-xs text-gray-600 dark:text-dark-300" :for="dismissalIpId">{{ t('admin.keyIpAudit.drawer.dismissalIp') }}</label>
                  <select :id="dismissalIpId" v-model="dismissalIp" class="input min-w-0 flex-1 font-mono text-xs">
                    <option v-for="ipRecord in detail.ips" :key="ipRecord.ip" :value="ipRecord.ip">{{ ipRecord.ip }}</option>
                  </select>
                </div>
                <p v-if="detail.key.status === 'dismissed'" class="mt-3 text-xs text-emerald-700 dark:text-emerald-300">
                  {{ t('admin.keyIpAudit.drawer.dismissedInWindow') }}
                  <button v-if="dismissalId != null" type="button" class="ml-2 underline" :disabled="busy" @click="$emit('remove-dismissal', dismissalId)">{{ t('admin.keyIpAudit.actions.undoFalsePositive') }}</button>
                </p>
              </section>

              <section>
                <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
                  <h3 class="section-title">{{ t('admin.keyIpAudit.drawer.trustedNetworks') }}</h3>
                  <button type="button" class="btn btn-secondary btn-sm" :disabled="busy" @click="showTrustedForm = !showTrustedForm">
                    <Icon name="plus" size="sm" />
                    {{ t('admin.keyIpAudit.actions.addTrusted') }}
                  </button>
                </div>
                <form v-if="showTrustedForm" class="mb-3 grid gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]" @submit.prevent="submitTrustedNetwork">
                  <label class="sr-only" :for="trustedInputId">{{ t('admin.keyIpAudit.drawer.cidrPlaceholder') }}</label>
                  <input :id="trustedInputId" v-model.trim="trustedNetwork" class="input min-w-0" :placeholder="t('admin.keyIpAudit.drawer.cidrPlaceholder')" autocomplete="off" />
                  <label class="sr-only" :for="trustedNoteId">{{ t('admin.keyIpAudit.drawer.notePlaceholder') }}</label>
                  <input :id="trustedNoteId" v-model.trim="trustedNote" class="input min-w-0" :placeholder="t('admin.keyIpAudit.drawer.notePlaceholder')" autocomplete="off" />
                  <button type="submit" class="btn btn-primary" :disabled="busy || !trustedNetwork">{{ t('common.add') }}</button>
                </form>
                <p v-if="trustedFormError" class="mb-3 text-xs text-red-600 dark:text-red-400">{{ trustedFormError }}</p>
                <ul v-if="trustedRules.length" class="divide-y divide-gray-100 border-y border-gray-100 dark:divide-dark-800 dark:border-dark-800">
                  <li v-for="rule in trustedRules" :key="rule.id" class="flex items-start justify-between gap-3 py-3">
                    <div class="min-w-0">
                      <p class="break-all font-mono text-xs text-gray-700 dark:text-gray-300">{{ rule.cidr }}</p>
                      <p v-if="rule.note" class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ rule.note }}</p>
                      <p v-if="rule.expires_at" class="mt-1 text-[11px] text-gray-400 dark:text-dark-500">{{ t('admin.keyIpAudit.drawer.expiresAt', { value: formatTime(rule.expires_at) }) }}</p>
                    </div>
                    <button type="button" class="icon-btn icon-btn-sm shrink-0 text-red-600 dark:text-red-400" :title="t('admin.keyIpAudit.actions.removeTrusted')" :aria-label="t('admin.keyIpAudit.actions.removeTrusted')" :disabled="busy" @click="$emit('remove-trusted', rule.id)">
                      <Icon name="trash" size="sm" />
                    </button>
                  </li>
                </ul>
                <p v-else class="empty-inline">{{ t('admin.keyIpAudit.drawer.noTrustedNetworks') }}</p>
                <Pagination
                  v-if="trustedTotal > 0"
                  class="mt-3"
                  :total="trustedTotal"
                  :page="trustedPage"
                  :page-size="trustedPageSize"
                  @update:page="$emit('trusted-page-change', $event)"
                  @update:pageSize="$emit('trusted-page-size-change', $event)"
                />
              </section>

              <section>
                <h3 class="section-title mb-3">{{ t('admin.keyIpAudit.drawer.trend') }}</h3>
                <div v-if="detail.trend.length" class="space-y-2">
                  <div v-for="point in detail.trend" :key="point.bucket_start" class="grid grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-3 text-xs">
                    <time class="truncate text-gray-500 dark:text-dark-400">{{ formatTime(point.bucket_start) }}</time>
                    <span class="text-gray-700 dark:text-gray-200">{{ formatNumber(point.request_count) }}</span>
                    <span class="text-amber-600 dark:text-amber-400">{{ formatNumber(point.risky_keys) }}</span>
                  </div>
                </div>
                <p v-else class="empty-inline">{{ t('admin.keyIpAudit.drawer.noTrend') }}</p>
              </section>

              <section class="border-t border-gray-100 pt-5 dark:border-dark-800">
                <h3 class="section-title mb-3">{{ t('admin.keyIpAudit.metadata.title') }}</h3>
                <dl class="grid gap-x-5 gap-y-3 text-xs sm:grid-cols-2">
                  <div><dt class="audit-label">{{ t('admin.keyIpAudit.metadata.source') }}</dt><dd class="audit-value">{{ detail.metadata.coverage.source }}</dd></div>
                  <div><dt class="audit-label">{{ t('admin.keyIpAudit.metadata.logs') }}</dt><dd class="audit-value">{{ formatNumber(detail.metadata.coverage.usage_log_count) }}</dd></div>
                  <div><dt class="audit-label">{{ t('admin.keyIpAudit.metadata.missingIp') }}</dt><dd class="audit-value">{{ formatNumber(detail.metadata.coverage.missing_ip_count) }}</dd></div>
                  <div><dt class="audit-label">{{ t('admin.keyIpAudit.metadata.missingUserAgent') }}</dt><dd class="audit-value">{{ formatNumber(detail.metadata.coverage.missing_user_agent_count) }}</dd></div>
                  <div><dt class="audit-label">{{ t('admin.keyIpAudit.metadata.ipCoverage') }}</dt><dd class="audit-value">{{ detail.metadata.coverage.ip_coverage_percent }}%</dd></div>
                </dl>
              </section>
            </div>
          </div>
        </aside>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import Icon from '@/components/icons/Icon.vue'
import LoadingSpinner from '@/components/common/LoadingSpinner.vue'
import Pagination from '@/components/common/Pagination.vue'
import type {
  KeyAuditDetailResponse,
  KeyAuditIpRecord,
  KeyAuditTrustedInput,
  KeyAuditTrustedRule,
  KeyRiskLevel
} from '@/features/key-ip-audit/types'
import { formatUnknown } from '@/features/key-ip-audit/viewModel'

const props = withDefaults(defineProps<{
  show: boolean
  detail: KeyAuditDetailResponse | null
  trustedRules?: KeyAuditTrustedRule[]
  trustedTotal?: number
  trustedPage?: number
  trustedPageSize?: number
  dismissalId?: number | null
  loading?: boolean
  error?: string
  busy?: boolean
  suspended?: boolean
}>(), {
  trustedRules: () => [],
  trustedTotal: 0,
  trustedPage: 1,
  trustedPageSize: 10,
  dismissalId: null,
  loading: false,
  error: '',
  busy: false,
  suspended: false
})

const emit = defineEmits<{
  (event: 'close'): void
  (event: 'retry'): void
  (event: 'disable'): void
  (event: 'rotate'): void
  (event: 'lookup-ip', ip: string): void
  (event: 'select-related-ip', ip: string): void
  (event: 'open-usage', ip: string): void
  (event: 'open-related-key', keyId: number): void
  (event: 'add-trusted', input: Omit<KeyAuditTrustedInput, 'key_id'>): void
  (event: 'remove-trusted', ruleId: number): void
  (event: 'dismiss', payload: { ip: string; riskCode: string }): void
  (event: 'remove-dismissal', dismissalId: number): void
  (event: 'ip-page-change', page: number): void
  (event: 'ip-page-size-change', pageSize: number): void
  (event: 'related-page-change', page: number): void
  (event: 'related-page-size-change', pageSize: number): void
  (event: 'trusted-page-change', page: number): void
  (event: 'trusted-page-size-change', pageSize: number): void
}>()

const { t } = useI18n()
const panelRef = ref<HTMLElement | null>(null)
const previousActiveElement = ref<HTMLElement | null>(null)
const trustedNetwork = ref('')
const trustedNote = ref('')
const trustedFormError = ref('')
const showTrustedForm = ref(false)
const dismissalIp = ref('')
const titleId = `key-ip-audit-drawer-${Math.random().toString(36).slice(2)}`
const trustedInputId = `${titleId}-trusted-network`
const trustedNoteId = `${titleId}-trusted-note`
const dismissalIpId = `${titleId}-dismissal-ip`

function close() {
  if (!props.busy && !props.suspended) emit('close')
}

function handleEscape(event: KeyboardEvent) {
  if (props.show && !props.suspended && event.key === 'Escape') close()
}

function submitTrustedNetwork() {
  const cidr = trustedNetwork.value.trim()
  if (!cidr) {
    trustedFormError.value = t('admin.keyIpAudit.drawer.cidrRequired')
    return
  }
  trustedFormError.value = ''
  emit('add-trusted', {
    cidr,
    ...(trustedNote.value.trim() ? { note: trustedNote.value.trim() } : {})
  })
  trustedNetwork.value = ''
  trustedNote.value = ''
  showTrustedForm.value = false
}

function locationLabel(record: KeyAuditIpRecord): string {
  const values = [record.geo, record.asn].map(value => String(value || '').trim()).filter(Boolean)
  return values.length ? values.join(' · ') : t('admin.keyIpAudit.unknownLocation')
}

function formatTime(value: string | null | undefined): string {
  if (!value) return t('common.unknown')
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function formatNumber(value: number | null | undefined): string {
  return new Intl.NumberFormat().format(value ?? 0)
}

function formatPercent(value: number | null): string {
  return value == null ? t('common.unknown') : `${value > 0 ? '+' : ''}${value.toFixed(1)}%`
}

function riskLabel(level: KeyRiskLevel): string {
  return t(`admin.keyIpAudit.risk.${level}`)
}

function auditStatusLabel(status: string): string {
  return t(`admin.keyIpAudit.auditStatus.${status}`)
}

function riskBadgeClass(level: KeyRiskLevel): string {
  const classes: Record<KeyRiskLevel, string> = {
    none: 'audit-badge bg-gray-100 text-gray-600 dark:bg-dark-800 dark:text-dark-300',
    low: 'audit-badge bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
    medium: 'audit-badge bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    high: 'audit-badge bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-300'
  }
  return classes[level]
}

function riskTextClass(level: KeyRiskLevel): string {
  if (level === 'high') return 'text-red-500'
  if (level === 'medium') return 'text-amber-500'
  return 'text-gray-400'
}

function auditStatusBadgeClass(status: string): string {
  if (status === 'dismissed') return 'audit-badge bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
  if (status === 'open') return 'audit-badge bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
  return 'audit-badge bg-gray-100 text-gray-600 dark:bg-dark-800 dark:text-dark-300'
}

function keyStatusBadgeClass(status: string): string {
  if (status === 'active') return 'audit-badge bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
  return 'audit-badge bg-gray-100 text-gray-600 dark:bg-dark-800 dark:text-dark-300'
}

watch(() => props.show, async (show) => {
  if (show) {
    previousActiveElement.value = document.activeElement as HTMLElement
    document.body.classList.add('modal-open')
    await nextTick()
    panelRef.value?.focus()
  } else {
    document.body.classList.remove('modal-open')
    previousActiveElement.value?.focus?.()
    previousActiveElement.value = null
    resetLocalForms()
  }
}, { immediate: true })

watch(() => props.detail?.key.key_id, () => {
  resetLocalForms()
  const firstIp = props.detail?.related_ip || props.detail?.ips[0]?.ip || ''
  dismissalIp.value = firstIp
})

function resetLocalForms() {
  showTrustedForm.value = false
  trustedNetwork.value = ''
  trustedNote.value = ''
  trustedFormError.value = ''
}

onMounted(() => document.addEventListener('keydown', handleEscape))

onBeforeUnmount(() => {
  document.removeEventListener('keydown', handleEscape)
  document.body.classList.remove('modal-open')
})
</script>

<style scoped>
.audit-label {
  @apply text-[11px] font-semibold uppercase tracking-wide text-gray-400 dark:text-dark-500;
}

.audit-value {
  @apply mt-1 text-sm font-medium text-gray-800 dark:text-gray-200;
}

.audit-badge {
  @apply inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium;
}

.section-title {
  @apply text-sm font-semibold text-gray-800 dark:text-gray-200;
}

.empty-inline {
  @apply border-y border-gray-100 py-4 text-sm text-gray-500 dark:border-dark-800 dark:text-dark-400;
}

.icon-btn {
  @apply inline-flex h-9 w-9 items-center justify-center rounded-md text-gray-500 transition-colors hover:bg-gray-100 hover:text-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-500/40 disabled:cursor-not-allowed disabled:opacity-50 dark:text-dark-400 dark:hover:bg-dark-800 dark:hover:text-dark-100;
}

.icon-btn-sm {
  @apply h-7 w-7;
}
</style>
