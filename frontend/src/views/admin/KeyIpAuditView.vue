<template>
  <AppLayout>
    <div class="space-y-5">
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div class="min-w-0">
          <h1 class="text-xl font-semibold text-gray-900 dark:text-white">{{ t('admin.keyIpAudit.title') }}</h1>
          <p class="mt-1 max-w-3xl text-sm text-gray-500 dark:text-dark-400">{{ t('admin.keyIpAudit.description') }}</p>
        </div>
        <button type="button" class="btn btn-secondary shrink-0" :disabled="loading" :title="t('admin.keyIpAudit.refresh')" @click="refresh">
          <Icon name="refresh" size="sm" :class="loading ? 'animate-spin' : ''" />
          <span>{{ t('common.refresh') }}</span>
        </button>
      </div>

      <section class="border-y border-gray-200 bg-white dark:border-dark-700 dark:bg-dark-900" aria-labelledby="key-audit-summary-title">
        <div class="flex flex-wrap items-center justify-between gap-3 border-b border-gray-100 px-4 py-3 dark:border-dark-800 sm:px-5">
          <h2 id="key-audit-summary-title" class="text-sm font-semibold text-gray-800 dark:text-gray-200">{{ t('admin.keyIpAudit.summary.title') }}</h2>
          <span v-if="metadata" class="text-xs text-gray-500 dark:text-dark-400">
            {{ formatTime(metadata.from) }} - {{ formatTime(metadata.to) }}
          </span>
        </div>

        <div v-if="loading && !summary" class="grid grid-cols-2 divide-x divide-y divide-gray-100 sm:grid-cols-6 sm:divide-y-0 dark:divide-dark-800" role="status">
          <div v-for="item in 6" :key="item" class="space-y-2 px-4 py-4 sm:px-5">
            <div class="h-3 w-20 animate-pulse rounded bg-gray-200 dark:bg-dark-700"></div>
            <div class="h-6 w-16 animate-pulse rounded bg-gray-200 dark:bg-dark-700"></div>
          </div>
        </div>
        <div v-else-if="summary" class="grid grid-cols-2 divide-x divide-y divide-gray-100 sm:grid-cols-6 sm:divide-y-0 dark:divide-dark-800">
          <div class="summary-stat">
            <span class="summary-label">{{ t('admin.keyIpAudit.summary.totalKeys') }}</span>
            <strong class="summary-value">{{ formatNumber(summary.total_keys) }}</strong>
          </div>
          <button type="button" class="summary-stat text-left hover:bg-gray-50 dark:hover:bg-dark-800" :class="filters.risk === 'high' ? 'bg-red-50/60 dark:bg-red-900/10' : ''" @click="applySummaryFilter('risk', 'high')">
            <span class="summary-label">{{ t('admin.keyIpAudit.summary.highRiskKeys') }}</span>
            <strong class="summary-value text-red-600 dark:text-red-400">{{ formatNumber(summary.high_risk_keys) }}</strong>
          </button>
          <button type="button" class="summary-stat text-left hover:bg-gray-50 dark:hover:bg-dark-800" :class="filters.signal === 'new_ip' ? 'bg-amber-50/60 dark:bg-amber-900/10' : ''" @click="applySummaryFilter('signal', 'new_ip')">
            <span class="summary-label">{{ t('admin.keyIpAudit.summary.newIpKeys') }}</span>
            <strong class="summary-value">{{ formatNumber(summary.new_ip_keys) }}</strong>
          </button>
          <button type="button" class="summary-stat text-left hover:bg-gray-50 dark:hover:bg-dark-800" :class="filters.signal === 'multi_ip_burst' ? 'bg-amber-50/60 dark:bg-amber-900/10' : ''" @click="applySummaryFilter('signal', 'multi_ip_burst')">
            <span class="summary-label">{{ t('admin.keyIpAudit.summary.multiIpKeys') }}</span>
            <strong class="summary-value">{{ formatNumber(summary.multi_ip_keys) }}</strong>
          </button>
          <button type="button" class="summary-stat text-left hover:bg-gray-50 dark:hover:bg-dark-800" :class="filters.signal === 'shared_ip_cross_users' ? 'bg-amber-50/60 dark:bg-amber-900/10' : ''" @click="applySummaryFilter('signal', 'shared_ip_cross_users')">
            <span class="summary-label">{{ t('admin.keyIpAudit.summary.sharedIps') }}</span>
            <strong class="summary-value">{{ formatNumber(summary.shared_ips) }}</strong>
          </button>
          <div class="summary-stat">
            <span class="summary-label">{{ t('admin.keyIpAudit.summary.pendingKeys') }}</span>
            <strong class="summary-value">{{ formatNumber(summary.pending_keys) }}</strong>
          </div>
        </div>

        <div class="border-t border-gray-100 px-4 py-4 dark:border-dark-800 sm:px-5">
          <h3 class="mb-2 text-xs font-medium text-gray-500 dark:text-dark-400">{{ t('admin.keyIpAudit.drawer.trend') }} · {{ t('admin.keyIpAudit.columns.requests') }}</h3>
          <div v-if="trendBars.length" class="flex h-16 items-end gap-1" role="img" :aria-label="t('admin.keyIpAudit.summary.trend')">
            <div v-for="point in trendBars" :key="point.bucket_start" class="min-w-0 flex-1 rounded-t bg-primary-400/70 transition-[height] dark:bg-primary-500/70" :style="{ height: `${point.height}%` }" :title="`${formatTime(point.bucket_start)}: ${formatNumber(point.request_count)}`"></div>
          </div>
          <p v-else class="text-sm text-gray-500 dark:text-dark-400">{{ t('admin.keyIpAudit.summary.noTrend') }}</p>
        </div>

        <div v-if="metadata" class="border-t border-gray-100 px-4 py-4 dark:border-dark-800 sm:px-5">
          <div class="mb-3 flex flex-wrap items-baseline justify-between gap-2">
            <h3 class="text-sm font-semibold text-gray-800 dark:text-gray-200">{{ t('admin.keyIpAudit.metadata.title') }}</h3>
            <span class="text-xs text-gray-500 dark:text-dark-400">{{ metadata.coverage.source }}</span>
          </div>
          <dl class="grid grid-cols-2 gap-x-5 gap-y-3 text-xs sm:grid-cols-4">
            <div><dt class="metadata-label">{{ t('admin.keyIpAudit.metadata.logs') }}</dt><dd class="metadata-value">{{ formatNumber(metadata.coverage.usage_log_count) }}</dd></div>
            <div><dt class="metadata-label">{{ t('admin.keyIpAudit.metadata.missingIp') }}</dt><dd class="metadata-value">{{ formatNumber(metadata.coverage.missing_ip_count) }}</dd></div>
            <div><dt class="metadata-label">{{ t('admin.keyIpAudit.metadata.missingUserAgent') }}</dt><dd class="metadata-value">{{ formatNumber(metadata.coverage.missing_user_agent_count) }}</dd></div>
            <div><dt class="metadata-label">{{ t('admin.keyIpAudit.metadata.ipCoverage') }}</dt><dd class="metadata-value">{{ metadata.coverage.ip_coverage_percent }}%</dd></div>
          </dl>
        </div>

        <p v-if="loadError && !rows.length" class="border-t border-red-100 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-900/20 dark:text-red-300" role="alert">{{ loadError }}</p>
        <p v-else-if="loadError" class="border-t border-amber-100 bg-amber-50 px-4 py-2 text-xs text-amber-800 dark:border-amber-900/40 dark:bg-amber-900/20 dark:text-amber-200" role="status">{{ loadError }}</p>
      </section>

      <TablePageLayout>
        <template #filters>
          <div class="border-y border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-900 sm:p-5">
            <div class="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-8">
              <div class="xl:col-span-2">
                <label class="input-label" for="key-audit-user">{{ t('admin.keyIpAudit.filters.user') }}</label>
                <input id="key-audit-user" v-model.trim="filters.user" type="text" class="input" :placeholder="t('admin.keyIpAudit.filters.userPlaceholder')" @keyup.enter="search" />
              </div>
              <div class="xl:col-span-2">
                <label class="input-label" for="key-audit-ip">{{ t('admin.keyIpAudit.filters.ip') }}</label>
                <input id="key-audit-ip" v-model.trim="filters.ip" type="text" class="input font-mono" :placeholder="t('admin.keyIpAudit.filters.ipPlaceholder')" @keyup.enter="search" />
              </div>
              <div class="xl:col-span-2">
                <label class="input-label" for="key-audit-key">{{ t('admin.keyIpAudit.filters.key') }}</label>
                <input id="key-audit-key" v-model.trim="filters.key" type="text" class="input" :placeholder="t('admin.keyIpAudit.filters.keyPlaceholder')" @keyup.enter="search" />
              </div>
              <div class="xl:col-span-2">
                <label class="input-label" for="key-audit-risk">{{ t('admin.keyIpAudit.filters.risk') }}</label>
                <Select id="key-audit-risk" v-model="filters.risk" :options="riskOptions" :aria-label="t('admin.keyIpAudit.filters.risk')" @change="search" />
              </div>
              <div class="xl:col-span-2">
                <label class="input-label" for="key-audit-status">{{ t('admin.keyIpAudit.filters.status') }}</label>
                <Select id="key-audit-status" v-model="filters.status" :options="statusOptions" :aria-label="t('admin.keyIpAudit.filters.status')" @change="search" />
              </div>
              <div class="xl:col-span-2">
                <label class="input-label" for="key-audit-signal">{{ t('admin.keyIpAudit.filters.signal') }}</label>
                <Select id="key-audit-signal" v-model="filters.signal" :options="signalOptions" :aria-label="t('admin.keyIpAudit.filters.signal')" @change="search" />
              </div>
              <div class="xl:col-span-2">
                <label class="input-label" for="key-audit-time-range">{{ t('admin.keyIpAudit.filters.timeRange') }}</label>
                <Select id="key-audit-time-range" v-model="filters.time_range" :options="timeRangeOptions" :aria-label="t('admin.keyIpAudit.filters.timeRange')" @change="handleTimeRangeChange" />
              </div>
              <div v-if="filters.time_range === 'custom'" class="sm:col-span-2 xl:col-span-2">
                <label class="input-label" for="key-audit-start-time">{{ t('admin.keyIpAudit.filters.startTime') }}</label>
                <input id="key-audit-start-time" v-model="filters.from" type="datetime-local" class="input" />
              </div>
              <div v-if="filters.time_range === 'custom'" class="sm:col-span-2 xl:col-span-2">
                <label class="input-label" for="key-audit-end-time">{{ t('admin.keyIpAudit.filters.endTime') }}</label>
                <input id="key-audit-end-time" v-model="filters.to" type="datetime-local" class="input" />
              </div>
            </div>
            <p v-if="rangeError" class="mt-3 text-xs text-red-600 dark:text-red-400">{{ rangeError }}</p>
            <div class="mt-4 flex flex-wrap items-center justify-end gap-2 border-t border-gray-100 pt-4 dark:border-dark-800">
              <button type="button" class="btn btn-secondary" :disabled="loading" @click="resetFilters">{{ t('common.reset') }}</button>
              <button type="button" class="btn btn-primary" :disabled="loading || Boolean(rangeError)" @click="search">
                <Icon name="search" size="sm" />
                {{ t('common.search') }}
              </button>
            </div>
          </div>
        </template>

        <template #table>
          <div v-if="loadError && rows.length" class="border-b border-red-100 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-900/20 dark:text-red-300" role="alert">
            <div class="flex flex-wrap items-center justify-between gap-3">
              <span>{{ loadError }}</span>
              <button type="button" class="btn btn-secondary btn-sm" :disabled="loading" @click="refresh"><Icon name="refresh" size="sm" />{{ t('common.refresh') }}</button>
            </div>
          </div>
          <DataTable :columns="columns" :data="rows" :loading="loading" :clickable-rows="true" row-key="key_id" @row-click="openDetail">
            <template #cell-key_name="{ row }">
              <div class="min-w-[170px] max-w-[250px]">
                <div class="truncate text-sm font-medium text-gray-900 dark:text-white" :title="row.key_name">{{ row.key_name }}</div>
                <div class="mt-0.5 truncate font-mono text-xs text-gray-500 dark:text-dark-400" :title="row.key_prefix">{{ row.key_prefix }}</div>
                <div class="mt-0.5 text-xs text-gray-400">#{{ row.key_id }}</div>
              </div>
            </template>
            <template #cell-user_email="{ row }">
              <button type="button" class="min-w-[150px] max-w-[220px] truncate text-left text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400" @click.stop="filterByUser(row)">
                {{ row.user_email }} <span class="text-xs text-gray-400">({{ row.user_id }})</span>
              </button>
            </template>
            <template #cell-latest_ip="{ row }">
              <button v-if="row.latest_ip" type="button" class="font-mono text-xs text-primary-600 hover:text-primary-700 dark:text-primary-400" @click.stop="filterByIp(row.latest_ip)">{{ row.latest_ip }}</button>
              <span v-else class="text-gray-400">{{ t('admin.keyIpAudit.unknownIp') }}</span>
            </template>
            <template #cell-ip_count="{ row }">
              <span class="whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">{{ formatNumber(row.ip_count) }}</span>
              <span v-if="row.new_ip_count" class="ml-1 text-xs text-amber-600 dark:text-amber-400">+{{ formatNumber(row.new_ip_count) }}</span>
            </template>
            <template #cell-last_seen="{ row }">
              <div class="min-w-[150px]">
                <div class="whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">{{ formatTime(row.last_seen) }}</div>
                <div class="mt-0.5 text-xs text-gray-500 dark:text-dark-400">{{ formatNumber(row.request_count) }} {{ t('admin.keyIpAudit.columns.requests').toLowerCase() }}</div>
              </div>
            </template>
            <template #cell-request_count="{ row }"><span class="whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">{{ formatNumber(row.request_count) }}</span></template>
            <template #cell-request_count_change_pct="{ row }"><span class="whitespace-nowrap text-xs" :class="requestChangeClass(row.request_count_change_pct)">{{ formatPercent(row.request_count_change_pct) }}</span></template>
            <template #cell-risk_level="{ row }">
              <div class="w-[170px]"><span :class="riskBadgeClass(row.risk_level)">{{ riskLabel(row.risk_level) }}</span><p class="mt-1 whitespace-normal text-xs text-gray-500 dark:text-dark-400">{{ row.risk_reasons.map((reason: string) => t(`admin.keyIpAudit.reasons.${reason}`)).join(', ') || t('admin.keyIpAudit.noReason') }}</p></div>
            </template>
            <template #cell-status="{ row }"><span :class="auditStatusBadgeClass(row.status)">{{ auditStatusLabel(row.status) }}</span></template>
            <template #cell-actions="{ row }"><button type="button" class="inline-flex items-center gap-1 font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400" @click.stop="openDetail(row)"><Icon name="eye" size="sm" />{{ t('admin.keyIpAudit.columns.detail') }}</button></template>
            <template #empty>
              <div class="flex flex-col items-center py-8"><Icon name="key" size="xl" class="mb-3 text-gray-300 dark:text-dark-600" /><p class="text-sm font-medium text-gray-600 dark:text-dark-300">{{ t('admin.keyIpAudit.empty') }}</p><p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.keyIpAudit.filteredEmpty') }}</p></div>
            </template>
          </DataTable>
        </template>

        <template #pagination>
          <Pagination v-if="total > 0" :total="total" :page="page" :page-size="pageSize" @update:page="onPageChange" @update:pageSize="onPageSizeChange" />
        </template>
      </TablePageLayout>
    </div>

    <KeyIpAuditDrawer
      :show="drawerVisible"
      :detail="detail"
      :trusted-rules="trustedRules"
      :trusted-total="trustedTotal"
      :trusted-page="trustedPage"
      :trusted-page-size="trustedPageSize"
      :dismissal-id="dismissalId"
      :loading="detailLoading"
      :error="detailError"
      :busy="mutationBusy"
      :suspended="Boolean(confirmAction) || Boolean(newSecret)"
      @close="closeDrawer"
      @retry="retryDetail"
      @disable="askDisable"
      @rotate="askRotate"
      @lookup-ip="filterByIp"
      @select-related-ip="selectRelatedIp"
      @open-usage="openUsageLogs"
      @open-related-key="openRelatedKey"
      @add-trusted="askAddTrusted"
      @remove-trusted="askRemoveTrusted"
      @dismiss="askDismiss"
      @remove-dismissal="askRemoveDismissal"
      @ip-page-change="onIpPageChange"
      @ip-page-size-change="onIpPageSizeChange"
      @related-page-change="onRelatedPageChange"
      @related-page-size-change="onRelatedPageSizeChange"
      @trusted-page-change="onTrustedPageChange"
      @trusted-page-size-change="onTrustedPageSizeChange"
    />

    <ConfirmDialog
      :show="Boolean(confirmAction)"
      :title="confirmDialogTitle"
      :message="confirmDialogMessage"
      :confirm-text="t('common.confirm')"
      :cancel-text="t('common.cancel')"
      :danger="confirmAction === 'disable' || confirmAction === 'rotate' || confirmAction === 'remove-dismissal'"
      @confirm="confirmPendingAction"
      @cancel="cancelPendingAction"
    />

    <BaseDialog :show="Boolean(newSecret)" :title="t('admin.keyIpAudit.secret.title')" width="wide" @close="closeSecret">
      <div class="space-y-4">
        <p class="text-sm text-amber-700 dark:text-amber-300">{{ t('admin.keyIpAudit.secret.warning') }}</p>
        <div class="flex items-start gap-3 border border-gray-200 bg-gray-50 p-3 dark:border-dark-700 dark:bg-dark-800">
          <code class="min-w-0 flex-1 break-all font-mono text-sm text-gray-800 dark:text-gray-100">{{ newSecret }}</code>
          <button type="button" class="btn btn-secondary btn-sm shrink-0" @click="copySecret"><Icon name="copy" size="sm" />{{ secretCopied ? t('admin.keyIpAudit.secret.copied') : t('admin.keyIpAudit.secret.copy') }}</button>
        </div>
      </div>
      <template #footer><button type="button" class="btn btn-primary" @click="closeSecret">{{ t('admin.keyIpAudit.secret.close') }}</button></template>
    </BaseDialog>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useAppStore } from '@/stores'
import AppLayout from '@/components/layout/AppLayout.vue'
import TablePageLayout from '@/components/layout/TablePageLayout.vue'
import DataTable from '@/components/common/DataTable.vue'
import Pagination from '@/components/common/Pagination.vue'
import Select from '@/components/common/Select.vue'
import BaseDialog from '@/components/common/BaseDialog.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import Icon from '@/components/icons/Icon.vue'
import KeyIpAuditDrawer from '@/components/admin/KeyIpAuditDrawer.vue'
import { getPersistedPageSize } from '@/composables/usePersistedPageSize'
import { extractApiErrorMessage } from '@/utils/apiError'
import type { Column } from '@/components/common/types'
import {
  createDismissal,
  detail as getDetail,
  disable,
  list,
  listTrusted,
  removeDismissal,
  removeTrusted,
  rotate,
  addTrusted
} from '@/api/admin/keyIpAudit'
import type {
  KeyAuditDetailResponse,
  KeyAuditFilters,
  KeyAuditKeyRow,
  KeyAuditMetadata,
  KeyAuditSignal,
  KeyAuditSummary,
  KeyAuditTimeRange,
  KeyAuditTrendPoint,
  KeyAuditTrustedInput,
  KeyAuditTrustedRule,
  KeyRiskLevel
} from '@/features/key-ip-audit/types'
import {
  buildKeyAuditDetailQuery,
  buildKeyAuditQuery,
  createDefaultKeyAuditFilters,
  DEFAULT_KEY_AUDIT_IP_PAGE_SIZE,
  DEFAULT_KEY_AUDIT_RELATED_PAGE_SIZE,
  DEFAULT_KEY_AUDIT_TRUSTED_PAGE_SIZE,
  isAbortError,
  resolveKeyAuditWindow,
  validateCustomKeyAuditRange,
  type KeyAuditWindow
} from '@/features/key-ip-audit/viewModel'

const { t } = useI18n()
const router = useRouter()
const appStore = useAppStore()

const filters = reactive<KeyAuditFilters>(createDefaultKeyAuditFilters())
const page = ref(1)
const pageSize = ref(getPersistedPageSize())
const rows = ref<KeyAuditKeyRow[]>([])
const total = ref(0)
const summary = ref<KeyAuditSummary | null>(null)
const trend = ref<KeyAuditTrendPoint[]>([])
const metadata = ref<KeyAuditMetadata | null>(null)
const loading = ref(false)
const loadError = ref('')
const currentWindow = ref<KeyAuditWindow | null>(null)

const drawerVisible = ref(false)
const detail = ref<KeyAuditDetailResponse | null>(null)
const selectedKeyId = ref<number | null>(null)
const detailWindow = ref<KeyAuditWindow | null>(null)
const detailLoading = ref(false)
const detailError = ref('')
const detailQuery = reactive({
  ip_page: 1,
  ip_page_size: DEFAULT_KEY_AUDIT_IP_PAGE_SIZE,
  related_ip: '',
  related_page: 1,
  related_page_size: DEFAULT_KEY_AUDIT_RELATED_PAGE_SIZE
})
const trustedRules = ref<KeyAuditTrustedRule[]>([])
const trustedTotal = ref(0)
const trustedPage = ref(1)
const trustedPageSize = ref(DEFAULT_KEY_AUDIT_TRUSTED_PAGE_SIZE)
const dismissalId = ref<number | null>(null)

const mutationBusy = ref(false)
const newSecret = ref('')
const secretCopied = ref(false)
const confirmAction = ref<ConfirmAction | null>(null)
const pendingTrusted = ref<Omit<KeyAuditTrustedInput, 'key_id'> | null>(null)
const pendingTrustedRuleId = ref<number | null>(null)
const pendingDismissal = ref<{ ip: string; riskCode: string } | null>(null)

type ConfirmAction = 'disable' | 'rotate' | 'remove-trusted' | 'dismiss' | 'remove-dismissal'

let listController: AbortController | null = null
let detailController: AbortController | null = null
let trustedController: AbortController | null = null
let mutationController: AbortController | null = null
let detailRequestSequence = 0
let trustedRequestSequence = 0

const columns = computed<Column[]>(() => [
  { key: 'key_name', label: t('admin.keyIpAudit.columns.key') },
  { key: 'risk_level', label: t('admin.keyIpAudit.columns.risk') },
  { key: 'user_email', label: t('admin.keyIpAudit.columns.user') },
  { key: 'latest_ip', label: t('admin.keyIpAudit.columns.latestIp') },
  { key: 'ip_count', label: t('admin.keyIpAudit.columns.ipCount') },
  { key: 'last_seen', label: t('admin.keyIpAudit.columns.lastUsed') },
  { key: 'request_count', label: t('admin.keyIpAudit.columns.requests') },
  { key: 'request_count_change_pct', label: t('admin.keyIpAudit.columns.requestChange') },
  { key: 'status', label: t('admin.keyIpAudit.columns.status') },
  { key: 'actions', label: t('common.actions') }
])

const riskOptions = computed(() => [
  { value: '', label: t('admin.keyIpAudit.filters.allRisk') },
  { value: 'none', label: t('admin.keyIpAudit.risk.none') },
  { value: 'low', label: t('admin.keyIpAudit.risk.low') },
  { value: 'medium', label: t('admin.keyIpAudit.risk.medium') },
  { value: 'high', label: t('admin.keyIpAudit.risk.high') }
])

const statusOptions = computed(() => [
  { value: '', label: t('admin.keyIpAudit.filters.allStatus') },
  { value: 'active', label: t('admin.keyIpAudit.keyStatus.active') },
  { value: 'inactive', label: t('admin.keyIpAudit.keyStatus.inactive') }
])

const signalOptions = computed(() => [
  { value: '', label: t('admin.keyIpAudit.filters.allSignals') },
  { value: 'new_ip', label: t('admin.keyIpAudit.signals.newIp') },
  { value: 'multi_ip_burst', label: t('admin.keyIpAudit.signals.multiIpBurst') },
  { value: 'shared_ip_cross_users', label: t('admin.keyIpAudit.signals.sharedIpCrossUsers') },
  { value: 'volume_spike', label: t('admin.keyIpAudit.signals.volumeSpike') }
])

const timeRangeOptions = computed(() => [
  { value: '24h', label: t('admin.keyIpAudit.timeRanges.24h') },
  { value: '7d', label: t('admin.keyIpAudit.timeRanges.7d') },
  { value: '30d', label: t('admin.keyIpAudit.timeRanges.30d') },
  { value: 'custom', label: t('admin.keyIpAudit.timeRanges.custom') }
])

const rangeError = computed(() => {
  const error = validateCustomKeyAuditRange(filters)
  if (error === 'required') return t('admin.keyIpAudit.filters.rangeRequired')
  if (error === 'invalid') return t('admin.keyIpAudit.filters.rangeInvalid')
  if (error === 'future') return t('admin.keyIpAudit.filters.rangeFuture')
  if (error === 'too_long') return t('admin.keyIpAudit.filters.rangeTooLong')
  return ''
})

const trendBars = computed(() => {
  const maximum = Math.max(...trend.value.map(point => point.request_count), 1)
  return trend.value.map(point => ({ ...point, height: Math.max(8, Math.round((point.request_count / maximum) * 100)) }))
})

const confirmDialogTitle = computed(() => {
  if (confirmAction.value === 'disable') return t('admin.keyIpAudit.confirm.disableTitle')
  if (confirmAction.value === 'rotate') return t('admin.keyIpAudit.confirm.rotateTitle')
  if (confirmAction.value === 'remove-trusted') return t('admin.keyIpAudit.confirm.trustedRemoveTitle')
  if (confirmAction.value === 'dismiss') return t('admin.keyIpAudit.confirm.falsePositiveTitle')
  if (confirmAction.value === 'remove-dismissal') return t('admin.keyIpAudit.confirm.undoFalsePositiveTitle')
  return ''
})

const confirmDialogMessage = computed(() => {
  if (confirmAction.value === 'disable') return t('admin.keyIpAudit.confirm.disableMessage')
  if (confirmAction.value === 'rotate') return t('admin.keyIpAudit.confirm.rotateMessage')
  if (confirmAction.value === 'remove-trusted') return t('admin.keyIpAudit.confirm.trustedRemoveMessage')
  if (confirmAction.value === 'dismiss') return t('admin.keyIpAudit.confirm.falsePositiveMessage')
  if (confirmAction.value === 'remove-dismissal') return t('admin.keyIpAudit.confirm.undoFalsePositiveMessage')
  return ''
})

function currentListQuery(targetWindow: KeyAuditWindow) {
  const query = buildKeyAuditQuery(filters, page.value, pageSize.value)
  query.from = targetWindow.from
  query.to = targetWindow.to
  return query
}

async function loadList(targetWindow = currentWindow.value): Promise<void> {
  if (!targetWindow) return
  listController?.abort()
  const controller = new AbortController()
  listController = controller
  loading.value = true
  loadError.value = ''
  try {
    const response = await list(currentListQuery(targetWindow), { signal: controller.signal })
    if (controller.signal.aborted || listController !== controller) return
    currentWindow.value = targetWindow
    rows.value = response.items
    total.value = response.total
    summary.value = response.summary
    trend.value = response.trend
    metadata.value = response.metadata
  } catch (error: unknown) {
    if (controller.signal.aborted || isAbortError(error) || listController !== controller) return
    loadError.value = extractApiErrorMessage(error, t('admin.keyIpAudit.loadFailed'))
  } finally {
    if (listController === controller) {
      listController = null
      loading.value = false
    }
  }
}

function refresh(): void {
  if (rangeError.value) return
  try {
    const targetWindow = resolveKeyAuditWindow(filters)
    void loadList(targetWindow)
  } catch (error: unknown) {
    loadError.value = extractApiErrorMessage(error, t('admin.keyIpAudit.loadFailed'))
  }
}

function search(): void {
  if (rangeError.value) return
  page.value = 1
  refresh()
}

function resetFilters(): void {
  Object.assign(filters, createDefaultKeyAuditFilters())
  page.value = 1
  refresh()
}

function handleTimeRangeChange(value: string | number | boolean | null): void {
  const next = String(value || '24h') as KeyAuditTimeRange
  filters.time_range = next
  if (next !== 'custom') {
    filters.from = ''
    filters.to = ''
    search()
  }
}

function applySummaryFilter(kind: 'risk' | 'signal', value: KeyRiskLevel | KeyAuditSignal): void {
  if (kind === 'risk') filters.risk = filters.risk === value ? '' : value as KeyRiskLevel
  else filters.signal = filters.signal === value ? '' : value as KeyAuditSignal
  search()
}

function onPageChange(nextPage: number): void {
  page.value = nextPage
  void loadList(currentWindow.value ?? resolveKeyAuditWindow(filters))
}

function onPageSizeChange(nextPageSize: number): void {
  pageSize.value = nextPageSize
  page.value = 1
  void loadList(currentWindow.value ?? resolveKeyAuditWindow(filters))
}

function openDetail(row: KeyAuditKeyRow): void {
  const targetWindow = currentWindow.value
  if (!targetWindow) return
  drawerVisible.value = true
  selectedKeyId.value = row.key_id
  detailWindow.value = targetWindow
  detail.value = null
  detailError.value = ''
  resetDetailPaging()
  void loadDetail(row.key_id, targetWindow)
}

async function loadDetail(keyId: number, targetWindow = detailWindow.value ?? currentWindow.value, overrides: Partial<typeof detailQuery> = {}): Promise<void> {
  if (!targetWindow) return
  detailWindow.value = targetWindow
  Object.assign(detailQuery, overrides)
  selectedKeyId.value = keyId
  detailController?.abort()
  trustedController?.abort()
  const detailRequest = new AbortController()
  const trustedRequest = new AbortController()
  const detailRequestId = ++detailRequestSequence
  const trustedRequestId = ++trustedRequestSequence
  detailController = detailRequest
  trustedController = trustedRequest
  detailLoading.value = true
  detailError.value = ''
  try {
    const params = buildKeyAuditDetailQuery(
      targetWindow,
      detailQuery.ip_page,
      detailQuery.ip_page_size,
      detailQuery.related_page,
      detailQuery.related_page_size,
      detailQuery.related_ip || undefined
    )
    const [response, trustedResponse] = await Promise.all([
      getDetail(keyId, params, { signal: detailRequest.signal }),
      listTrusted({ key_id: keyId, page: trustedPage.value, page_size: trustedPageSize.value }, { signal: trustedRequest.signal })
    ])
    if (
      detailRequest.signal.aborted
      || trustedRequest.signal.aborted
      || detailRequestId !== detailRequestSequence
      || trustedRequestId !== trustedRequestSequence
      || detailController !== detailRequest
      || trustedController !== trustedRequest
    ) return
    detail.value = response
    trustedRules.value = trustedResponse.items
    trustedTotal.value = trustedResponse.total
    if (response.key.status !== 'dismissed') dismissalId.value = null
    if (!detailQuery.related_ip && response.related_ip) detailQuery.related_ip = response.related_ip
  } catch (error: unknown) {
    const isCurrentRequest = (
      detailRequestId === detailRequestSequence
      && trustedRequestId === trustedRequestSequence
      && detailController === detailRequest
      && trustedController === trustedRequest
    )
    if (!isCurrentRequest || detailRequest.signal.aborted || trustedRequest.signal.aborted || isAbortError(error)) return
    detailRequest.abort()
    trustedRequest.abort()
    detailError.value = extractApiErrorMessage(error, t('admin.keyIpAudit.loadFailed'))
  } finally {
    if (detailController === detailRequest && detailRequestId === detailRequestSequence) {
      detailController = null
      detailLoading.value = false
    }
    if (trustedController === trustedRequest && trustedRequestId === trustedRequestSequence) trustedController = null
  }
}

async function loadTrustedRules(): Promise<void> {
  const keyId = selectedKeyId.value
  if (keyId == null) return
  trustedController?.abort()
  const controller = new AbortController()
  const requestId = ++trustedRequestSequence
  trustedController = controller
  try {
    const response = await listTrusted({ key_id: keyId, page: trustedPage.value, page_size: trustedPageSize.value }, { signal: controller.signal })
    if (controller.signal.aborted || trustedController !== controller || requestId !== trustedRequestSequence || selectedKeyId.value !== keyId) return
    trustedRules.value = response.items
    trustedTotal.value = response.total
  } catch (error: unknown) {
    if (controller.signal.aborted || isAbortError(error) || trustedController !== controller || requestId !== trustedRequestSequence || selectedKeyId.value !== keyId) return
    appStore.showError(extractApiErrorMessage(error, t('admin.keyIpAudit.loadFailed')))
  } finally {
    if (trustedController === controller && requestId === trustedRequestSequence) trustedController = null
  }
}

function retryDetail(): void {
  if (selectedKeyId.value != null) void loadDetail(selectedKeyId.value)
}

function closeDrawer(): void {
  drawerVisible.value = false
  detailRequestSequence += 1
  trustedRequestSequence += 1
  detailController?.abort()
  trustedController?.abort()
  mutationController?.abort()
  mutationController = null
  mutationBusy.value = false
  detailWindow.value = null
  selectedKeyId.value = null
  closeSecret()
}

function resetDetailPaging(): void {
  detailQuery.ip_page = 1
  detailQuery.ip_page_size = DEFAULT_KEY_AUDIT_IP_PAGE_SIZE
  detailQuery.related_ip = ''
  detailQuery.related_page = 1
  detailQuery.related_page_size = DEFAULT_KEY_AUDIT_RELATED_PAGE_SIZE
  trustedPage.value = 1
  trustedPageSize.value = DEFAULT_KEY_AUDIT_TRUSTED_PAGE_SIZE
  trustedRules.value = []
  trustedTotal.value = 0
  dismissalId.value = null
}

function onIpPageChange(nextPage: number): void {
  if (selectedKeyId.value == null) return
  detailQuery.ip_page = nextPage
  void loadDetail(selectedKeyId.value)
}

function onIpPageSizeChange(nextPageSize: number): void {
  if (selectedKeyId.value == null) return
  detailQuery.ip_page = 1
  detailQuery.ip_page_size = nextPageSize
  void loadDetail(selectedKeyId.value)
}

function onRelatedPageChange(nextPage: number): void {
  if (selectedKeyId.value == null) return
  detailQuery.related_page = nextPage
  void loadDetail(selectedKeyId.value)
}

function onRelatedPageSizeChange(nextPageSize: number): void {
  if (selectedKeyId.value == null) return
  detailQuery.related_page = 1
  detailQuery.related_page_size = nextPageSize
  void loadDetail(selectedKeyId.value)
}

function onTrustedPageChange(nextPage: number): void {
  trustedPage.value = nextPage
  void loadTrustedRules()
}

function onTrustedPageSizeChange(nextPageSize: number): void {
  trustedPage.value = 1
  trustedPageSize.value = nextPageSize
  void loadTrustedRules()
}

function selectRelatedIp(ip: string): void {
  if (selectedKeyId.value == null) return
  detailQuery.related_ip = ip
  detailQuery.related_page = 1
  void loadDetail(selectedKeyId.value)
}

function openRelatedKey(keyId: number): void {
  const targetWindow = detailWindow.value ?? currentWindow.value
  if (!targetWindow) return
  resetDetailPaging()
  detailWindow.value = targetWindow
  detail.value = null
  void loadDetail(keyId, targetWindow)
}

function filterByIp(ip: string): void {
  filters.ip = ip
  closeDrawer()
  search()
}

function filterByUser(row: KeyAuditKeyRow): void {
  filters.user = String(row.user_id)
  closeDrawer()
  search()
}

function openUsageLogs(ip: string): void {
  const query: Record<string, string> = { ip_address: ip }
  const targetWindow = detailWindow.value ?? currentWindow.value
  if (targetWindow) {
    query.from = targetWindow.from
    query.to = targetWindow.to
  }
  if (selectedKeyId.value != null) query.key_id = String(selectedKeyId.value)
  void router.push({ path: '/admin/usage', query })
}

function askDisable(): void { confirmAction.value = 'disable' }
function askRotate(): void { confirmAction.value = 'rotate' }

function askAddTrusted(input: Omit<KeyAuditTrustedInput, 'key_id'>): void {
  pendingTrusted.value = input
  void executeMutation('add-trusted')
}

function askRemoveTrusted(ruleId: number): void {
  pendingTrustedRuleId.value = ruleId
  confirmAction.value = 'remove-trusted'
}

function askDismiss(payload: { ip: string; riskCode: string }): void {
  pendingDismissal.value = payload
  confirmAction.value = 'dismiss'
}

function askRemoveDismissal(dismissalIdToRemove: number): void {
  pendingTrustedRuleId.value = dismissalIdToRemove
  confirmAction.value = 'remove-dismissal'
}

function cancelPendingAction(): void {
  confirmAction.value = null
  pendingTrusted.value = null
  pendingTrustedRuleId.value = null
  pendingDismissal.value = null
}

function confirmPendingAction(): void {
  const action = confirmAction.value
  const ruleId = pendingTrustedRuleId.value
  const dismissal = pendingDismissal.value
  cancelPendingAction()
  if (action === 'remove-trusted' && ruleId != null) void executeMutation(action, { ruleId })
  else if (action === 'remove-dismissal' && ruleId != null) void executeMutation(action, { dismissalId: ruleId })
  else if (action === 'dismiss' && dismissal) void executeMutation(action, { dismissal })
  else if (action === 'disable' || action === 'rotate') void executeMutation(action)
}

async function executeMutation(
  action: ConfirmAction | 'add-trusted',
  context: { ruleId?: number; dismissalId?: number; dismissal?: { ip: string; riskCode: string } } = {}
): Promise<void> {
  const keyId = selectedKeyId.value
  if (keyId == null || mutationBusy.value) return
  mutationController?.abort()
  const controller = new AbortController()
  mutationController = controller
  mutationBusy.value = true
  try {
    if (action === 'disable') {
      await disable(keyId, { signal: controller.signal })
    } else if (action === 'rotate') {
      const result = await rotate(keyId, { signal: controller.signal })
      if (controller.signal.aborted || mutationController !== controller) return
      newSecret.value = result.secret
      secretCopied.value = false
    } else if (action === 'add-trusted') {
      if (!pendingTrusted.value) return
      await addTrusted({ key_id: keyId, ...pendingTrusted.value }, { signal: controller.signal })
    } else if (action === 'remove-trusted') {
      if (context.ruleId == null) return
      await removeTrusted(context.ruleId, { signal: controller.signal })
    } else if (action === 'dismiss') {
      const dismissalWindow = detailWindow.value
      if (!context.dismissal || !dismissalWindow) return
      const now = new Date()
      const eventStart = new Date(dismissalWindow.from)
      const windowEnd = new Date(dismissalWindow.to)
      const eventEnd = windowEnd.getTime() < now.getTime() ? windowEnd : now
      if (Number.isNaN(eventStart.getTime()) || Number.isNaN(eventEnd.getTime()) || eventStart >= eventEnd) {
        throw new Error(t('admin.keyIpAudit.confirm.pastEventsOnly'))
      }
      const result = await createDismissal({
        key_id: keyId,
        ip: context.dismissal.ip,
        risk_code: context.dismissal.riskCode,
        event_start: eventStart.toISOString(),
        event_end: eventEnd.toISOString()
      }, { signal: controller.signal })
      dismissalId.value = result.id
    } else if (action === 'remove-dismissal') {
      if (context.dismissalId == null) return
      await removeDismissal(context.dismissalId, { signal: controller.signal })
      dismissalId.value = null
    }
    if (controller.signal.aborted || mutationController !== controller) return
    appStore.showSuccess(t('admin.keyIpAudit.confirm.success'))
    pendingTrusted.value = null
    const listWindow = currentWindow.value ?? resolveKeyAuditWindow(filters)
    const drawerWindow = detailWindow.value
    await Promise.all([
      loadList(listWindow),
      drawerWindow ? loadDetail(keyId, drawerWindow) : Promise.resolve()
    ])
  } catch (error: unknown) {
    if (controller.signal.aborted || isAbortError(error) || mutationController !== controller) return
    appStore.showError(extractApiErrorMessage(error, t('admin.keyIpAudit.confirm.failed')))
  } finally {
    if (mutationController === controller) {
      mutationController = null
      mutationBusy.value = false
    }
  }
}

function closeSecret(): void {
  newSecret.value = ''
  secretCopied.value = false
}

async function copySecret(): Promise<void> {
  if (!newSecret.value || !navigator.clipboard) return
  try {
    await navigator.clipboard.writeText(newSecret.value)
    secretCopied.value = true
    appStore.showSuccess(t('admin.keyIpAudit.secret.copied'))
  } catch {
    appStore.showError(t('common.copyFailed'))
  }
}

function formatTime(value: string | null | undefined): string {
  if (!value) return t('admin.keyIpAudit.unknownIp')
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function formatNumber(value: number | null | undefined): string {
  return new Intl.NumberFormat().format(value ?? 0)
}

function formatPercent(value: number | null): string {
  return value == null ? t('common.unknown') : `${value > 0 ? '+' : ''}${value.toFixed(1)}%`
}

function riskLabel(level: KeyRiskLevel): string { return t(`admin.keyIpAudit.risk.${level}`) }
function auditStatusLabel(status: string): string { return t(`admin.keyIpAudit.auditStatus.${status}`) }

function riskBadgeClass(level: KeyRiskLevel): string {
  const classes: Record<KeyRiskLevel, string> = {
    none: 'audit-badge bg-gray-100 text-gray-600 dark:bg-dark-800 dark:text-dark-300',
    low: 'audit-badge bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
    medium: 'audit-badge bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    high: 'audit-badge bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-300'
  }
  return classes[level]
}

function auditStatusBadgeClass(status: string): string {
  if (status === 'dismissed') return 'audit-badge bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
  if (status === 'open') return 'audit-badge bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
  return 'audit-badge bg-gray-100 text-gray-600 dark:bg-dark-800 dark:text-dark-300'
}

function requestChangeClass(value: number | null): string {
  if (value == null || value === 0) return 'text-gray-500 dark:text-dark-400'
  return value > 0 ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'
}

onMounted(refresh)

onBeforeUnmount(() => {
  listController?.abort()
  detailController?.abort()
  trustedController?.abort()
  mutationController?.abort()
  closeSecret()
})
</script>

<style scoped>
.summary-stat {
  @apply flex min-h-[88px] flex-col justify-center px-4 py-3 transition-colors sm:px-5;
}

.summary-label {
  @apply text-[11px] font-semibold uppercase tracking-wide text-gray-400 dark:text-dark-500;
}

.summary-value {
  @apply mt-1 text-xl font-semibold text-gray-900 dark:text-white;
}

.metadata-label {
  @apply text-gray-500 dark:text-dark-400;
}

.metadata-value {
  @apply mt-1 font-medium text-gray-800 dark:text-gray-200;
}

.audit-badge {
  @apply inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium;
}
</style>
