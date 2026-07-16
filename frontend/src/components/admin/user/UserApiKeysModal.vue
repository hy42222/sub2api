<template>
  <BaseDialog :show="show" :title="t('admin.users.userApiKeys')" width="wide" @close="handleClose">
    <div v-if="user" class="space-y-4">
      <div class="flex items-center gap-3 rounded-xl bg-gray-50 p-4 dark:bg-dark-700">
        <div class="flex h-10 w-10 items-center justify-center rounded-full bg-primary-100 dark:bg-primary-900/30">
          <span class="text-lg font-medium text-primary-700 dark:text-primary-300">{{ user.email.charAt(0).toUpperCase() }}</span>
        </div>
        <div><p class="font-medium text-gray-900 dark:text-white">{{ user.email }}</p><p class="text-sm text-gray-500 dark:text-dark-400">{{ user.username }}</p></div>
      </div>
      <form v-if="editingKey" class="space-y-4" @submit.prevent="saveEdit">
        <div class="grid gap-4 sm:grid-cols-2">
          <div>
            <label class="input-label">{{ t('keys.nameLabel') }}</label>
            <input v-model.trim="editForm.name" class="input" required maxlength="100" />
          </div>
          <div>
            <label class="input-label">{{ t('keys.statusLabel') }}</label>
            <select v-model="editForm.status" class="input">
              <option value="">{{ t(`keys.status.${editingKey.status}`) }}</option>
              <option value="active">{{ t('keys.status.active') }}</option>
              <option value="inactive">{{ t('keys.status.inactive') }}</option>
            </select>
          </div>
          <div>
            <label class="input-label">{{ t('keys.groupLabel') }}</label>
            <select v-model.number="editForm.groupId" class="input">
              <option :value="0">{{ t('keys.noGroup') }}</option>
              <option v-for="group in allGroups" :key="group.id" :value="group.id">{{ group.name }}</option>
            </select>
          </div>
          <div>
            <label class="input-label">{{ t('keys.quotaAmount') }}</label>
            <input v-model.number="editForm.quota" class="input" type="number" min="0" step="0.000001" />
          </div>
          <div class="sm:col-span-2">
            <label class="input-label">{{ t('keys.expirationDate') }}</label>
            <input v-model="editForm.expiresAt" class="input" type="datetime-local" />
          </div>
          <div>
            <label class="input-label">{{ t('keys.ipWhitelist') }}</label>
            <textarea v-model="editForm.ipWhitelist" class="input min-h-24 font-mono text-sm" :placeholder="t('keys.ipWhitelistPlaceholder')"></textarea>
          </div>
          <div>
            <label class="input-label">{{ t('keys.ipBlacklist') }}</label>
            <textarea v-model="editForm.ipBlacklist" class="input min-h-24 font-mono text-sm" :placeholder="t('keys.ipBlacklistPlaceholder')"></textarea>
          </div>
          <div>
            <label class="input-label">{{ t('keys.rateLimit5h') }}</label>
            <input v-model.number="editForm.rateLimit5h" class="input" type="number" min="0" step="0.000001" />
          </div>
          <div>
            <label class="input-label">{{ t('keys.rateLimit1d') }}</label>
            <input v-model.number="editForm.rateLimit1d" class="input" type="number" min="0" step="0.000001" />
          </div>
          <div>
            <label class="input-label">{{ t('keys.rateLimit7d') }}</label>
            <input v-model.number="editForm.rateLimit7d" class="input" type="number" min="0" step="0.000001" />
          </div>
        </div>
        <div class="flex justify-end gap-3 border-t border-gray-200 pt-4 dark:border-dark-600">
          <button type="button" class="btn-secondary" :disabled="saving" @click="cancelEdit">{{ t('common.cancel') }}</button>
          <button type="submit" class="btn-primary" :disabled="saving || !editForm.name">
            {{ saving ? t('keys.saving') : t('common.save') }}
          </button>
        </div>
      </form>
      <div v-else-if="loading" class="flex justify-center py-8"><svg class="h-8 w-8 animate-spin text-primary-500" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg></div>
      <div v-else-if="apiKeys.length === 0" class="py-8 text-center"><p class="text-sm text-gray-500">{{ t('admin.users.noApiKeys') }}</p></div>
      <div v-else ref="scrollContainerRef" class="max-h-96 space-y-3 overflow-y-auto" @scroll="closeGroupSelector">
        <div v-for="key in apiKeys" :key="key.id" class="rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-600 dark:bg-dark-800">
          <div class="flex items-start justify-between">
            <div class="min-w-0 flex-1">
              <div class="mb-1 flex items-center gap-2"><span class="font-medium text-gray-900 dark:text-white">{{ key.name }}</span><span :class="['badge text-xs', key.status === 'active' ? 'badge-success' : 'badge-danger']">{{ key.status }}</span></div>
              <p class="truncate font-mono text-sm text-gray-500">{{ key.key.substring(0, 20) }}...{{ key.key.substring(key.key.length - 8) }}</p>
            </div>
            <div class="ml-3 flex shrink-0 items-center gap-1">
              <button class="icon-btn" type="button" :title="t('keys.editKey')" @click="startEdit(key)">
                <Icon name="edit" size="sm" />
              </button>
              <button class="icon-btn text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20" type="button" :title="t('keys.deleteKey')" @click="deletingKey = key">
                <Icon name="trash" size="sm" />
              </button>
            </div>
          </div>
          <div class="mt-3 flex flex-wrap gap-4 text-xs text-gray-500">
            <div class="flex items-center gap-1">
              <span>{{ t('admin.users.group') }}:</span>
              <button
                :ref="(el) => setGroupButtonRef(key.id, el)"
                @click="openGroupSelector(key)"
                class="-mx-1 -my-0.5 flex cursor-pointer items-center gap-1 rounded-md px-1 py-0.5 transition-colors hover:bg-gray-100 dark:hover:bg-dark-700"
                :disabled="updatingKeyIds.has(key.id)"
              >
                <GroupBadge
                  v-if="key.group_id && key.group"
                  :name="key.group.name"
                  :platform="key.group.platform"
                  :subscription-type="key.group.subscription_type"
                  :rate-multiplier="key.group.rate_multiplier"
                  :peak-rate-enabled="key.group.peak_rate_enabled"
                  :peak-start="key.group.peak_start"
                  :peak-end="key.group.peak_end"
                  :peak-rate-multiplier="key.group.peak_rate_multiplier"
                />
                <span v-else class="text-gray-400 italic">{{ t('admin.users.none') }}</span>
                <svg v-if="updatingKeyIds.has(key.id)" class="h-3 w-3 animate-spin text-primary-500" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                <svg v-else class="h-3 w-3 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8.25 15L12 18.75 15.75 15m-7.5-6L12 5.25 15.75 9" /></svg>
              </button>
            </div>
            <div class="flex items-center gap-1"><span>{{ t('admin.users.columns.created') }}: {{ formatDateTime(key.created_at) }}</span></div>
          </div>
        </div>
      </div>
    </div>
  </BaseDialog>

  <!-- Group Selector Dropdown -->
  <Teleport to="body">
    <div
      v-if="groupSelectorKeyId !== null && dropdownPosition"
      ref="dropdownRef"
      class="animate-in fade-in slide-in-from-top-2 fixed z-[100000020] w-64 overflow-hidden rounded-xl bg-white shadow-lg ring-1 ring-black/5 duration-200 dark:bg-dark-800 dark:ring-white/10"
      :style="{ top: dropdownPosition.top + 'px', left: dropdownPosition.left + 'px' }"
    >
      <div class="max-h-64 overflow-y-auto p-1.5">
        <!-- Unbind option -->
        <button
          @click="changeGroup(selectedKeyForGroup!, null)"
          :class="[
            'flex w-full items-center rounded-lg px-3 py-2 text-sm transition-colors',
            !selectedKeyForGroup?.group_id
              ? 'bg-primary-50 dark:bg-primary-900/20'
              : 'hover:bg-gray-100 dark:hover:bg-dark-700'
          ]"
        >
          <span class="text-gray-500 italic">{{ t('admin.users.none') }}</span>
          <svg
            v-if="!selectedKeyForGroup?.group_id"
            class="ml-auto h-4 w-4 shrink-0 text-primary-600 dark:text-primary-400"
            fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"
          ><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" /></svg>
        </button>
        <!-- Group options -->
        <button
          v-for="group in allGroups"
          :key="group.id"
          @click="changeGroup(selectedKeyForGroup!, group.id)"
          :class="[
            'flex w-full items-center justify-between rounded-lg px-3 py-2 text-sm transition-colors',
            selectedKeyForGroup?.group_id === group.id
              ? 'bg-primary-50 dark:bg-primary-900/20'
              : 'hover:bg-gray-100 dark:hover:bg-dark-700'
          ]"
        >
          <GroupOptionItem
            :name="group.name"
            :platform="group.platform"
            :subscription-type="group.subscription_type"
            :rate-multiplier="group.rate_multiplier"
            :peak-rate-enabled="group.peak_rate_enabled"
            :peak-start="group.peak_start"
            :peak-end="group.peak_end"
            :peak-rate-multiplier="group.peak_rate_multiplier"
            :description="group.description"
            :selected="selectedKeyForGroup?.group_id === group.id"
          />
        </button>
      </div>
    </div>
  </Teleport>

  <ConfirmDialog
    :show="deletingKey !== null"
    :title="t('keys.deleteKey')"
    :message="t('keys.deleteConfirmMessage', { name: deletingKey?.name || '' })"
    :confirm-text="t('common.delete')"
    danger
    @confirm="confirmDelete"
    @cancel="deletingKey = null"
  />
</template>

<script setup lang="ts">
import { ref, reactive, computed, watch, onMounted, onUnmounted, type ComponentPublicInstance } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAppStore } from '@/stores/app'
import { adminAPI } from '@/api/admin'
import { formatDateTime } from '@/utils/format'
import type { AdminUser, AdminGroup, ApiKey, UpdateApiKeyRequest } from '@/types'
import BaseDialog from '@/components/common/BaseDialog.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import GroupBadge from '@/components/common/GroupBadge.vue'
import GroupOptionItem from '@/components/common/GroupOptionItem.vue'
import Icon from '@/components/icons/Icon.vue'

const props = defineProps<{ show: boolean; user: AdminUser | null }>()
const emit = defineEmits(['close'])
const { t } = useI18n()
const appStore = useAppStore()

const apiKeys = ref<ApiKey[]>([])
const allGroups = ref<AdminGroup[]>([])
const loading = ref(false)
const saving = ref(false)
const editingKey = ref<ApiKey | null>(null)
const deletingKey = ref<ApiKey | null>(null)
const updatingKeyIds = ref(new Set<number>())
const groupSelectorKeyId = ref<number | null>(null)
const dropdownPosition = ref<{ top: number; left: number } | null>(null)
const dropdownRef = ref<HTMLElement | null>(null)
const scrollContainerRef = ref<HTMLElement | null>(null)
const groupButtonRefs = ref<Map<number, HTMLElement>>(new Map())
const editForm = reactive({
  name: '',
  status: '' as '' | 'active' | 'inactive',
  groupId: 0,
  quota: 0,
  expiresAt: '',
  ipWhitelist: '',
  ipBlacklist: '',
  rateLimit5h: 0,
  rateLimit1d: 0,
  rateLimit7d: 0
})

const selectedKeyForGroup = computed(() => {
  if (groupSelectorKeyId.value === null) return null
  return apiKeys.value.find((k) => k.id === groupSelectorKeyId.value) || null
})

const setGroupButtonRef = (keyId: number, el: Element | ComponentPublicInstance | null) => {
  if (el instanceof HTMLElement) {
    groupButtonRefs.value.set(keyId, el)
  } else {
    groupButtonRefs.value.delete(keyId)
  }
}

watch(() => props.show, (v) => {
  if (v && props.user) {
    load()
    loadGroups()
  } else {
    closeGroupSelector()
    cancelEdit()
    deletingKey.value = null
  }
})

const load = async () => {
  if (!props.user) return
  loading.value = true
  groupButtonRefs.value.clear()
  try {
    const res = await adminAPI.users.getUserApiKeys(props.user.id)
    apiKeys.value = res.items || []
  } catch (error) {
    console.error('Failed to load API keys:', error)
  } finally {
    loading.value = false
  }
}

const loadGroups = async () => {
  try {
    const groups = await adminAPI.groups.getAll()
    allGroups.value = groups
  } catch (error) {
    console.error('Failed to load groups:', error)
  }
}

const DROPDOWN_HEIGHT = 272 // max-h-64 = 16rem = 256px + padding
const DROPDOWN_GAP = 4

const openGroupSelector = (key: ApiKey) => {
  if (groupSelectorKeyId.value === key.id) {
    closeGroupSelector()
  } else {
    const buttonEl = groupButtonRefs.value.get(key.id)
    if (buttonEl) {
      const rect = buttonEl.getBoundingClientRect()
      const spaceBelow = window.innerHeight - rect.bottom
      const openUpward = spaceBelow < DROPDOWN_HEIGHT && rect.top > spaceBelow
      dropdownPosition.value = {
        top: openUpward ? rect.top - DROPDOWN_HEIGHT - DROPDOWN_GAP : rect.bottom + DROPDOWN_GAP,
        left: rect.left
      }
    }
    groupSelectorKeyId.value = key.id
  }
}

const closeGroupSelector = () => {
  groupSelectorKeyId.value = null
  dropdownPosition.value = null
}

const changeGroup = async (key: ApiKey, newGroupId: number | null) => {
  closeGroupSelector()
  if (key.group_id === newGroupId || (!key.group_id && newGroupId === null)) return

  updatingKeyIds.value.add(key.id)
  try {
    const result = await adminAPI.apiKeys.updateApiKeyGroup(key.id, newGroupId)
    // Update local data
    const idx = apiKeys.value.findIndex((k) => k.id === key.id)
    if (idx !== -1) {
      apiKeys.value[idx] = result.api_key
    }
    if (result.auto_granted_group_access && result.granted_group_name) {
      appStore.showSuccess(t('admin.users.groupChangedWithGrant', { group: result.granted_group_name }))
    } else {
      appStore.showSuccess(t('admin.users.groupChangedSuccess'))
    }
  } catch (error: any) {
    appStore.showError(error?.message || t('admin.users.groupChangeFailed'))
  } finally {
    updatingKeyIds.value.delete(key.id)
  }
}

const toLocalDateTimeValue = (value: string | null): string => {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16)
}

const parseIPLines = (value: string): string[] =>
  value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)

const startEdit = (key: ApiKey) => {
  closeGroupSelector()
  editingKey.value = key
  editForm.name = key.name
  editForm.status = key.status === 'active' || key.status === 'inactive' ? key.status : ''
  editForm.groupId = key.group_id || 0
  editForm.quota = key.quota || 0
  editForm.expiresAt = toLocalDateTimeValue(key.expires_at)
  editForm.ipWhitelist = (key.ip_whitelist || []).join('\n')
  editForm.ipBlacklist = (key.ip_blacklist || []).join('\n')
  editForm.rateLimit5h = key.rate_limit_5h || 0
  editForm.rateLimit1d = key.rate_limit_1d || 0
  editForm.rateLimit7d = key.rate_limit_7d || 0
}

const cancelEdit = () => {
  editingKey.value = null
  saving.value = false
}

const saveEdit = async () => {
  const key = editingKey.value
  if (!key || !editForm.name.trim()) return

  saving.value = true
  try {
    const updates: UpdateApiKeyRequest = {
      name: editForm.name.trim(),
      ip_whitelist: parseIPLines(editForm.ipWhitelist),
      ip_blacklist: parseIPLines(editForm.ipBlacklist),
      quota: Number(editForm.quota) || 0,
      expires_at: editForm.expiresAt ? new Date(editForm.expiresAt).toISOString() : '',
      rate_limit_5h: Number(editForm.rateLimit5h) || 0,
      rate_limit_1d: Number(editForm.rateLimit1d) || 0,
      rate_limit_7d: Number(editForm.rateLimit7d) || 0
    }
    if (editForm.status) updates.status = editForm.status

    let updated = await adminAPI.apiKeys.updateApiKey(key.id, updates)
    const nextGroupID = editForm.groupId || null
    if (nextGroupID !== key.group_id) {
      const groupResult = await adminAPI.apiKeys.updateApiKeyGroup(key.id, nextGroupID)
      updated = groupResult.api_key
    }

    const index = apiKeys.value.findIndex((item) => item.id === key.id)
    if (index !== -1) apiKeys.value[index] = updated
    appStore.showSuccess(t('keys.keyUpdatedSuccess'))
    editingKey.value = null
  } catch (error: any) {
    appStore.showError(error?.message || t('keys.failedToSave'))
  } finally {
    saving.value = false
  }
}

const confirmDelete = async () => {
  const key = deletingKey.value
  if (!key) return
  try {
    await adminAPI.apiKeys.deleteApiKey(key.id)
    apiKeys.value = apiKeys.value.filter((item) => item.id !== key.id)
    appStore.showSuccess(t('keys.keyDeletedSuccess'))
    deletingKey.value = null
  } catch (error: any) {
    appStore.showError(error?.message || t('keys.failedToDelete'))
  }
}

const handleKeyDown = (event: KeyboardEvent) => {
  if (event.key === 'Escape' && groupSelectorKeyId.value !== null) {
    event.stopPropagation()
    closeGroupSelector()
  }
}

const handleClickOutside = (event: MouseEvent) => {
  const target = event.target as HTMLElement
  if (dropdownRef.value && !dropdownRef.value.contains(target)) {
    // Check if the click is on one of the group trigger buttons
    for (const el of groupButtonRefs.value.values()) {
      if (el.contains(target)) return
    }
    closeGroupSelector()
  }
}

const handleClose = () => {
  closeGroupSelector()
  cancelEdit()
  deletingKey.value = null
  emit('close')
}

onMounted(() => {
  document.addEventListener('click', handleClickOutside)
  document.addEventListener('keydown', handleKeyDown, true)
})

onUnmounted(() => {
  document.removeEventListener('click', handleClickOutside)
  document.removeEventListener('keydown', handleKeyDown, true)
})
</script>
