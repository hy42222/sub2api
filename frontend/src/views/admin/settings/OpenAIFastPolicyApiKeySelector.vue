<template>
  <div ref="containerRef" class="relative">
    <div v-if="selectedApiKeyIds.length > 0" class="mb-2 flex flex-wrap gap-2">
      <span
        v-for="apiKeyId in selectedApiKeyIds"
        :key="apiKeyId"
        class="inline-flex max-w-full items-center gap-1.5 rounded-md bg-gray-100 px-2.5 py-1.5 text-xs text-gray-700 dark:bg-dark-600 dark:text-gray-200"
      >
        <span class="max-w-64 truncate font-medium" :title="selectedApiKeyLabel(apiKeyId)">
          {{ selectedApiKeyLabel(apiKeyId) }}
        </span>
        <span class="shrink-0 text-gray-400">#{{ apiKeyId }}</span>
        <span v-if="selectedApiKeys[apiKeyId]?.user_id" class="shrink-0 text-gray-400">
          · {{ t("admin.settings.openaiFastPolicy.apiKeyUser", { id: selectedApiKeys[apiKeyId].user_id }) }}
        </span>
        <button
          type="button"
          class="shrink-0 rounded text-gray-400 hover:text-red-600 dark:hover:text-red-400"
          :aria-label="t('admin.settings.openaiFastPolicy.removeApiKey')"
          :title="t('admin.settings.openaiFastPolicy.removeApiKey')"
          @click="removeApiKey(apiKeyId)"
        >
          <Icon name="x" size="xs" :stroke-width="2" />
        </button>
      </span>
    </div>

    <div class="relative">
      <Icon
        name="search"
        size="sm"
        class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"
      />
      <input
        v-model="searchQuery"
        type="text"
        autocomplete="off"
        class="input input-sm w-full pl-9"
        :placeholder="t('admin.settings.openaiFastPolicy.apiKeySearchPlaceholder')"
        @input="debounceSearch"
        @focus="showDropdown = true"
      />
    </div>

    <div
      v-if="showDropdown && searchQuery.trim()"
      class="absolute z-50 mt-1 max-h-60 w-full overflow-auto rounded-lg border border-gray-200 bg-white shadow-lg dark:border-dark-600 dark:bg-dark-700"
    >
      <div v-if="searchLoading" class="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
        {{ t("common.loading") }}
      </div>
      <div
        v-else-if="availableResults.length === 0"
        class="px-4 py-3 text-sm text-gray-500 dark:text-gray-400"
      >
        {{ t("admin.settings.openaiFastPolicy.apiKeySearchEmpty") }}
      </div>
      <template v-else>
        <button
          v-for="apiKey in availableResults"
          :key="apiKey.id"
          type="button"
          class="flex w-full items-center justify-between gap-3 px-4 py-2 text-left text-sm hover:bg-gray-100 dark:hover:bg-dark-600"
          @click="selectApiKey(apiKey)"
        >
          <span class="min-w-0 truncate font-medium text-gray-900 dark:text-white">
            {{ apiKey.name || t("admin.settings.openaiFastPolicy.apiKeyIdFallback", { id: apiKey.id }) }}
          </span>
          <span class="shrink-0 text-xs text-gray-400">
            #{{ apiKey.id }} · {{ t("admin.settings.openaiFastPolicy.apiKeyUser", { id: apiKey.user_id }) }}
          </span>
        </button>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { adminAPI } from "@/api/admin";
import type { SimpleApiKey } from "@/api/admin/usage";
import Icon from "@/components/icons/Icon.vue";

const props = defineProps<{
  modelValue: number[];
}>();

const emit = defineEmits<{
  "update:modelValue": [value: number[]];
}>();

const { t } = useI18n();
const containerRef = ref<HTMLElement | null>(null);
const searchQuery = ref("");
const searchResults = ref<SimpleApiKey[]>([]);
const searchLoading = ref(false);
const showDropdown = ref(false);
const selectedApiKeys = ref<Record<number, SimpleApiKey>>({});
let searchTimer: ReturnType<typeof setTimeout> | null = null;
let searchSequence = 0;

const selectedApiKeyIds = computed(() =>
  Array.from(new Set(props.modelValue.filter((id) => Number.isInteger(id) && id > 0))),
);

const availableResults = computed(() => {
  const selected = new Set(selectedApiKeyIds.value);
  return searchResults.value.filter((apiKey) => !selected.has(apiKey.id));
});

function selectedApiKeyLabel(apiKeyId: number): string {
  return (
    selectedApiKeys.value[apiKeyId]?.name ||
    t("admin.settings.openaiFastPolicy.apiKeyIdFallback", { id: apiKeyId })
  );
}

function clearPendingSearch(): void {
  if (searchTimer) {
    clearTimeout(searchTimer);
    searchTimer = null;
  }
  searchSequence += 1;
}

function debounceSearch(): void {
  clearPendingSearch();
  const query = searchQuery.value.trim();
  showDropdown.value = true;
  if (!query) {
    searchResults.value = [];
    searchLoading.value = false;
    return;
  }

  const sequence = searchSequence;
  searchTimer = setTimeout(async () => {
    searchLoading.value = true;
    try {
      const results = await adminAPI.usage.searchApiKeys(undefined, query);
      if (sequence === searchSequence) {
        searchResults.value = results;
      }
    } catch {
      if (sequence === searchSequence) {
        searchResults.value = [];
      }
    } finally {
      if (sequence === searchSequence) {
        searchLoading.value = false;
      }
    }
  }, 300);
}

function selectApiKey(apiKey: SimpleApiKey): void {
  selectedApiKeys.value = { ...selectedApiKeys.value, [apiKey.id]: apiKey };
  emit("update:modelValue", [...selectedApiKeyIds.value, apiKey.id]);
  clearPendingSearch();
  searchQuery.value = "";
  searchResults.value = [];
  searchLoading.value = false;
  showDropdown.value = false;
}

function removeApiKey(apiKeyId: number): void {
  emit(
    "update:modelValue",
    selectedApiKeyIds.value.filter((id) => id !== apiKeyId),
  );
}

function handleDocumentClick(event: MouseEvent): void {
  const target = event.target as Node | null;
  if (target && !containerRef.value?.contains(target)) {
    showDropdown.value = false;
  }
}

onMounted(() => {
  document.addEventListener("click", handleDocumentClick);
});

onUnmounted(() => {
  clearPendingSearch();
  document.removeEventListener("click", handleDocumentClick);
});
</script>
