import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import OpenAIFastPolicyApiKeySelector from '../OpenAIFastPolicyApiKeySelector.vue'

const messages: Record<string, string> = {
  'admin.settings.openaiFastPolicy.apiKeyIdFallback': 'API key #{id}',
  'admin.settings.openaiFastPolicy.apiKeySearchPlaceholder': 'Search API keys',
  'admin.settings.openaiFastPolicy.apiKeySearchEmpty': 'No API keys found',
  'admin.settings.openaiFastPolicy.apiKeyUser': 'User #{id}',
  'admin.settings.openaiFastPolicy.removeApiKey': 'Remove API key',
  'common.loading': 'Loading',
}

vi.mock('vue-i18n', () => ({
  useI18n: () => ({
    t: (key: string, params?: Record<string, unknown>) => {
      const message = messages[key] ?? key
      return params
        ? Object.entries(params).reduce(
            (value, [name, replacement]) => value.replace(`{${name}}`, String(replacement)),
            message,
          )
        : message
    },
  }),
}))

const mockSearchApiKeys = vi.fn()

vi.mock('@/api/admin', () => ({
  adminAPI: {
    usage: {
      searchApiKeys: (...args: unknown[]) => mockSearchApiKeys(...args),
    },
  },
}))

describe('OpenAIFastPolicyApiKeySelector', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    mockSearchApiKeys.mockReset()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('searches API keys and emits the selected ID', async () => {
    mockSearchApiKeys.mockResolvedValue([
      { id: 11, name: 'codex-key', user_id: 7 },
    ])

    const wrapper = mount(OpenAIFastPolicyApiKeySelector, {
      props: { modelValue: [] },
      global: { stubs: { Icon: true } },
    })
    const input = wrapper.get('input')
    await input.trigger('focus')
    await input.setValue('codex')
    await input.trigger('input')
    vi.advanceTimersByTime(300)
    await flushPromises()

    expect(mockSearchApiKeys).toHaveBeenCalledWith(undefined, 'codex')
    const result = wrapper.findAll('button').find((button) =>
      button.text().includes('codex-key'),
    )
    expect(result).toBeDefined()
    await result!.trigger('click')

    expect(wrapper.emitted('update:modelValue')).toEqual([[[11]]])
  })

  it('keeps an unresolved saved ID visible and removable', async () => {
    const wrapper = mount(OpenAIFastPolicyApiKeySelector, {
      props: { modelValue: [42] },
      global: { stubs: { Icon: true } },
    })

    expect(wrapper.text()).toContain('API key #42')
    await wrapper.get('button[aria-label="Remove API key"]').trigger('click')
    expect(wrapper.emitted('update:modelValue')).toEqual([[[]]])
  })
})
