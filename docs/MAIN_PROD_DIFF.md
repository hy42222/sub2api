# main 和 prod 的差异

## 当前基线

- 更新日期：2026-09-20
- 同步来源：官方正式版 v0.2.7，发布于 2026-09-19；tag commit aea725f2ea644d5592d0bbb1d63b607efa7e200a。
- main：aea725f2ea644d5592d0bbb1d63b607efa7e200a（v0.2.7）。
- 同步时的 upstream/main：d2e319b2a17006122cd2d53d828c44a0bf21bd9b，比 release tag 多 23 个提交；本次按“最新发布版”要求有意不包含这些未发布提交。
- prod 合并快照：3189c094144cb0eba50036ef7973d11836855896。
- 本次同步 merge：3189c094144cb0eba50036ef7973d11836855896（merge: sync upstream release v0.2.7 into prod）。
- merge parents：旧 prod 00aa08ccb1a7d7c684157cf03e49881e0d297a87，release baseline main aea725f2ea644d5592d0bbb1d63b607efa7e200a。

main 已快进到发布 tag，prod 通过显式 merge 接入该 release；main 是 prod 的祖先。以下提交和文件清单以合并快照 3189c094 为准；本次后续的文档/skill 维护提交不属于产品功能差异。

## prod 专属提交

| 能力 | 提交 | 说明 |
| --- | --- | --- |
| API Key 与安全审计 | e32f904ce, 58ef0a788, 3b68d9746, 7bd41f6b5, 91e80b6c4, 1de3c512b | Key/IP 安全审计、用户重新生成 Key、管理员跨用户查看与管理 Key、按公开注册设置控制注册入口。 |
| 生产部署 | c764bd90a, e852f9b9a, cf6934b69, 4cf71aa73, 7b4c30b51, 4a4dd2b66, 2ab1b92dd, 2993b6382, 96b6e92e6 | 生产 originator、Caddy、Docker Compose、备份、健康检查、防火墙恢复、镜像版本及构建缓存配置。 |
| OpenAI/Codex 身份与指纹 | 781e00424, 06fd20a33, 0c99fe71c, 7d7c4d9b0, ddb2c8868, c08f22cda, 90c54d0a4, dbb0c2be6 | OAuth 身份与版本、metadata 隔离、指纹池、续链 ID 和搜索端点兼容。 |
| OpenAI/Codex 链路与观测 | 00aa08ccb, bb8ab7b4b, 315b88aaa, 1c005ee1b, 05441539d, b4ad0d2ca, 70218dd44, bfe7be6a2, a26f68510, e37e01b5f | Fast 策略按 API Key 生效、usage log 记录 Codex turn 状态、原生压缩与隐私重试，以及 tool_search、心跳和错误响应修复。 |
| 管理策略与账户维护 | bac750c58, dcb641ae5 | Fast/Flex 策略支持搜索用户；账户重新认证时刷新过期时间。 |
| 测试与同步资料 | 0465d7526, 67304aa37, 995734249, 9a28272b0, f87ad620c | OAuth 测试对齐上游 canonical Codex 身份，维护同步流程和差异基线文档。 |

以下是该合并快照的 git log --no-merges --format='%h %s' main..prod。同步 merge 历史不列为产品功能：

    00aa08ccb feat: scope OpenAI fast policy by API key
    bb8ab7b4b feat: expose Codex turn state in usage logs
    e32f904ce feat: add admin key and IP security audit
    67304aa37 docs: refresh prod difference baseline
    0465d7526 test: align OAuth assertions with canonical Codex identity
    58ef0a788 feat: support regenerating user API keys
    96b6e92e6 chore(docker): exclude root pnpm cache from builds
    a26f68510 fix(merge): restore codex runtime and upstream audit definitions
    3b68d9746 fix(admin): allow admins to change API key groups
    2993b6382 chore(deploy): use v0.1.170 production image
    315b88aaa fix(openai): retry privacy opt-out through active proxies
    b278ad3e2 feat: add Codex fingerprint persona pool
    2ab1b92dd fix(deploy): update production image and Redis auth
    4a4dd2b66 chore(deploy): use v0.1.161 production image
    7b4c30b51 chore(deploy): use v0.1.159 production image
    4cf71aa73 chore(deploy): use v0.1.157 production image
    cf6934b69 chore(deploy): use v0.1.156 production image
    e852f9b9a style(deploy): format production Caddyfile
    995734249 docs: refresh prod baseline for v0.1.156
    7bd41f6b5 feat(prod): secure registration and admin API key management
    91e80b6c4 fix: admin can edit any API key group
    dcb641ae5 fix: auto-refresh expires_at on account update (re-auth)
    dbb0c2be6 fix(openai): 转发 Codex alpha/search 独立搜索端点
    90c54d0a4 fix(openai): restore Codex identity for OAuth Messages
    1c005ee1b fix: 保留 remote_compaction_v2 原生 Responses 链路
    05441539d fix(service): guard compact keepalive writer delegates
    b4ad0d2ca 关联上游 issue #3818 #3887 #3961
    70218dd44 修复 compact 心跳 writer 生命周期
    bfe7be6a2 修复 tool_search 参数对象反序列化
    bac750c58 feat(frontend): Fast/Flex 策略支持搜索选择用户
    c08f22cda fix(codex): 剥离续链 message item 的非法 item_* id
    9a28272b0 docs: refresh prod difference baseline
    06fd20a33 fix: unify Codex OAuth version
    f87ad620c docs: add upstream sync workflow
    e37e01b5f fix: detect already-written error responses from handleErrorResponse
    0c99fe71c feat: workspace fingerprint pool with idle eviction and UI-configurable timeout
    ddb2c8868 feat: re-salt x-codex-turn-metadata after session_id UUID override in ForwardAsAnthropic
    7d7c4d9b0 feat: salt x-codex-turn-metadata for cross-account fingerprint isolation
    1de3c512b feat: admin can view all API keys across all users
    781e00424 feat: auto-config UA/originator/expiry for new OpenAI OAuth accounts
    c764bd90a feat: originator server-side override + production deployment config

## 当前树差异

以下状态和路径对应 git diff --name-status main..prod。包含本次文档/skill 更新后的统计为 127 个文件、8788 行新增、221 行删除；本次维护仅更新下列既有文档路径。

    M	.dockerignore
    M	.gitignore
    M	backend/cmd/server/wire_gen.go
    M	backend/ent/migrate/schema.go
    M	backend/ent/mutation.go
    M	backend/ent/runtime/runtime.go
    M	backend/ent/schema/usage_log.go
    M	backend/ent/usagelog.go
    M	backend/ent/usagelog/usagelog.go
    M	backend/ent/usagelog/where.go
    M	backend/ent/usagelog_create.go
    M	backend/ent/usagelog_update.go
    A	backend/internal/handler/admin/key_ip_audit_handler.go
    M	backend/internal/handler/admin/usage_handler.go
    A	backend/internal/handler/admin/usage_handler_codex_turn_state_test.go
    M	backend/internal/handler/api_key_handler.go
    M	backend/internal/handler/dto/mappers.go
    M	backend/internal/handler/dto/settings.go
    M	backend/internal/handler/dto/types.go
    M	backend/internal/handler/handler.go
    M	backend/internal/handler/openai_gateway_handler.go
    M	backend/internal/handler/wire.go
    M	backend/internal/pkg/ctxkey/ctxkey.go
    M	backend/internal/pkg/openai/constants.go
    M	backend/internal/repository/api_key_repo.go
    M	backend/internal/repository/api_key_repo_integration_test.go
    A	backend/internal/repository/key_ip_audit_repo.go
    A	backend/internal/repository/key_ip_audit_repo_integration_test.go
    M	backend/internal/repository/usage_log_repo_insert.go
    M	backend/internal/repository/usage_log_repo_query.go
    M	backend/internal/repository/usage_log_repo_request_type_test.go
    M	backend/internal/repository/wire.go
    M	backend/internal/server/api_contract_test.go
    M	backend/internal/server/middleware/api_key_auth.go
    M	backend/internal/server/middleware/api_key_auth_google.go
    M	backend/internal/server/middleware/api_key_auth_google_test.go
    M	backend/internal/server/middleware/api_key_auth_test.go
    M	backend/internal/server/middleware/audit_log.go
    M	backend/internal/server/middleware/openai_fast_policy_forwarding_test.go
    M	backend/internal/server/routes/admin.go
    A	backend/internal/server/routes/key_ip_audit_routes_test.go
    A	backend/internal/server/routes/usage_codex_turn_state_routes_test.go
    M	backend/internal/server/routes/user.go
    M	backend/internal/service/admin_account.go
    M	backend/internal/service/api_key_service.go
    M	backend/internal/service/api_key_service_delete_test.go
    A	backend/internal/service/api_key_service_regenerate_test.go
    A	backend/internal/service/key_ip_audit.go
    A	backend/internal/service/key_ip_audit_test.go
    M	backend/internal/service/openai_alpha_search.go
    M	backend/internal/service/openai_alpha_search_test.go
    M	backend/internal/service/openai_codex_turn_state.go
    M	backend/internal/service/openai_codex_turn_state_test.go
    M	backend/internal/service/openai_fast_policy_test.go
    M	backend/internal/service/openai_gateway_chat_completions.go
    M	backend/internal/service/openai_gateway_forward.go
    M	backend/internal/service/openai_gateway_messages.go
    M	backend/internal/service/openai_gateway_passthrough.go
    M	backend/internal/service/openai_gateway_request_body.go
    M	backend/internal/service/openai_gateway_service.go
    M	backend/internal/service/openai_gateway_usage.go
    M	backend/internal/service/openai_images_responses.go
    M	backend/internal/service/openai_oauth_service.go
    M	backend/internal/service/openai_privacy_retry_test.go
    M	backend/internal/service/openai_privacy_service.go
    M	backend/internal/service/openai_ws_forwarder_ingress.go
    M	backend/internal/service/openai_ws_forwarder_v2.go
    M	backend/internal/service/openai_ws_http_bridge.go
    M	backend/internal/service/openai_ws_v2_passthrough_adapter.go
    M	backend/internal/service/setting_features.go
    M	backend/internal/service/setting_gateway_runtime.go
    M	backend/internal/service/settings_view.go
    M	backend/internal/service/token_refresh_service.go
    M	backend/internal/service/usage_log.go
    M	backend/internal/service/wire.go
    A	backend/migrations/235_key_ip_audit.sql
    A	backend/migrations/236_key_ip_audit_usage_log_indexes_notx.sql
    A	backend/migrations/239_add_usage_log_codex_turn_state.sql
    M	deploy/Caddyfile
    A	deploy/backup.sh
    A	deploy/check-production.sh
    A	deploy/docker-compose.prod.yml
    A	deploy/iptables-restore.service
    A	docs/MAIN_PROD_DIFF.md
    A	frontend/src/api/__tests__/admin.keyIpAudit.spec.ts
    A	frontend/src/api/__tests__/keys.spec.ts
    M	frontend/src/api/admin/apiKeys.ts
    M	frontend/src/api/admin/index.ts
    A	frontend/src/api/admin/keyIpAudit.ts
    M	frontend/src/api/admin/settings.ts
    M	frontend/src/api/admin/usage.ts
    M	frontend/src/api/admin/users.ts
    M	frontend/src/api/keys.ts
    M	frontend/src/components/account/CreateAccountModal.vue
    A	frontend/src/components/admin/KeyIpAuditDrawer.vue
    M	frontend/src/components/admin/usage/UsageTable.vue
    M	frontend/src/components/admin/usage/__tests__/UsageTable.spec.ts
    M	frontend/src/components/admin/user/UserApiKeysModal.vue
    M	frontend/src/components/layout/AppSidebar.vue
    A	frontend/src/features/key-ip-audit/types.ts
    A	frontend/src/features/key-ip-audit/viewModel.ts
    M	frontend/src/i18n/locales/en/admin/accounts.ts
    M	frontend/src/i18n/locales/en/admin/index.ts
    A	frontend/src/i18n/locales/en/admin/keyIpAudit.ts
    M	frontend/src/i18n/locales/en/admin/resources.ts
    M	frontend/src/i18n/locales/en/admin/settings.ts
    M	frontend/src/i18n/locales/en/common.ts
    M	frontend/src/i18n/locales/en/dashboard.ts
    M	frontend/src/i18n/locales/zh/admin/accounts.ts
    M	frontend/src/i18n/locales/zh/admin/index.ts
    A	frontend/src/i18n/locales/zh/admin/keyIpAudit.ts
    M	frontend/src/i18n/locales/zh/admin/resources.ts
    M	frontend/src/i18n/locales/zh/admin/settings.ts
    M	frontend/src/i18n/locales/zh/common.ts
    M	frontend/src/i18n/locales/zh/dashboard.ts
    M	frontend/src/router/index.ts
    M	frontend/src/types/index.ts
    A	frontend/src/views/admin/KeyIpAuditView.vue
    M	frontend/src/views/admin/SettingsView.vue
    M	frontend/src/views/admin/UsageView.vue
    M	frontend/src/views/admin/__tests__/SettingsView.spec.ts
    A	frontend/src/views/admin/settings/OpenAIFastPolicyApiKeySelector.vue
    A	frontend/src/views/admin/settings/__tests__/OpenAIFastPolicyApiKeySelector.spec.ts
    M	frontend/src/views/user/KeysView.vue
    M	frontend/src/views/user/__tests__/KeysView.spec.ts
    A	skills/sub2api-upstream-sync/SKILL.md
    A	skills/sub2api-upstream-sync/agents/openai.yaml

## 后续同步

- 请求同步 upstream 开发分支时，将本地 main 快进到 upstream/main 后再合并到 prod。
- 请求同步最新正式发布版时，将本地 main 快进到 GitHub 最新 release tag；不要把 tag 之后的开发提交一并合入。
- 每次合并后重新记录 release/branch 来源、SHA、merge 及 parents、main..prod 非 merge 提交和完整文件状态；相关步骤见 skills/sub2api-upstream-sync/SKILL.md。
