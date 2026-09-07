# main 和 prod 的差异

## 当前基线

- 更新日期：2026-09-07
- `main`：`ab99d56e9626e6cd731592dae8553c9758a0efa2`（`chore: sync VERSION to 0.2.1 [skip ci]`）
- `prod`：`0465d752607b560ead602ad1fda97a96f103f6e0`（`test: align OAuth assertions with canonical Codex identity`）
- 本次同步来源：`upstream/main`，包含上游 `v0.2.1` 及其后的版本同步提交。
- 本次同步 merge：`7f3e073de731aced9ffc54b285820528bf5397da`（`merge: sync upstream main into prod`）。
- 本次 merge 的父提交：旧 `prod` `5c6c4c497cc6f5c40f74928578ec8fc27868878f`，新 `main` `ab99d56e9626e6cd731592dae8553c9758a0efa2`。

`main` 已快进到 `upstream/main`，`prod` 通过显式 merge 保留生产分支历史。`main` 是 `prod` 的祖先；后续比较使用 `main..prod`，只描述当前仍存在的生产专属树差异。

## prod 专属提交

以下是 `git log --no-merges main..prod` 的完整结果。历史同步 merge 提交不列入功能清单；同一能力下的提交按行为归组。

| 能力 | 提交 | 说明 |
| --- | --- | --- |
| API Key 与账户管理 | `1de3c512`, `91e80b6c`, `3b68d9746`, `7bd41f6b`, `58ef0a788` | 管理员查看、编辑、分组、删除任意用户 API Key；支持用户重新生成 API Key；按公开注册设置控制注册入口。 |
| 生产部署与发布 | `c764bd90`, `e852f9b9`, `cf6934b69`, `4cf71aa73`, `7b4c30b51`, `4a4dd2b66`, `2ab1b92dd`, `2993b6382`, `96b6e92e6` | 生产环境 originator、Caddy、Docker Compose、备份、健康检查、防火墙恢复、镜像版本和构建缓存配置。 |
| OpenAI/Codex 身份与指纹 | `781e00424`, `06fd20a33`, `7d7c4d9b0`, `ddb2c8868`, `0c99fe71c`, `c08f22cda`, `90c54d0a4`, `dbb0c2be6` | 新 OAuth 账户默认身份和过期时间、OAuth 版本统一、跨账户 metadata 加盐、指纹池淘汰、续链 ID、OAuth 身份和搜索端点兼容。 |
| OpenAI/Codex 链路稳定性 | `1c005ee1b`, `05441539d`, `70218dd44`, `bfe7be6a2`, `b4ad0d2ca`, `315b88aaa`, `a26f68510` | 保留原生压缩、修复心跳 writer 和 tool_search 参数、跟进上游相关 issue、隐私退出重试及 Codex runtime/audit 定义。 |
| 管理端策略与运维 | `bac750c58`, `dcb641ae5`, `e37e01b5f` | Fast/Flex 策略按用户搜索、重新认证刷新过期时间、避免错误响应重复写入。 |
| 测试基线兼容 | `0465d7526` | 将 OAuth 测试断言对齐到上游的 canonical Codex 身份，覆盖动态 `originator + User-Agent` 行为。 |
| 同步维护资料 | `f87ad620c`, `995734249`, `9a28272b0` | 上游同步 skill 及 main/prod 差异文档的历史维护。 |

完整的非 merge 提交序列如下：

```text
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
```

## 当前树差异

以下内容对应 `git diff --name-status main..prod`，用于定位当前实际不同于上游的文件：

```text
M .dockerignore
M .gitignore
M backend/internal/handler/api_key_handler.go
M backend/internal/handler/openai_gateway_handler.go
M backend/internal/pkg/openai/constants.go
M backend/internal/repository/api_key_repo.go
M backend/internal/repository/api_key_repo_integration_test.go
M backend/internal/server/api_contract_test.go
M backend/internal/server/middleware/audit_log.go
M backend/internal/server/routes/user.go
M backend/internal/service/admin_account.go
M backend/internal/service/api_key_service.go
M backend/internal/service/api_key_service_delete_test.go
A backend/internal/service/api_key_service_regenerate_test.go
M backend/internal/service/openai_gateway_service.go
M backend/internal/service/openai_oauth_service.go
M backend/internal/service/openai_privacy_retry_test.go
M backend/internal/service/openai_privacy_service.go
M backend/internal/service/setting_gateway_runtime.go
M backend/internal/service/token_refresh_service.go
M deploy/Caddyfile
A deploy/backup.sh
A deploy/check-production.sh
A deploy/docker-compose.prod.yml
A deploy/iptables-restore.service
A docs/MAIN_PROD_DIFF.md
A frontend/src/api/__tests__/keys.spec.ts
M frontend/src/api/admin/apiKeys.ts
M frontend/src/api/admin/users.ts
M frontend/src/api/keys.ts
M frontend/src/components/account/CreateAccountModal.vue
M frontend/src/components/admin/user/UserApiKeysModal.vue
M frontend/src/i18n/locales/en/admin/accounts.ts
M frontend/src/i18n/locales/en/dashboard.ts
M frontend/src/i18n/locales/zh/admin/accounts.ts
M frontend/src/i18n/locales/zh/dashboard.ts
M frontend/src/types/index.ts
M frontend/src/views/auth/LoginView.vue
M frontend/src/views/user/KeysView.vue
M frontend/src/views/user/__tests__/KeysView.spec.ts
A skills/sub2api-upstream-sync/SKILL.md
A skills/sub2api-upstream-sync/agents/openai.yaml
```

当前 `main..prod` 的统计为 42 个文件、1745 行新增、269 行删除；其中包含本文件和同步 skill。

## 每次同步后的维护流程

1. 确认工作区干净，执行 `git fetch upstream`。
2. 更新本地 `main` 到 `upstream/main`；首次同步时创建 `git switch -c main --track upstream/main`，后续使用 `git switch main && git merge --ff-only upstream/main`。
3. 在合并前查看 `git log --left-right main...prod` 和 `git diff --stat main...prod`，识别上游新增与 prod 专属改动。
4. 执行 `git switch prod && git merge --no-ff main -m 'merge: sync upstream main into prod'`，按语义解决冲突。
5. 更新本文件的当前 SHA、同步 merge 提交、`git log --no-merges main..prod` 输出和 prod 专属能力说明；使用 `git diff --name-status main..prod` 更新影响范围。
6. 验证 `git merge-base --is-ancestor main prod`，运行相关测试。没有明确授权时不 push、rebase 或 reset 分支。
