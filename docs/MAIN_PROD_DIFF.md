# main 和 prod 的差异

## 当前基线

- 更新日期：2026-07-17
- 上游稳定版：`v0.1.159`（`2a75d7d2387587d86ca3c5e5cd8ca96cf3d104c6`）
- `prod` 升级合并：`8075d304d merge: upgrade prod to upstream v0.1.159`
- 最近一次远端整合：`d5eac3fa5 merge: integrate origin prod v0.1.157`
- 升级前回退分支：`backup/prod-pre-v0.1.159-20260717_105458`

`v0.1.159` 和 `origin/prod` 均为当前 `prod` 的祖先。`prod` 在稳定版之外保留注册安全、管理员 API Key 管理、生产部署和 Codex 兼容等定制；同步和远端整合 merge 仅保留历史。`upstream/main` 已继续前进，不作为本次生产发布基线。

## prod 专属改动

| 范围 | 提交 | 说明 |
| --- | --- | --- |
| 生产部署 | `c764bd90` | 生产部署配置、Caddy 配置、备份和健康检查脚本。 |
| OpenAI OAuth 账户 | `781e0042`, `06fd20a3` | 新账户自动配置 UA、originator 和过期时间；OAuth 换 token 与网关统一使用 Codex 0.144.1。 |
| 管理端 API Key | `1de3c512`, `91e80b6c`, `7bd41f6b` | 管理员可查看、改分组、完整编辑和删除任意用户的 API Key。 |
| 注册安全 | `7bd41f6b` | 登录页按公开注册开关隐藏注册入口；生产环境关闭公开注册。 |
| Codex 元数据隔离 | `7d7c4d9b`, `ddb2c886` | 会话 ID 覆盖后重新加盐 `x-codex-turn-metadata`，隔离跨账户指纹。 |
| 工作区指纹池 | `0c99fe71` | 指纹池的空闲淘汰和可配置超时。 |
| 错误响应处理 | `e37e01b5` | 避免 `handleErrorResponse` 重复写入响应。 |
| Codex 兼容修复 | `c08f22cd`, `bfe7be6a`, `70218dd4`, `05441539`, `1c005ee1`, `90c54d0a`, `dbb0c2be` | 保留原生压缩、修复续链 ID、tool_search、心跳生命周期、OAuth 身份和独立搜索端点。 |
| 管理端策略 | `bac750c5`, `dcb641ae` | Fast/Flex 策略支持搜索用户，账号重新认证后刷新过期时间。 |

当前相对 `v0.1.159` 的差异主要在 `deploy/`、API Key 管理、OpenAI/Codex 转发、工作区指纹池和运维设置；另包含本文件和上游同步 skill。

## 每次同步后的维护流程

1. 确认工作区干净，执行 `git fetch upstream`。
2. 更新本地 `main` 到 `upstream/main`；首次同步时创建 `git switch -c main --track upstream/main`，后续使用 `git switch main && git merge --ff-only upstream/main`。
3. 在合并前查看 `git log --left-right main...prod` 和 `git diff --stat main...prod`，识别上游新增与 prod 专属改动。
4. 执行 `git switch prod && git merge --no-ff main -m 'merge: sync upstream main into prod'`，按语义解决冲突。
5. 更新本文件的当前 SHA、同步 merge 提交、`git log --no-merges main..prod` 输出和 prod 专属能力说明；使用 `git diff --name-status main..prod` 更新影响范围。
6. 验证 `git merge-base --is-ancestor main prod`，运行相关测试。没有明确授权时不 push、rebase 或 reset 分支。
