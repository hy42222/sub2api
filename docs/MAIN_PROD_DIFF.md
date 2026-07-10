# main 和 prod 的差异

## 当前基线

- 更新日期：2026-07-10
- `main`：`9a2f11b4e21763cb7003ea29921d9a672ab50b1f`（跟踪 `upstream/main`）
- `prod`：`73d6cb286833062d160accb60707a8f309b82e25`
- 最近一次上游同步：`73d6cb28 merge: sync upstream main into prod`

`main` 是当前 `prod` 的祖先。`prod` 在 main 之外保留 7 个功能提交；另有 1 个同步 merge commit 用于保留整合历史。因此 `git diff main..prod` 仅展示生产分支的专属文件差异。

## prod 专属改动

| 范围 | 提交 | 说明 |
| --- | --- | --- |
| 生产部署 | `c764bd90` | 生产部署配置、Caddy 配置、备份和健康检查脚本。 |
| OpenAI OAuth 账户 | `781e0042` | 新账户自动配置 UA、originator 和过期时间。 |
| 管理端 API Key | `1de3c512` | 管理员可查看所有用户的 API Key。 |
| Codex 元数据隔离 | `7d7c4d9b`, `ddb2c886` | 会话 ID 覆盖后重新加盐 `x-codex-turn-metadata`，隔离跨账户指纹。 |
| 工作区指纹池 | `0c99fe71` | 指纹池的空闲淘汰和可配置超时。 |
| 错误响应处理 | `e37e01b5` | 避免 `handleErrorResponse` 重复写入响应。 |

当前差异影响 18 个文件，主要在 `deploy/`、账户和 API Key 服务、OpenAI 网关服务以及运维设置模型。

## 每次同步后的维护流程

1. 确认工作区干净，执行 `git fetch upstream`。
2. 更新本地 `main` 到 `upstream/main`；首次同步时创建 `git switch -c main --track upstream/main`，后续使用 `git switch main && git merge --ff-only upstream/main`。
3. 在合并前查看 `git log --left-right main...prod` 和 `git diff --stat main...prod`，识别上游新增与 prod 专属改动。
4. 执行 `git switch prod && git merge --no-ff main -m 'merge: sync upstream main into prod'`，按语义解决冲突。
5. 更新本文件的当前 SHA、同步 merge 提交、`git log --no-merges main..prod` 输出和 prod 专属能力说明；使用 `git diff --name-status main..prod` 更新影响范围。
6. 验证 `git merge-base --is-ancestor main prod`，运行相关测试。没有明确授权时不 push、rebase 或 reset 分支。
