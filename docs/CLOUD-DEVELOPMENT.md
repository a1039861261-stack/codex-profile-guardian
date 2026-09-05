# 云端开发、发布与本地清理

## 强制约束：只在云端开发（2026-09-06）

这是所有者明确要求，不是可自行绕过的建议：公开源码只通过 GitHub 网页/API 或明确选定的远程环境修改；测试、前端编译、Windows 打包及隔离验收只在 GitHub-hosted Windows Actions 执行。本机遗留目录不再作为开发工作区。

- 禁止在所有者电脑 clone/新建/更新开发 checkout 或 worktree，禁止安装或重建 `.venv`、`node_modules`、构建缓存、测试夹具、预览服务及构建产物。需要测试、UI 验收或修复构建不构成本地执行的例外；只有用户之后明确修改本规则才可恢复本地开发。
- 允许必要的轻量只读检查、GitHub API 操作，以及用户当次授权的文件清理或软件安装；这些操作不能顺带恢复本地开发环境。
- 不配置本机 self-hosted runner，不擅自开通付费 Codespaces/云机器。沿用临时 GitHub-hosted `windows-2022`、不跨任务缓存依赖、Actions 成品保留 3 天，正式 Releases 持续保留。
- 默认在云端验真，不把安装包/构建产物批量回下载到本机；用户明确需要交付或安装时才下载对应文件。普通开发不再产生本地聊天/安装回滚冷备；用户明确授权真实数据操作时的必要安全备份另行按精确范围执行。
- 不能把账号、凭据、聊天、SQLite 或私人备份上传公开 GitHub，也不能把“云端开发”解释成自动清空本机。旧私人备份只有明确知情的永久删除授权后才删除；稳定 v1.6.2 与唯一源码继续受保护。
- Codex、浏览器和已安装 Guardian 运行仍会占用本机内存；减少的是本地开发、测试和构建负载，不承诺本机零 RAM。

## 日常方式

1. 在 GitHub 网页或明确选定的远程环境修改源码，使用 `ci/` 开头的开发分支并审核变更；创建面向 `main` 的 Pull Request 也会运行检查。
2. `Windows release` 在 GitHub 托管的 `windows-2022` 临时虚拟机安装依赖、运行全量 Python 测试、编译前端、扫描公开文件、生成四个程序及安装包，并执行隔离安装/升级/卸载/回滚验收。失败不会生成可发布的 Actions 成品。
3. 将已审核源码合入 `main` 后，在 Actions → Windows release → Run workflow 选择 `main`。默认 `publish=false`，只验证并生成可下载成品；明确勾选 `publish` 才在成功后创建新正式 Release/Latest。
4. 已存在的版本或 tag 不覆盖。上传先进入草稿，大小与 GitHub SHA-256 digest 核对一致后才公开；失败保留草稿供检查，不自动删除。发布不会安装任何用户电脑上的 Guardian。

普通 main 提交不自动发布；`main` 可手动构建，`ci/**` push 与 Pull Request 自动构建。手动运行需要工作流文件已经在默认分支。首次引入工作流时，可先推送 `ci/**` 分支完成验证，再将同一提交快进到 main，并核验同一份成品后发布。

源码、测试、锁文件和工作流保存在 Git；Windows 安装包、portable ZIP、manifest 和 SHA256SUMS 保存在 Releases。manifest 包含实际构建的 Git commit/tree，可与 tag 核对。安装器暂未代码签名，下载后应核对 SHA-256，Windows 可能显示 SmartScreen。

## 资源与费用边界

- 这是 GitHub-hosted runner，不是本机 self-hosted runner；全量测试与打包消耗云端虚拟机资源。GitHub 不会替你自动编写代码，网页编辑或远程编码环境仍需另行选择。
- 临时运行器工作区随任务结束回收，不开跨任务依赖缓存。Actions 仅保留四个公开成品，保留期 3 天；正式 Releases 不随临时成品过期。
- 公共仓库的标准 GitHub-hosted runner 执行免费，但资产/缓存额度有独立规则；不要擅自启用大型 runner、付费 Codespaces 或付费云机器。参见 [Actions 计费说明](https://docs.github.com/en/billing/concepts/product-billing/github-actions)。
- Codespaces 是另一种可选的云端 Linux 开发环境，不是 Windows 打包机，且有独立计算/存储计费；本流程不创建 Codespaces。
- Guardian、Codex 客户端和浏览器实际在本机运行时仍会占用正常内存。删除项目文件主要释放硬盘，不等于关闭进程或释放所有 RAM。

## 不上传私人数据，也不自动删除本机

不得上传真实账号、Key、Token、DPAPI 密文、聊天、SQLite、日志、私人回滚包、未审查的旧 Git 历史。GitHub 公开源码备份不等于这些私人数据已得到远端备份。

云端新虚拟机没有本机不可覆盖的 `v1.6.2` 安装包。构建的 `-IsolatedHostedRunner` 模式只接受 GitHub-hosted 环境，拒绝携带本机基线、拒绝构建 v1.6.2 或在输出目录发现该基线；manifest 明确记录基线不在云端，而不是伪称已验证云端副本。源码仍保留历史本地构建兼容路径，但当前强制云端规则禁止在所有者电脑调用；不得据此恢复本地构建。

本地删除前必须逐项确认：

1. 需要保留的源码提交已在远端，版本资产已回下载并验哈希。
2. 所有工作树的未提交/未跟踪文件已分类；忽略文件不代表可以删除。
3. 私人数据和不可覆盖基线有单独的保留安排。
4. 精确列出待清理路径并获得确认；先通过 Git 注销工作树，不能直接删共享 `.git` 或整个项目根目录。

本工作流只回收自己的云端临时环境，不配置本机定时删除，不删除本机源码、备份或聊天。以后若仅需要 Releases 的安装包，可在完成上述检查后单独清理可重建的本机依赖、缓存和冗余工作树。
