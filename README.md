# DualTransfer 实验版试用

在两台 DeepSeek Harness 之间配对，向各自绑定的会话发送 Agent 消息。本仓库用于提供实验安装包、校验文件和问题反馈，不是稳定版，也不是源码仓库。

## 当前构建：6.9 reboot.3

版本为 `0.2.0-candidate.6.9.reboot.3`，macOS 与 Windows 共用一个安装包。reboot.3 新增 Windows Native 持久根证据，保留 Darwin 的重启／重新挂载检查。

下方发布页提供本版安装包、校验文件和测试摘要。当前同包 macOS arm64 的七组定向检查已通过；正规 Roslyn 构建的 Windows helper 已编译，同包 Windows 六组已请求执行，尚未返回结果。详细范围见[测试记录](<TEST-RESULTS.md>)。

- [下载页：实验安装包及校验文件](<https://github.com/axt714/dsh-plugin-dualtransfer-trial/releases/tag/demo-6.9-reboot.3>)
- [查看本次测试范围](<TEST-RESULTS.md>)
- [提交脱敏试用反馈](<https://github.com/axt714/dsh-plugin-dualtransfer-trial/issues/new>)，或参照[反馈模板](<.github/ISSUE_TEMPLATE/bug_report.md>)
- [试用与许可说明](<TRIAL-TERMS.md>)

源码仓库保持私有，但安装包内的 JavaScript、客户端源码及部分 Native 构建源码可被下载者查看。私有仓库不意味着安装包的代码保密，公开下载也不等于开源授权。

## Windows 跨系统重启的条件

Windows 旧根必须在原先同一个 boot 内成功提交过 Native anchor，跨 boot 时还要核对完整历史链的最新 owner，以及当前 Native 读取的 machine、volume 和目录身份。Windows 不使用 Darwin 的 `dev` 映射，也不会把 unknown 当作 owner 已死亡。

如果旧根已经跨 boot，却没有所需的历史 Native anchor，仍会返回 `OWNER_ROOT_ORIGIN_REQUIRED`。操作者说明和当前机器身份都不能补造历史证明；缺少所需固件信息或持久 NTFS 身份时也会拒绝。这次补丁不保证所有旧根都能恢复。

请只在隔离测试环境中试用，不接入生产任务。遇到所有权拒绝时不要删锁、改日志或强行运行维护工具。

## 环境要求

需要兼容本包 SDK 的 DeepSeek Harness 环境，以及 Node.js 24 或更新版本。仅满足 Node 版本并不足以保证兼容。包声明的六项 peer dependencies 为：

| 依赖 | 精确版本 |
| --- | --- |
| `@deepseek-ai/cordis` | `4.0.5` |
| `@deepseek-ai/schemastery` | `3.18.5` |
| `@deepseek-ai/dsh-scope` | `0.2.1-rc.2` |
| `@deepseek-ai/dsh-tools` | `0.2.1-rc.2` |
| `@deepseek-ai/dsh-llm` | `0.2.1-rc.2` |
| `@deepseek-ai/dsh-session` | `0.2.1-rc.2` |

这些依赖由兼容宿主提供，未随本安装包捆绑，插件不会自动安装 SDK。出现缺失或版本冲突时请记录警告并停止，不要用 `--force`、手改 profile 或自动补装未知版本来绕过。

本轮隔离运行测试使用 macOS arm64；Intel Mac 未执行本轮测试。Windows 试用需满足原 Native 条件，包括 Windows 11 x64、build 22621 或更新、固定 NTFS 卷及私有 ACL；系统策略禁止执行 Native EXE 时不提供绕过路径。Windows 同包结果和真实系统重启验收尚未取得。

## 安装

1. 先备份现有数据，并优先使用独立的 Harness 测试配置。安装影响所选 profile 中的所有会话，不只是当前聊天。
2. 从上方 Release 下载 `dsh-plugin-dualtransfer-0.2.0-candidate.6.9.reboot.3.tgz`、`PACKAGE-SHA256.json` 和 `SHA256SUMS.txt`。本包不通过 npm 或 Marketplace 安装。
3. 核对 TGZ：`479394` 字节，SHA-256：

   `54429f67cbce106e74ccc9e774273aa182f692816070556e8db192f1b661bd06`

4. 在目标 Harness 中，让 Agent 使用官方插件管理器，将已下载 TGZ 的本地绝对路径作为 `install_bundle` 目标。不要直接修改 profile 文件或在 profile 目录运行 npm/pnpm。
5. 检查安装结果和依赖警告。确认正常完全退出后，重新打开整个 Harness，以加载新的 Host 和 Client 代码；只刷新浏览器不能重载 Host。安装成功不代表消息收发、重启恢复或旧根维护已经验证。

请勿把未完成退出的服务强制当作已停止，也不要让测试 Agent 自动迁移、清锁或修复原有生产根。本轮测试未执行插件安装或生产根操作。

## 建议先测这些

两端都使用同一版本和同一安装包哈希。

1. 建立配对，通过私密渠道交换短时邀请，并在两端核对设备指纹、确认信任。
2. 在两台机器上分别人工绑定目标会话，检查当前连接状态。旧的确认记录不代表本次连接已就绪。
3. 发送不含敏感信息的随机测试标记，检查对端收件与回执。收件回执只证明收到，不代表任务完成或新增执行授权。
4. 通过正常 Stop 等待关闭完成，再在同一次系统启动内 Start。记录成功步骤和明确的错误码。

本包尚未完成完整 Host/Peer/Core/模型自动处理端到端测试。通知出现、安装成功或连接状态不代表整条流程已经通过。可按上述步骤隔离试用。

## 已知边界

- Windows 跨 boot 恢复受上述历史 Native anchor 条件限制；本版同包 Windows 六组尚无返回结果。
- macOS 的历史 boot/dev 变更使用合成场景，当前 Native 和 guards 为真实执行；进程重开不等于真实系统重启。本轮没有重启系统，也没有掉电测试。
- 所有权日志每段仍为 4 MiB，成员上限仍为 128；分段不回收旧段，也不保证磁盘总量不增长。
- 未知所有者、损坏或部分记录、未结束屏障及失败退出会拒绝接管；不要通过清理证据绕过。
- 界面上的清理历史只改变展示范围，不删除任务、去重或 ACK 事实。

反馈请提供版本、包哈希、系统与 Harness 版本、可复现步骤及脱敏错误码。不要上传邀请、token、密钥、完整会话数据、生产备份、origin 文件、硬件标识或 Windows SID。
