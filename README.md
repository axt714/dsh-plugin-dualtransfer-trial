# DualTransfer 实验版试用

在两台 DeepSeek Harness 之间配对，向各自绑定的会话发送 Agent 消息。本仓库提供实验安装包、校验文件和问题反馈，不是稳定版，也不是源码仓库。

## 当前构建：6.9 reboot.2

这是基础外测包，版本为 `0.2.0-candidate.6.9.reboot.2`。相对 reboot.1，只修正包描述、语言资源和图标导出，以及对应打包校验；运行时与 Native 实现未变。

**尚未包含正在处理的 Windows 跨系统重启修复。** Windows 的旧数据根在系统重启后可能拒绝启动。请只在隔离测试环境中试用，不接入生产任务；遇到所有权拒绝时不要删锁、改日志或强行运行维护工具。

- [下载实验安装包及校验文件](https://github.com/axt714/dsh-plugin-dualtransfer-trial/releases/tag/demo-6.9-reboot.2)
- [查看本次测试范围](TEST-RESULTS.md)
- [提交脱敏试用反馈](https://github.com/axt714/dsh-plugin-dualtransfer-trial/issues/new)
- [试用与许可说明](TRIAL-TERMS.md)

源码仓库保持私有，但安装包内的 JavaScript、客户端源码及部分 Native 构建源码可被下载者查看。私有仓库不意味着安装包的代码保密。

## 环境要求

需要兼容本包 SDK 的 DeepSeek Harness 环境，以及 Node.js 24 或更新版本。仅满足 Node 版本并不足以保证兼容。包声明的 peer dependencies 为：

| 依赖 | 版本 |
| --- | --- |
| `@deepseek-ai/cordis` | `4.0.5` |
| `@deepseek-ai/schemastery` | `3.18.5` |
| `@deepseek-ai/dsh-scope`、`dsh-tools`、`dsh-llm`、`dsh-session` | 各 `0.2.1-rc.2` |

这些依赖由兼容宿主提供，未随本安装包捆绑。出现缺失或版本冲突时请记录警告并停止，不要用 `--force`、手改 profile 或自动补装未知版本来绕过。

本轮隔离运行测试使用 macOS arm64；Intel Mac 未执行本轮测试。Windows 试用需满足原 Native 条件，包括 Windows 11 x64、build 22621 或更新、固定 NTFS 卷及私有 ACL；系统策略禁止执行 Native EXE 时不提供绕过路径。完整 Windows 运行与系统重启验收尚未完成。

## 安装

1. 先备份现有数据，并优先使用独立的 Harness 测试配置。安装影响所选 profile 中的所有会话，不只是当前聊天。
2. 从 Release 下载 TGZ、`PACKAGE-SHA256.json` 和 `SHA256SUMS.txt`。本包不通过 npm 或 Marketplace 安装。
3. 核对 TGZ：`476339` 字节，SHA-256：

   `3407558a7fc78faa1592277c5d25a02df6e31e4a382b7ed26647da13b65d87fa`

4. 在目标 Harness 中，让 Agent 使用官方插件管理器，将已下载 TGZ 的本地绝对路径作为 `install_bundle` 目标。不要直接修改 profile 文件或在 profile 目录运行 npm/pnpm。
5. 检查安装结果和依赖警告。正常完全退出并重新打开 Harness，以加载新的 Host 和 Client 代码。安装成功不代表消息收发、重启恢复或旧根维护已经验证。

请勿把未完成退出的服务强制当作已停止，也不要让测试 Agent 自动迁移、清锁或修复原有生产根。

## 建议先测这些

两端都使用同一版本和同一安装包哈希。

1. 建立配对，通过私密渠道交换短时邀请，并在两端核对设备指纹、确认信任。
2. 在两台机器上分别人工绑定目标会话，检查当前连接状态。旧的确认记录不代表本次连接已就绪。
3. 发送不含敏感信息的随机测试标记，检查对端收件与回执。收件回执只证明收到，不代表任务完成或新增执行授权。
4. 通过正常 Stop 等待关闭完成，再在同一次系统启动内 Start。记录成功步骤和明确的错误码。

本包没有完成完整 Host/Peer/模型自动处理端到端测试。不要把通知出现、安装成功或连接状态当作整条流程已经通过。

## 已知边界

- Windows 跨系统重启旧根仍有限制，修复将在收到并核验补丁后另发版本。
- macOS 的模拟 boot/dev 变更测试不等于真实系统重启；本轮没有重启系统。
- 所有权日志每段仍为 4 MiB；分段不回收旧段，也不保证磁盘总量不增长。
- 未知所有者、损坏或部分记录、未结束屏障及失败退出会拒绝接管；不要通过清理证据绕过。
- 界面上的清理历史只改变展示范围，不删除任务、去重或 ACK 事实。

反馈请提供版本、包哈希、系统与 Harness 版本、可复现步骤及脱敏错误码。不要上传邀请、token、密钥、完整会话数据、生产备份或 origin 文件。
