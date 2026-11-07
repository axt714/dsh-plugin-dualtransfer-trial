# DualTransfer 评估分发包

版本：0.2.0-candidate.6.9.reboot.3.market.1。

这是面向隔离测试环境的预编译评估包，不是开源发行、市场准入声明或生产可用性保证。
`private: true` 与 `UNLICENSED` 保持不变。请先阅读同目录 `TRIAL-TERMS.md`；
其中的评估条款保持原文，不新增许可证。安装包含可读 JavaScript/MJS、客户端实现及
运行时必须校验的 PowerShell 源码；下载后的实现代码不保密。第三方 YAML ISC 通知保留。

## 环境

- Node.js `>=24`。
- DeepSeek Harness：精确版本 `0.2.1-rc.2`；并非任意 Harness 版本。
- 六项精确 peerDependencies（需另行取得并遵守其条款）：
  - `@deepseek-ai/cordis`：`4.0.5`
  - `@deepseek-ai/schemastery`：`3.18.5`
  - `@deepseek-ai/dsh-scope`：`0.2.1-rc.2`
  - `@deepseek-ai/dsh-tools`：`0.2.1-rc.2`
  - `@deepseek-ai/dsh-llm`：`0.2.1-rc.2`
  - `@deepseek-ai/dsh-session`：`0.2.1-rc.2`

本包只包含预编译运行文件及必要资源，不包含开发、测试、Native 编译或维护工具，
也没有安装期构建脚本。保留 Darwin 二进制、Windows EXE 及其运行校验依赖；
这不表示新增平台兼容性或安装实测。此目录本身不是 Registry 发布或市场上架记录。

## 已测范围与限制

旧密封 reboot.3 的 Mac 7 组、Windows 6 组定向记录属于旧构建的历史记录，
不是这个 market.1 包的新市场安装、激活或跨机业务实测。market.1 的本次验证仅为
文件字节、SHA-256、权限、JSON/XML 与静态资源闭包核对，没有执行产品或安装。
它不能替代 Host/Client 注册、完整配对收发、会话激活、端到端业务、真实重启、
掉电恢复或目标机器兼容性验证；不承诺稳定性或自动修复历史状态。

评估前请备份，并使用隔离环境；不要依赖此实验包处理不可丢失的生产任务。
提交反馈前请脱敏，不公开 token、密钥、完整会话、生产备份或 origin 文件。

项目与反馈：https://github.com/axt714/dsh-plugin-dualtransfer-trial
