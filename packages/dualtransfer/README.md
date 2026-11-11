# DualTransfer 评估分发包

版本：0.2.0-candidate.6.9.reboot.3.market.3。

非开源（UNLICENSED 评估试用版，勿用于生产）；需要 Node.js 24+，仅在 macOS arm64 与 Windows 11 x64 build 22621+ 上测试。

Not open source (UNLICENSED evaluation build, not for production); requires Node.js 24+, tested only on macOS arm64 and Windows 11 x64 build 22621+.

本构建面向公共 npm 分发，移除阻止发布的 `private: true`，保留 `UNLICENSED` 和原有评估条款。开发仓库仍为私有；公开安装包可以下载，不代表开源授权。请先阅读同目录 `TRIAL-TERMS.md`。安装包含可读 JavaScript/MJS、客户端实现及运行时必须校验的 PowerShell 源码；下载后的实现代码不保密。第三方 YAML ISC 通知保留。

## npm 安装与“发现”

发布包名为 `dsh-plugin-dualtransfer`。在兼容的 Harness 测试配置中，通过官方插件管理器安装指定版本 `dsh-plugin-dualtransfer@0.2.0-candidate.6.9.reboot.3.market.3`；不要在正在使用的 profile 目录里手工运行 npm/pnpm。

Awesome DSH Plugin 公共索引根据 npm 的 `latest` 标签生成条目。这里的 `latest` 只表示默认分发版本，**本插件仍是评估试用版，不是稳定版**。进入“发现”还取决于公共目录完成扫描与发布、用户启用对应索引，以及宿主兼容性检查。目录 PR 合并不代表所有用户默认可见或获得官方推荐。

market.3 相对 market.2 仅调整版本、npm 发布配置及本说明；运行代码、Native 文件、依赖声明和试用条款保持不变。旧版运行测试仍属于旧版，不作为本次新增业务验收。

## 环境

- Node.js `>=24`。
- DeepSeek Harness 声明范围：`0.2.1-rc.2 || >=0.2.2-rc.1 <0.2.3-0`。保留旧测试基线，并放行当前 `0.2.2-rc.1` 起的 `0.2.2` 版本线；不自动放行 `0.2.3` 或 `0.3` 的预发布版。
- 平台仅测试过 macOS arm64 和 Windows 11 x64 build 22621+；Intel Mac 未测试。Windows 仍需固定 NTFS 卷、私有 ACL 和允许执行 Native EXE 的系统策略，不提供绕过路径。
- 六项精确 peerDependencies 保持原声明，需另行取得并遵守其条款：
  - `@deepseek-ai/cordis`：`4.0.5`
  - `@deepseek-ai/schemastery`：`3.18.5`
  - `@deepseek-ai/dsh-scope`：`0.2.1-rc.2`
  - `@deepseek-ai/dsh-tools`：`0.2.1-rc.2`
  - `@deepseek-ai/dsh-llm`：`0.2.1-rc.2`
  - `@deepseek-ai/dsh-session`：`0.2.1-rc.2`

版本门控放行不代表新版 SDK 或完整业务已经验证。不要为消除依赖警告申请版本豁免、强制安装或手改 profile。

本包只包含预编译运行文件及必要资源，不包含开发、测试、Native 编译或维护工具，也没有安装期构建脚本。保留 Darwin 二进制、Windows EXE 及其运行校验依赖；这不表示新增平台运行验收。此目录本身不是 Registry 发布或市场上架记录。

## 本轮变更与验证边界

market.2 仅修订包元数据与说明：放宽宿主版本门控、补足平台及许可限制、把当前项目与反馈链接改为 `AXTUT`。其余运行文件、试用条款与执行位保持 market.1 的内容，不更换业务或 Native 实现。

market.1 曾在 DSH `0.2.1-rc.2` 上完成 Mac、Windows 各八阶段的隔离官方安装生命周期；这是旧版本的历史结果，不是 market.2 的新安装验收。旧封存 reboot.3 的 Mac 七组、Windows 六组定向检查同样属于旧构建。

本轮检查版本门控、官方索引解析及文件资源闭包；本机宿主仍为 `0.2.1-rc.2`。对 `0.2.2-rc.1` 的版本参数检查不是在该版本宿主上运行插件。新版宿主上的实际加载仍待复验，不承诺完整配对收发、端到端业务、模型自动处理、真实重启、掉电恢复或自动修复历史状态。详见[市场指南](<https://github.com/AXTUT/dsh-plugin-dualtransfer-trial/blob/main/market/README.md>)。

评估前请备份并使用隔离环境，不要接入生产任务。提交反馈前请脱敏，不公开 token、密钥、完整会话、生产备份或 origin 文件。

项目与反馈：https://github.com/AXTUT/dsh-plugin-dualtransfer-trial
