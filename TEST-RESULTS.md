# 6.9 reboot.3 实验包测试记录

记录日期：2026-11-06。[实验版发布页](<https://github.com/axt714/dsh-plugin-dualtransfer-trial/releases/tag/demo-6.9-reboot.3>)提供以下共用安装包：

- 版本：`0.2.0-candidate.6.9.reboot.3`
- TGZ：`dsh-plugin-dualtransfer-0.2.0-candidate.6.9.reboot.3.tgz`
- TGZ 大小：`479394` 字节
- TGZ SHA-256：`54429f67cbce106e74ccc9e774273aa182f692816070556e8db192f1b661bd06`
- 包内运行文件：`142` 个
- Windows helper：正规 Roslyn、.NET Framework 4.8、x64 构建，`33280` 字节
- Windows helper SHA-256：`4e40e340ce4a6076de3c35046fe3d2e749135ef2ad72cfcfede941758203df19`

## 当前已执行

| 检查 | 结果与范围 |
| --- | --- |
| 常规语法、构建与检查 | 11 条命令通过；不代表 Windows Native 已执行 |
| Windows 补丁静态审查 | 未发现确定的源码阻塞；静态审查不是运行验收 |
| Windows helper 正规构建 | 在 Mac 上以 Roslyn/net48/x64 编译成功；本次发布包使用上列 33280 字节 EXE，不使用早期 Framework 实验产物 |
| 同包 macOS arm64 元数据 | 主入口、Client、control、bundle patch、中英文 locale、icon 共七个导出实际解析到包内普通文件；未加载宿主 SDK |
| 同包 macOS arm64 Native 首轮运行 | 新建私有测试根，open → 获得一项所有权租约 → release → close 通过 |
| 同包 macOS arm64 独立进程重开 | 第二个独立进程重开同一测试根并完成上述流程通过；没有重启操作系统 |
| 同包 macOS arm64 七组定向检查 | 7/7，0 失败、0 取消、0 跳过，用时 49,656.603167 ms；历史 boot/dev 变化为合成场景，当前 Native 身份与 guards 为真实执行 |
| 同包 Mac 命令退出 | 元数据、首轮 Native、独立进程重开、七组定向检查共四条命令均自然退出 0，stdout/stderr 均完成 EOF；没有把超时或强退算作通过 |
| 运行前后完整性 | 142 个包内运行文件与五份定向定义保持不变；未修改已安装 profile 或接触生产数据 |

Mac 运行使用 Node.js 24.21.0。早期两次运行因验证包装器准备错误而失败，原始失败记录保留；只修正包装器，没有据此修改产品或测试定义。上表的同包通过结果来自准备修正后的完整运行。

历史 boot、dev 和登记后的 owner 场景由夹具合成，机器或卷不匹配也使用受控输入，不能当作真实重启、迁机或 PID reuse。发布边界故障通过受控注入检查拒绝和 guard 保留；故障进程自行退出只表示收容，不算 runtime close 或业务 drain 成功。

运行只使用新建私有测试根与合成业务内容，未进入完整 Harness 的 Host、Peer、Store、Core 或模型流程，也没有发送业务消息。所有权层 close 成功不代表整套业务服务 drain 已验收。

## Windows 当前同包结果

使用上列 TGZ 和正规 33280 字节 EXE 的六组检查已请求执行，当前尚未返回结果，未取得同包通过结论。构建成功和静态审查都不能替代这次 Windows 执行。

早期 Windows 六组 6/6 来自另一份 Framework 构建的 34304 字节 EXE，只能作为不同构建的源码历史，不能算作本次 33280 字节包的结果。更早 C69 Windows 十项记录为 5 通过、3 失败、2 取消，另有 proper-prefix 整案在 360,000 ms 取消、growth 超过 1,200,000 ms 预算的记录；本版尚无 Windows 结果取代这些历史记录。

## Windows 修复的适用条件

Windows 跨 boot 恢复要求原先同一个 boot 内已成功提交 Native anchor，完整历史链中的最新 owner 通过核对，且 fresh Native 的 machine、volume 和目录身份与历史根证据相符。Windows 不使用 Darwin 的 `dev` 映射；unknown 不能当作 owner 已死亡。

已经跨 boot 且缺少历史 Native anchor 的旧根仍返回 `OWNER_ROOT_ORIGIN_REQUIRED`。操作者说明不能替代这份历史证据，当前 Native 身份也不能补造旧 boot 的来源。缺少固件或持久 NTFS 身份、来源不明或关闭不确定时仍会拒绝。

## 公开内容与许可

相对此前审查过的安装内容，132 个载荷保持不变，10 个变更载荷已复核。源码仓库仍私有，安装包内含可读的 JavaScript、客户端源码和部分 Native 构建源码；公开下载不等于开源授权。yaml 2.9.1 的 ISC 许可、版权通知和元数据保留。

内容检查不构成对未知秘密或全部历史权属的法律保证。试用权限和第三方条款见[试用与许可说明](<TRIAL-TERMS.md>)。

## 尚未验证

- 当前正规 Roslyn helper 的 Windows 同包六组结果，以及真实 Windows 系统重启恢复。
- Intel Mac 的 Native 运行；当前实测平台为 macOS arm64。
- 本轮真实 macOS 系统重启、物理掉电恢复或整个数据根连同证据被回滚后的识别能力。
- 官方插件管理器安装后的新 Host/Client 界面、完整 Host/Agent/双机业务往返与模型自动处理。
- 生产数据根维护、恢复、回滚或容量压力测试。

这些结果支持在隔离环境中试用，不支持稳定版或完整业务可用性的结论。安装步骤和反馈方式见[试用说明](<README.md>)。
