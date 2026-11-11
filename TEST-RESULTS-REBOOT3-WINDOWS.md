# Windows 同包验证补充：6.9 reboot.3

本页补充首发后的 Windows 验收结果，不变更版本或安装包。[首发测试记录](<https://github.com/AXTUT/dsh-plugin-dualtransfer-trial/blob/main/TEST-RESULTS.md>)及封存摘要保留发布时状态；其中“Windows 待验证”是首发时的记录，当前结果以本页为准。

## 结论与安装包

Windows x64、Node v24.13.0 在隔离目录完成固定的六组定向检查：**6/6 通过，16 个 actor，无失败、取消或跳过**。Mac 已接收原始证据并完成主审及独立 actor 复核，没有重新运行 Windows 测试或使用旧 Framework 结果替代本轮结果。

两平台使用同一份公开 TGZ；先前 macOS arm64 的七组同包定向检查为 7/7。本版仍是实验版，尚无真实系统重启或完整 Host/Agent/模型协作链路的通过结论。

| 项目 | 核验结果 |
| --- | --- |
| 版本 | `0.2.0-candidate.6.9.reboot.3` |
| [安装包](<https://github.com/AXTUT/dsh-plugin-dualtransfer-trial/releases/download/demo-6.9-reboot.3/dsh-plugin-dualtransfer-0.2.0-candidate.6.9.reboot.3.tgz>) | 479,394 字节，142 个运行文件 |
| 安装包 SHA-256 | `54429f67cbce106e74ccc9e774273aa182f692816070556e8db192f1b661bd06` |
| [包内文件清单](<https://github.com/AXTUT/dsh-plugin-dualtransfer-trial/releases/download/demo-6.9-reboot.3/PACKAGE-SHA256.json>) SHA-256 | `6cdae4fa31cf1f22ee2511dd3cf67edbd35bf074d89c447f1ae2a73ca5a041ea` |
| Windows Native helper | 正规 Roslyn/net48/x64 构建，33,280 字节 |
| helper SHA-256 | `4e40e340ce4a6076de3c35046fe3d2e749135ef2ad72cfcfede941758203df19` |
| Windows 执行时间 | 2026-11-07 05:08:20.633768–05:24:04.530322 UTC |
| 定向测试报告总时长 | 943,501.8314 毫秒；不是启动或停机耗时承诺 |

这次 Windows 任务未重新编译、安装、重打包或自动重试，也未操作既有生产根、绑定、系统重启或对端 Goal。

## 六组覆盖范围

| 组 | actor 数 | 已核对的范围 |
| --- | ---: | --- |
| 原版与新版本对比 | 1 | 哈希绑定的原 reboot.1 完整 142 文件参考在同一私有夹具上返回 `OWNER_BOOTSTRAP_SCOPE`，无写入或备份；新版本完成该夹具操作。 |
| 新根、停止与再打开 | 3 | 六个 Native ownership lease、正常停止、独立进程 reopen、同 boot 的 Native enrollment；保留 128 成员和 4 MiB 单日志限制。 |
| 小规模历史恢复 | 1 | 合成 prior-boot 的 stopped、六 active legacy、small segmented 三种历史；检查备份、全量复核后退役、原始日志前缀及幂等行为。五类不透明业务字节保全检查仅在六 active legacy 变体中执行。 |
| 来源与复制根拒绝 | 1 | 部分来源负例通过内存接缝构造；另检查缺少历史 Native anchor、缺少 marker，以及实际复制目录的拒绝。 |
| 进程资格与 guard 争用 | 7 | 合成的 active/reused/unknown 等资格负例、真实同 boot 活进程，以及独立 Native Whole/IO holder 与 contender 的互斥检查。 |
| 不完整历史与发布故障 | 3 | pending、barrier、blocked、partial、已提交日志损坏的拒绝；合成发布不确定故障后的 guard 保留及并发 contender 拒绝。 |

历史 boot、历史 enrollment、部分负例探测及注入故障是合成输入。当前机器、卷、文件身份、Native helper 与内核 guard 有实际执行证据，不能据此把合成历史写成真实系统重启。

## 原件和退出记录怎样核对

- 接收的私有证据 ZIP 为 116,743 字节，SHA-256 为 `942389b42e7d0870541c28867bd8384e741d6af0527edf90d468c84dd1330a84`。67 个条目实际读取并与磁盘副本比较，其中 66 个逐项匹配证据清单。
- 142 个运行文件逐项匹配封存安装包的字节、SHA-256 和 TAR mode。两份定向定义与 Mac 冻结原件一致，组成 144 文件的 Windows stage；运行前后的全部文件盘点一致。
- 原 reboot.1 只读参考的全部 142 文件另与 Mac 保留的独立清单核对，运行前后不变。没有以单个 runtime 文件哈希代替全参考检查。
- parent 记录的 43 个 lib/tests 输入及其聚合哈希重新计算一致。Windows Node、Python 和 TAR 的 mode 表示分别核对，不把它们当成相同的 POSIX 权限证明。
- 全部 16 个 actor 的原始 stdout、stderr、process 与汇总 phase 对象一致，PID 关联一致。每个 actor 均有实际 exit、close、双 EOF，退出码和 close 码均为 0，无父进程 kill、超限输出或 stderr。
- 外层记录是 Python `communicate` 加实际 wait、双 EOF 和退出 0；没有单独记录外层 Node 的 `close` 事件。六组均在原定每组 360,000 毫秒预算内完成，未扩大预算。

16 个 actor 的结束方式分别为：5 个正常 runtime close、6 个只读失败路径 close、2 个只构造夹具而未 open runtime、2 个仅关闭 Native guard、1 个故障 actor 自行退出。最后一种保留失败 ownership 后退出属于 containment，**不是 runtime/plugin 成功 drain**。本轮未测试该故障 actor 退出后的 guard 重新获取。

原始记录保留在受控私有归档中。公开说明不上传机器标识、SID、本机路径、临时接收 URL 或凭据；这些内容也不需要用于试用反馈。

## 仍未验证的内容

- 真实 Windows 或 macOS 系统重启、真实硬件迁移和历史 Native enrollment。
- 完整 Host、Peer、Core、Store、Agent/模型业务及物理双机端到端流程；不透明业务字节夹具不代表这些链路已验收。
- 无人值守通知的及时性和可靠性、浏览器交互、Intel Mac 执行、物理掉电、管理员干预、VM 克隆和整卷回滚。
- 停机时延或稳定版性能保证。单组完成预算不是产品 stop budget；`stopBudgetGuaranteed` 仍为 `false`。

跨 boot 恢复仍要求 boot 变化前已提交的 Native anchor、LAST-owner 关联及当前 Native 证据。缺少历史 anchor 且已跨 boot 的旧根继续返回 `OWNER_ROOT_ORIGIN_REQUIRED`；操作者说明不能补造历史 Native 证据，unknown 也不会被直接当成 dead。

试用请从[README](<README.md>)和[反馈模板](<https://github.com/AXTUT/dsh-plugin-dualtransfer-trial/blob/main/.github/ISSUE_TEMPLATE/bug_report.md>)开始。任务接续始终受接收端本机既有授权、绑定和收件配置约束；收到事实回执不代表执行或验收成功。本次补充不扩大任何远端执行权限。
