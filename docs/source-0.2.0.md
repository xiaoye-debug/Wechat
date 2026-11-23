# WeChatEnvBypass 0.2.0

基于原 0.1.0 源码、DD arm64 静态反编译行为及提供的头文件进行合并。

## 修改范围

- 88 个方法、31 个类，88 个独立 Logos group，逐项检查运行时方法存在性、类/实例类型、参数个数及类型编码，再显式 `%init`。
- 修正 `HasInstallJailbreakPlugin:` 的 `+`/`-` 错误；删除空扩展表及不保存原实现的通用 patch 器。
- DD 55 项中 54 项有行为变化的方法身份已纳入；`WCAccountControlMgr -onAuthOK` 原样透传，不重复 Hook。
- 纳入头文件中的 12 项相关入口：`ClientCheckMgr` 两个报告、缓存收银报告、`TSEnvironment` 三项、支付 helper 三项、内购三项。
- 保留原有策略，不宣称精确复制 DD：原有路径 getter 仍直接给 nil；系统查询保留失败信息；IDFV 验证 UUID；支付能力判断保留硬件能力，内购保留原流程和返回值。

## 开关

偏好 domain：`com.macxk.wcenvbypass`。所有开关在进程启动时读取；改变后要重新启动目标进程。示例配置位于同目录的 `preferences.example.plist`，仅作配置模板，**不会随安装自动导入**。

| Key | 默认 | 内容 |
|---|---|---|
| Enabled | true | 总开关 |
| HookJailbreak / HookModules / HookEnvChecks | true | 原有环境分类及 DD 对应项 |
| HookReporting / HookSceneGate | true | 原有报告 / 场景入口 |
| HookSystemQueries | true | DD 系统查询视图过滤，不修改真实文件或进程环境 |
| HookClientChecks | true | ClientCheckMgr 检查与关联回调 |
| HookCacheReports | true | MMClientCacheManager，报告另受 HookReporting 控制 |
| HookSignature | true | CAppUtil 生产签名状态接口 |
| HookHeaderEnvironment | true | TSEnvironment 三项，另受对应环境分类控制 |
| HookReportFields | false | 三个 WCExtInfo setter 与五个联系人字段 getter |
| HookDeviceIdentity | false | 替代 IDFV 视图；优先验证 ddab_fake_idfv 环境值，再读 FakeIDFV / GeneratedIDFV |
| HookReceiptView | false | 只调整返回 URL，不创建或验证任何收据 |
| HookDiagnosticsSuppression | false | 崩溃监控与安全模式行为，默认保留诊断 |
| HookPaymentEnvironment | false | 支付/内购环境分支；不伪造交易成功 |
| HookIntegrity | false | 原有直播目录完整性；返回码语义未获消费者实现确认 |
| LogEnabled | false | 逐项安装/跳过日志，不记录传入业务内容 |

已关闭分类不安装其 Hook；启用时也先检查运行时签名。开关关闭的入口不能计作“已生效覆盖”。启动摘要中的 registered 表示当时观察到 IMP 改变的数量，不是检测调用次数或防封效果。

## 构建

要求现成的 Theos、iOS SDK、Substrate 开发依赖，目标最低 iOS 15，arm64 / arm64e。注入过滤仍保持 `com.tencent.xin`，没有增加其他 App。

在配置完整的 Theos 主机中，从此目录运行：

```sh
make clean package FINALPACKAGE=1
```

这只是构建命令，当前 Windows 环境未编译、签名、打包、安装或运行目标。不要将静态检查 PASS 误认为编译或设备验证通过。

## 验证与边界

- 静态契约检查：88 项身份唯一，DD 缺项为 0（1 个纯透传设计排除），10 项 E1 候选均有实现。9 项保留类型信息提示：8 项对象类与 id 的 ABI 家族差异，1 项未知 block 原型。
- 头文件只有声明；版本对应、动态方法生成、延迟类加载、安装结果、调用覆盖与服务端判定均未通过设备观察确认。
- 类或方法在构造时尚不可见会被跳过，本版本不监听后续镜像加载；Protobuf `@dynamic` setter 因实际实现/类型不符被跳过时不会强行创建。
- 已提供声明的普通版本/机型 getter、未知回调和资源更新完整性入口未盲目改写。
- 输入原始备份、逐项覆盖与源码 diff 随交付包提供；没有创建 Git commit 或推送。
