# RFC-P1-001 — RFC-P1-001 — 日冕系统（天枢）协议 v4.4

**GnomonSystem 协议基线 v4.4**

## 摘要

本文件定义Gnomon System的P1层——天枢协议（Prime Protocol）。
天枢协议解决两个问题：

**问题一（单域）：** 如何将物理时间（原子钟）密码学化为可验证的数字时序？

**问题二（多域）：** 当存在多个独立L1节点体系时，如何在不统一TI空间的前提下，实现因果宇宙间的互认？

核心原则：

* 时序的信任根是物理现实（铯原子振动），不是任何机构的信誉
* 多个L1体系是平行的因果宇宙，不需要全局时序同步
* 跨域因果关系通过协作事件的接触面自然建立，不需要统一时钟

---

## 目录

术语与符号

单域：物理时序锚定

### 2.1 时序层级体系

### 2.2 根THK（Root TimeHashKey）

### 2.3 子THK（Child TimeHashKey）

### 2.4 操作密钥证书（OpCertificate）

### 2.5 分层THK的使用规则

### 2.6 KeyPackage

### 2.7 TemporalIndex分配

单域：节点管理

### 3.1 L1节点要求

### 3.2 L2节点认证

### 3.3 降级模式

多域：因果宇宙互认（Federation）

### 4.1 联盟基本原则

### 4.2 联盟宪章（FederationCharter）

### 4.3 联盟成员互认协议

### 4.4 跨域事件的处理

### 4.5 联盟退出与撤销

协议消息

### 5.1 消息格式

### 5.2 服务接口

安全考量

测试向量

错误码

版本历史

---

## 1. 术语与符号

### 1.1 核心术语

物理时间（Physical Time）：
由原子钟（铯-133超精细跃迁）提供的时间基准
通过NTSC（国家授时中心）或北斗系统分发
单位：纳秒（ns）

TemporalIndex（TI）：
物理时间在特定L1域内的离散化映射
uint64单调递增整数，在域内全局唯一
约1微秒/TI（可配置，按部署调整）
TI不是绝对物理时间，是因果序的工程化表达

因果宇宙（Causal Universe）：
共享同一L1节点信任根的节点网络
同一因果宇宙内的事件具有 TI 值可比性（授权唯一性），不保证物理时间排序（因果偏序）
不同因果宇宙之间的事件无需比较先后（偏序sufficient）

接触面（Contact Surface）：
两个因果宇宙之间通过跨域协作事件建立的关联点
接触面之后，跨宇宙事件的先后关系通过事件引用可追溯

根THK（Root THK）：
每小时由L1节点生成的物理时间密码学锚点
锚定真实物理时间，精度≤20ns
TI大范围分配（覆盖整个小时）

子THK（Child THK）：
从根THK派生的高频时序凭证
按需签发，可秒级·分钟级触发
TI小范围分配（覆盖特定业务窗口）
继承根THK的物理时序权威

联盟（Federation）：
多个独立L1因果宇宙签署联盟宪章后形成的互认网络
类ITU多边机构，各成员平等，无全球根节点

### 1.2 符号定义

H(·) SM3哈希函数（256位输出）
Sign(sk, ·) SM2签名
Verify(pk, m, σ) SM2验证，返回 {0,1}
BE64(n) 64位大端整数编码
∥ 字节串拼接
rTHK 根THK（Root THK）
cTHK 子THK（Child THK）
KP_v L2节点v的KeyPackage
TI_v 节点v的当前TemporalIndex
FC FederationCharter（联盟宪章）
FMR FederationMemberRecord（联盟成员记录）
CSR CrossDomainContactRecord（跨域接触面记录）
OpCert 操作密钥证书（Operation Certificate）

---

## 2. 单域：物理时序锚定

### 2.1 时序层级体系

天枢协议采用分层THK设计，解决物理时序精度与业务灵活性之间的平衡：
物理时间（原子钟·精度≤20ns）
│
│ 每小时采样一次
▼
根THK（Root THK）
· 锚定物理时间
· TI段分配：每根THK覆盖3,600,000,000个TI（约1小时）
· 由L1节点根密钥签名
│
│ 按需派生（使用操作密钥）
▼
子THK（Child THK）
· 从根THK派生，继承物理时序权威
· TI段分配：每子THK覆盖1,000,000个TI（约1秒）或自定义
· 由L1节点操作密钥签名（操作密钥由根密钥签发短期证书）
· 适用场景：高频金融清算·实时AI决策·毫秒级事件序列
│
│ KeyPackage分发
▼
L2节点（使用TI签发EEA）

**分层的必要性：**
若只有根THK（1小时/次）：
L2节点在1小时内使用相同的TI段
高频场景（60,000 TPS × 3600s = 2.16亿个EEA）需要足够大的TI段
根THK无法精确反映小时内的时序关系

若只有子THK（按需）：
每次业务都要等L1签发 → 延迟高（HSM签名≥2ms）
L1成为热点 → 性能瓶颈

分层方案（根THK+子THK）：
根THK：每小时一次，物理时间精确锚定
子THK：按需签发，继承根THK权威，细分TI段
L2节点：持有KeyPackage（承载子THK）即可在子THK的TI段内本地高速签发EEA

### 2.2 根THK（Root TimeHashKey）

**数据结构（176B）：**
字段 长度 类型 说明
──────────────────────────────────────────────────────────
t_utc 8B uint64 BE UTC时间（纳秒）
t_epoch 8B uint64 BE 本根THK对应的TI起始值
ti_range_start 8B uint64 BE 本根THK覆盖的TI起始
ti_range_end 8B uint64 BE 本根THK覆盖的TI结束（不含）
nonce 16B bytes CSPRNG随机数
prev_root_commitment 32B bytes 前序根THK的时间承诺
time_commitment 32B bytes 本根THK的时间承诺
root_thk_signature 64B bytes L1根密钥SM2签名
──────────────────────────────────────────────────────────
合计：176B

**time_commitment计算：**
time_commitment = H(
BE64(t_utc) ∥ // 物理时间（纳秒）
BE64(t_epoch) ∥ // TI起始值
l1_node_id(32B) ∥ // L1节点标识（SM3(L1公钥)）
nonce(16B) // 随机盐
)

**root_thk_signature签名原文：**
signing_payload =
"Prime.RootTHK.v1"(16B) ∥
BE64(t_utc) ∥
BE64(t_epoch) ∥
BE64(ti_range_start) ∥
BE64(ti_range_end) ∥
prev_root_commitment(32B) ∥
time_commitment(32B)
root_thk_signature = Sign(sk_root_L1, H(signing_payload))

**根THK链完整性规则：**
∀ n ≥ 1：
rTHK_n.prev_root_commitment = rTHK\_{n-1}.time_commitment
rTHK_n.ti_range_start = rTHK\_{n-1}.ti_range_end
rTHK_n.t_utc > rTHK\_{n-1}.t_utc
Verify(pk_root_L1, rTHK_n) = 1

创世根THK（n=0）：
prev_root_commitment = 0x00 × 32
ti_range_start = 1（TI从1开始，0保留）

### 2.3 子THK（Child TimeHashKey）

子THK从根THK派生，适用于高频业务场景和细粒度时序需求。子THK的签名使用操作密钥（见§2.4）。

**数据结构（208B）：**
字段 长度 类型 说明
──────────────────────────────────────────────────────────
parent_root_thk_id 32B bytes 父根THK的time_commitment
t_utc 8B uint64 BE 签发时的物理时间（纳秒）
ti_range_start 8B uint64 BE 子THK覆盖TI起始
ti_range_end 8B uint64 BE 子THK覆盖TI结束（不含）
sub_sequence 4B uint32 BE 子THK在父THK内的序号（从1开始）
max_issuance_delay 4B uint32 BE TI使用时效（秒）。
与sub_sequence聚合为8B控制块。
从ChildTHK签发时刻起，TI段内的每个TI
必须在max_issuance_delay秒内用于签发EEA。
超过时效的TI被验证方拒绝。
0=无限期（向后兼容）。
作用范围：约束L2在收到TI段后必须按时消费，
但不约束不同L2节点之间的并行消费速率差异。
target_node_fp 32B bytes 目标L2节点指纹（可为全零=通用）
nonce 16B bytes CSPRNG随机数
child_commitment 32B bytes 子THK承诺
child_thk_signature 64B bytes L1操作密钥SM2签名
──────────────────────────────────────────────────────────
合计：208B
固定二进制布局直读（决策019）。无protobuf双表示。

**child_commitment计算：**
child_commitment = H(
parent_root_thk_id(32B) ∥
BE64(t_utc) ∥
BE64(ti_range_start) ∥
BE64(ti_range_end) ∥
BE32(sub_sequence) ∥
BE32(max_issuance_delay) ∥
nonce(16B)
)

**child_thk_signature签名原文：**
signing_payload =
"Prime.ChildTHK.v1"(17B) ∥
parent_root_thk_id(32B) ∥
BE64(t_utc) ∥
BE64(ti_range_start) ∥
BE64(ti_range_end) ∥
BE32(sub_sequence) ∥
BE32(max_issuance_delay) ∥
target_node_fp(32B) ∥
child_commitment(32B)
child_thk_signature = Sign(sk_op_L1, H(signing_payload))

**子THK防重放机制：**

* L1节点 MUST 记录每个父根THK下已签发的最大 `sub_sequence` 值，新签发的子THK的 `sub_sequence = max+1`
* 子THK签发历史记录（至少30天）持久化存储
* 验证方 SHOULD 检查是否已见过相同 `(parent_root_thk_id, sub_sequence)` 对，若存在则拒绝（返回 E009）

### 2.4 操作密钥证书（OpCertificate）

操作密钥（`sk_op_L1`）与根密钥（`sk_root_L1`）分离，用于签发子THK，可更频繁轮换。操作密钥的有效性通过 OpCertificate 传递信任。

**OpCertificate 结构（216B）：**
字段 长度 类型 说明
──────────────────────────────────────────────────────────
op_cert_id 32B bytes H("Prime.OpCertID.v1" ∥ issuer_root_fp ∥ op_pubkey ∥ valid_from ∥ valid_until ∥ key_version_op ∥ allowed_ops)
issuer_root_fp 32B bytes 签发方L1根指纹
op_pubkey 64B bytes 操作公钥（SM2）
valid_from 8B uint64 BE 生效TI
valid_until 8B uint64 BE 失效TI
key_version_op 4B uint32 BE 操作密钥版本号
allowed_ops 2B uint16 BE 允许操作：0x01=签发子THK
reserved_future 2B bytes MUST=0·与key_version_op+allowed_ops聚合8B控制块（uint32→uint16→pad）
root_sig 64B bytes 根密钥SM2签名
──────────────────────────────────────────────────────────
合计：216B（固定二进制布局直读，决策019）

**OpCertificate 签名原文：**
signing_payload =
"Prime.OpCert.v1"(15B) ∥
issuer_root_fp(32B) ∥
op_pubkey(64B) ∥
BE64(valid_from) ∥
BE64(valid_until) ∥
BE32(key_version_op) ∥
BE16(allowed_ops) ∥
reserved_future(2B) MUST=0
root_sig = Sign(sk_root_L1, H(signing_payload))

**子THK验证的信任链：**
验证子THK时，MUST 执行以下步骤：
Step 1 验证 parent_root_thk_id 对应的根THK存在且有效
Step 2 验证 OpCertificate（操作密钥证书）有效：
① root_sig 有效（根密钥签名）
② valid_from ≤ current_TI < valid_until
③ allowed_ops 包含 0x01（签发子THK）
Step 3 使用 OpCertificate.op_pubkey 验证 child_thk_signature
Step 4 验证子THK的 TI 段在父根THK范围内

没有有效 OpCertificate 的操作密钥签发的子THK视为无效（E005）。

### 2.5 分层THK使用规则

规则一：TI段不重叠
同一L1域内，所有根THK和子THK的TI段不得重叠
L1节点维护TI分配注册表（持久化存储），防止重复分配

**V4.1 安全修订：L1 状态持久化**

以下 L1 状态必须持久化存储——使用 WAL（Write-Ahead Log）保证崩溃安全性。重启时从持久化 checkpoint 恢复——不允许从 initial_counter 重建。

| 状态 | 持久化方式 | 崩溃安全 |
|----|----|:---:|
| epoch_id | WAL write -> fsync -> commit | 重启恢复最后 committed epoch |
| KeyPackage 签发记录 | WAL + snapshot | 恢复所有有效 KP |
| 节点注册表 | WAL + snapshot | 恢复注册表·心跳时间重置 |
| TI 分配器 checkpoint | 每次分配后 fsync | 杜绝重启后 TI 重复发放 |

Tier-1 控制面认证模型见 RFC-SEC-001 §2。

分配请求需在注册表中记录，跨节点请求通过序列化处理

规则二：子THK的TI段在父根THK范围内
cTHK.ti_range_start ≥ rTHK.ti_range_start
cTHK.ti_range_end ≤ rTHK.ti_range_end

规则三：L2节点对KeyPackage承载子THK的验证能力
L2节点收到KeyPackage（承载一个子THK）时，MUST验证：
① KeyPackage.package_signature有效（L1根密钥签名）
② KeyPackage.target_node_fp == 自身节点指纹（确认凭证发给本节点）
③ KeyPackage.child_thk_commitment对应的子THK：child_thk_signature有效（操作密钥及OpCertificate链）
④ 子THK的parent_root_thk_id对应的根THK存在且有效（根密钥）
⑤ 子THK的TI段在根THK范围内
（L2不直接接收裸子THK，子THK通过KeyPackage承载下发）

规则四：通用子THK（target_node_fp = 全零）的限制
通用子THK可由任何L2节点使用。
为防止滥用，L1节点 SHOULD 限制通用子THK的TI段长度（建议≤10,000 TI）。
L2节点使用通用子THK时，MUST 验证该子THK未被撤销。
建议优先签发绑定节点指纹的子THK（target_node_fp = 申请节点指纹）。

规则五：子THK的物理时序精度声明
子THK的t_utc精度：L1操作密钥签发时刻
不保证与根THK.t_utc的偏差 ≤ 20ns
实际精度声明在子THK.nanos_precision字段（预留扩展）

规则六：退化场景（KeyPackage宽限期）
退化场景统一定义为**KeyPackage宽限期**，不存在"L2持有根THK直接签发"的路径（根THK是L1物理锚定凭证，L2不持有；且根THK为1小时粒度，无法满足高频时序精度）：

* 正常：current_wallclock < KeyPackage.valid_until → degraded_mode = 0
* 宽限：valid_until ≤ current_wallclock < valid_until + grace_period
  → degraded_mode = 1，L2仍可用当前KeyPackage承载的子THK的剩余TI段签发EEA
  → 该EEA打degraded标记，提示"L1连接异常期间签发，待校准"
* 超出宽限：current_wallclock ≥ valid_until + grace_period
  → L2 MUST停止签发，重新向L1申请KeyPackage（携带新子THK）

注：宽限期内TI仍取自子THK的ti_range，degraded_mode仅标记凭证续期异常，不改变TI分配基准。

### 2.6 KeyPackage

KeyPackage是L1节点向Tier-2（L2）节点签发的时序使用凭证，**承载一个子THK**并绑定到特定L2节点。L2节点持有KeyPackage作为签发EEA的**唯一时序凭证**：KeyPackage通过`child_thk_commitment`绑定其承载的子THK，EEA的TemporalIndex取自该子THK的TI段。Tier-2节点身份由NodeCertificate和KeyPackage sync请求链路校验。

**KeyPackage与子THK的关系（V2.4）：**

* 根THK（物理锚定，1小时）→ 子THK（细分TI段，约1秒/百万TI）→ KeyPackage（承载子THK，绑定L2）→ L2本地高速签发EEA
* KeyPackage的`child_thk_commitment`引用所承载子THK的`child_commitment`，`package_signature`覆盖该字段，使"KeyPackage↔子THK"的绑定在密码学上不可篡改
* **TI语义分工**：`valid_until`是KeyPackage的**凭证过期时间**（续期信号，墙钟语义，到期L2须重新申请）；子THK的`ti_range_start/end`是**TI分配段**（EEA.TemporalIndex落在此区间）。二者语义不同，不重复

**数据结构（224B，V2.4定稿）：**
字段 长度 类型 说明
──────────────────────────────────────────────────────────
t_epoch 8B uint64 BE 签发时TI
valid_until 8B uint64 BE 凭证过期TI（exclusive，续期信号）
grace_period_seconds 4B uint32 BE 宽限期秒数
key_version 4B uint32 BE L1根密钥版本号·与grace_period聚合8B控制块
issuer_node_id 32B bytes L1 issuer节点ID
root_public_key_hash 32B bytes L1 issuer根公钥哈希
issued_at 8B uint64 BE 签发Unix毫秒时间
child_thk_commitment 32B bytes 承载子THK的child_commitment（V2.4新增）
target_node_fp 32B bytes 绑定的L2节点指纹（V2.4新增）
package_signature 64B bytes L1根密钥SM2签名
──────────────────────────────────────────────────────────
合计：224B（固定二进制布局直读，决策019）

**KeyPackage签名原文：**
signing_payload = KeyPackagePayloadV2_4

KeyPackagePayloadV2_4 = (
BE64(t_epoch) ∥
BE64(valid_until) ∥
BE32(grace_period_seconds) ∥
BE32(key_version) ∥
issuer_node_id(32B) ∥
root_public_key_hash(32B) ∥
BE64(issued_at) ∥
child_thk_commitment(32B) ∥
target_node_fp(32B)
)
payload长度：160B
package_signature = Sign(sk_root_L1, H(signing_payload))

**KeyPackage有效性谓词：**
Valid(KP, t_wallclock, ti) ⟺
Verify(pk_root_L1, H(signing_payload), package_signature) = 1
∧ key_version = current_key_version(L1)
∧ issuer_node_id ∈ trusted_issuer_registry
∧ KP.child_thk_commitment 对应的子THK存在且有效
∧ ti ∈ \[子THK.ti_range_start, 子THK.ti_range_end)   ← EEA.TI落在子THK段
∧ t_wallclock < valid_until                          ← 凭证未过期（续期信号）

注：TI合法性验证基准是**子THK的ti_range**（不是KeyPackage的t_epoch/valid_until）。valid_until仅用于判断凭证是否需要续期。

**§2.6.1 L2签发EEA的凭证规则（唯一凭证原则）：**
L2节点签发EEA时，持有**一个KeyPackage**作为唯一时序凭证，签发流程完全本地化（不与L1交互，这是分层设计的效率来源）：

1. L2验证持有的KeyPackage：`target_node_fp == 自身节点指纹`、`package_signature`有效、未过期
2. 取KeyPackage承载子THK的TI段`[ti_range_start, ti_range_end)`
3. 在该段内本地单调递增分配TemporalIndex
4. 用L2自身私钥签发EEA：`DigitalSignature = Sign(sk_L2_node, ...)`
5. 整个过程不请求L1 → 一次子THK/KeyPackage申请，支撑该TI段内的全部高速签发

三种凭证的角色（消除歧义）：

* 根THK：L1物理时间锚定凭证，**L1自用，不下发L2**
* 子THK：TI分配段的来源，承载在KeyPackage中下发
* KeyPackage：**L2持有的唯一签发凭证**（内部绑定一个子THK）

L2节点**不直接持有根THK**，也不持有裸子THK，只认KeyPackage。

### 2.7 TemporalIndex分配

**分配原则：**
TI空间：uint64，约1.8×10¹⁹个值
按1微秒/TI，可用584,942年，无容量瓶颈

分配策略：
L1节点维护全局TI分配注册表（ti_allocation_registry）
每次分配记录：{接收方指纹, ti_range_start, ti_range_end, 分配时间}
注册表持久化存储，主备节点定期同步

根THK分配：
每次分配 3,600,000,000 个TI（覆盖1小时）
实际按需分配，支持更小或更大的段

子THK分配（按需场景）：
场景A：高频业务节点（金融·AI）
申请：1,000,000 TI/次（约1秒）
频率：按需，每秒最多100次（避免L1成为热点）

场景B：批量事件处理
申请：100,000,000 TI（约100秒）
适用：离线批处理·补签场景

分配碰撞检测：
L1节点MUST检测TI段重叠
收到重叠申请：返回E004（TI段冲突），建议申请紧接着的空闲段

TI 可比性说明：

TI 在同一 L1 域内保证授权唯一性和单调递增——不同 L2 节点从同一 TI 池
分配 TI 段，段的大小顺序反映 L1 的分配顺序，段内 TI 按数值递增分配。
因此同一 L1 域内任意两个 EEA 的 TI 值可直接数值比较。

但"数值可比"不等于"物理时间可比"：
· 有因果链接的事件之间（通过 ChainProof 引用），TI 反映确定的、
可证的先后——因为后继事件必然在被引用事件之后签发，TI 严格递增。
· 无因果链接的事件之间，TI 值仅供数值比较，不代表物理签发先后。
并行消费场景下，较小 TI 值的 EEA 可能在物理时间上晚于较大 TI 值的 EEA。
此类事件构成偏序，先后不被定义（见 P2 §3.4.2）。

需要事件的物理签发时刻：通过 EEA.TI 回溯至所关联 ChildTHK.t_utc（段级精度）。
更高精度（事件级）需独立向国家授时中心获取——EEA 自身不携带 per-event t_utc 字段。

多L1域的TI空间：
不同L1域的TI空间相互独立，允许重叠
（这是因果宇宙设计的关键：不同宇宙的TI没有可比性）
跨域事件的先后关系通过接触面记录（CSR）而非TI比较确定

---

### 2.8 KeyPackage 续期与消费声明

L2 节点在 KeyPackage 过期前 MUST 向 L1 申请续期，获取新的 KeyPackage。

**续期请求 MUST 附带上一段 TI 的消费摘要：**

```
消费摘要（ConsumptionSummary）：
  prev_kp_id             32B  上一 KeyPackage 的 package_signature 或唯一 ID
  ti_consumed            uint32  上一段实际消费的 TI 数量
  last_eea_anchor_id     32B  上一段最后一个 EEA 的 AnchorID
  last_eea_ti            uint64  该 EEA 的 TemporalIndex
```

**L1 验证规则：**

1. 用 `last_eea_anchor_id` 追溯 L2 的 EEA 链（通过 ChainProof 验证链完整性）
2. 统计上一 TI 段内实际签发的 EEA 数量 → 比对 `ti_consumed`
3. 计算利用率 = `ti_consumed / (ti_range_end - ti_range_start)`
4. 利用率为 0 时 L1 MAY 拒绝续期（未使用 TI 段 → 无需求信号）
5. L1 将利用率写入信誉注册表

**信誉动态调节：**

```
利用率阈值（建议值）    KeyPackage 段大小    KeyPackage 有效期
────────────────────────────────────────────────────
≥ 50%                   标准段                标准有效期
< 50%, ≥ 10%            标准段 × 0.5          有效期 × 0.5
< 10%                    最小段                最小有效期
= 0（连续两次）          MAY 拒绝续期           —
```

**设计边界：**

* L1 不做自动处罚——只做统计和段大小动态调节
* 利用率低可能是业务量低，非必然作恶
* 降级可逆：利用率恢复 → 信誉恢复 → 段恢复
* L1 的信誉注册表是所有业务系统的公共参考——持续低利用率的 L2 在市场选择中被自然淘汰
* 本机制不增字段、不改二进制布局。消费摘要以 KeyPackage 续期请求参数形式传递

**已知残余风险（透明度边界）：**

L2 自主签发权必然携带两类不可消除的残余风险。协议不做技术防御——恶意不可用技术控制——
但通过透明度使行为可见，使代价可计算。

1. **TI 回溯签名：** L2 在 KeyPackage 有效窗口内可用任意未消费 TI 签发 EEA，
   无需按物理时间顺序。ChainProof 链完整性检查通过（链接正确），
   TI 单调性检查通过（尚未使用），续期声明通过（消费了 N 个）。
   协议层无条件检测 TI 是否在物理时间上被延迟消费。

2. **EEA 延迟发布：** L2 可合法签发 EEA 后扣留不发布。EEA 密码学完全正确，
   外界无法判断签发时刻与发布时刻之间的延迟。

**透明度机制（应用层对照）：**

* 业务系统同时接入多个 L2 → 同一事件获取多条 EEA →
  比较接收时间戳与 TI 值 → TI 更小但接收更晚 = 矛盾暴露
* 业务系统站在"接收端"，知道哪条 EEA 何时到手，
  是 L2 延迟行为的最佳见证者

**归责边界：**

* 跨 L2 对照能做到：暴露矛盾——两个 L2 对同一事件的 TI 值差异超过正常窗口
* 跨 L2 对照做不到：判断谁是作恶方——两个将军问题，无第三个诚实节点则无法归责
* 生态淘汰：业务系统拒绝延迟/回溯方的 EEA，迁移到诚实 L2；
  持续异常 → L1 信誉降级 → 段缩小 → 自然淘汰

---

## 3. 单域：节点管理

### 3.1 L1节点要求

硬件要求（MUST）：
授时：北斗/NTSC专线授时，精度≤20ns
HSM：GM/T 0028第四级，×2（主+热备）
网络：专线，不通公网
物理安全：机房双门禁·视频监控·防电磁泄漏

操作要求（MUST）：
双人授权：所有根密钥操作需两名授权人员同时在场
密钥分片：根密钥采用Shamir(3,5)分片存储
密钥轮换：根密钥每年轮换，轮换期间双密钥并行（Overlap 30天）
审计日志：所有签名操作记录，保留10年

可用性要求：
正常模式：99.99%可用性（年停机≤53分钟）
故障切换：主→热备≤30秒自动切换
降级触发：与授时源断联>5分钟，触发降级模式

### 3.2 L2节点认证

申请流程：
Step 1 L2节点运营方提交申请（含节点公钥·硬件证明·运营资质）
Step 2 天枢时源科技有限公司技术审查（硬件·软件·合规）
Step 3 通过后，L1节点签发NodeCertificate
Step 4 L2节点进入30天观察期（监控异常行为）
Step 5 观察期通过，正式上线

**吊销（运营决策，非协议自动触发）：**

L1 运营方可基于以下治理原因停止向 L2 节点签发新 KeyPackage：

* 多业务系统举报并经人工核实
* 监管/执法指令
* 持续信誉异常且无改善（P1 RFC §2.8 信誉调节机制无法纠正）

吊销后：

* 已有 EEA 密码学有效（签发时 KeyPackage 合法）——历史不可篡改
* L2 无法再签发新 EEA（无新 KeyPackage → 无 TI 段）
* KeyPackage 过期后，该 L2 的所有 EEA 链自然终止

触发条件由 L1 运营方人工判定。协议不规定"何时吊销"——
那是人类社会仲裁，不是密码学可编程逻辑。

NodeCertificate结构：
node_fingerprint(32B) = H(node_public_key)
node_level(1B) = 2（L2）
node_type(1B) = 见NodeType枚举
valid_from(8B) TI
valid_until(8B) TI
allowed_ext_types(N×2B) 允许签发的extension_type列表
allowed_contact_signing(1B) 0=不可签署CSR，1=可签署（见§4.4）
node_cert_signature(64B) L1根密钥签名

### 3.3 降级模式

**触发条件：** L2节点与L1节点连接中断，或当前KeyPackage即将过期（剩余<宽限期）。
降级流程：
Step 1 L2节点检测到L1连接中断或KeyPackage即将过期
Step 2 切换到本地逻辑时钟（单调递增计数器）
Step 3 后续签发的EEA：degraded_mode=1
Step 4 生成DegradedModeRecord（extension_type=0x0011）
记录：降级开始TI·原因·本地计数起始值
Step 5 L1连接恢复后：
① 申请新KeyPackage（包含降级期间的TI补偿段）
② 执行TI映射（参考实施例5的M3公式）
③ 广播降级映射表至关联L2节点
④ DegradedModeRecord记录恢复时间

高安全场景处理降级EEA：
SHOULD接受（不直接拒绝），但标注"含降级时段"
MAY拒绝（司法·金融高安全场景）：由验证方策略决定
拒绝时返回W005（降级时段EEA）

---

## 4. 多域：因果宇宙互认（Federation）

**设计前提：L1 节点独立运行。** 多个 L1 节点各自拥有独立的原子钟，相互之间存在纳秒级微观偏差。Gnomon 不接受"L1 集群统一对时"的设计——NTP 的 stratum 1 之间也不互相对齐。L1 节点之间不选举、不协商、不投票、不交换 THK。联盟机制（Federation）解决的不是"时钟对齐"问题，而是"互信互认"问题——在不需要统一 TI 空间的前提下，让不同因果宇宙的事件可以建立因果关系。

### 4.1 联盟基本原则

**原则一：平等主权**
每个L1节点体系是独立的因果宇宙（Causal Universe）
联盟成员之间地位平等，无全局根节点
（类比：ITU成员国平等，无"超级成员"）

**原则二：TI空间独立**
不同因果宇宙的TI空间相互独立，不需要同步
TI只在本宇宙内有意义
跨宇宙的先后关系通过接触面记录（CSR）建立，而非TI比较

类比（相对论）：
不同参考系有自己的时间轴
参考系间的因果关系通过事件的光锥（接触面）确定
没有绝对同时性，只有因果关系是绝对的

**原则二·bis：节点级量的跨宇宙连续性**

L2 节点切换 L1（换 KeyPackage）时，节点级的量保持连续、不重置：

| 量 | 切换后 | 依据 |
|----|----|----|
| ST（SequenceToken） | 同一 OriginFP 下严格单调递增，切宇宙不重置 | RFC-P2 §2.1 |
| ChainProof | 新宇宙第一个锚点 MUST 链旧宇宙最后一个锚点（同一 OriginFP 前序），不重置为 Genesis | RFC-P2 §3.3 |

只有宇宙级的量（TI）跨宇宙独立（允许重叠，偏序）。节点级连续 + 宇宙级独立，共同构成"切换点可识别"的基础——链上相邻两锚点 KeyPackage 追溯到不同 L1 的链接即切换事件。

**原则三：最小互认**
联盟互认只需要三件事：
① 互信：成员互相信任对方的根公钥（公钥交换·联盟宪章锚定）
② 互验：成员能验证对方体系下的THK签名和EEA签名
③ 互联：跨域协作事件通过CSR记录接触面（双方各自签名）

不需要：
✗ 统一TI空间
✗ 时序同步协议
✗ 全局共识机制
✗ 跨域事件的物理时间排序

**原则四：因果宇宙边界**
同一因果宇宙内：TI 值可比（授权唯一性），不保证物理时间排序
所有事件有唯一的 TI 数值，并行消费时 TI 值大小 ≠ 物理先后

不同因果宇宙之间：偏序（partial order）
没有跨宇宙接触面时：事件间无先后关系（无法比较）
有跨宇宙接触面时：接触面后的事件可以通过CSR追溯因果关系

正式定义：
设 E_A ∈ 宇宙A，E_B ∈ 宇宙B
E_A ≺ E_B（A的事件先于B的事件），当且仅当：
∃ 接触面CSR，使得 E_A ≺ CSR.eea_A ∧ CSR.eea_B ≺ E_B

### 4.2 联盟宪章（FederationCharter）

联盟宪章是多个L1节点共同签署的互认协议，是联盟的密码学基础。

**FederationCharter结构：**
字段 长度 说明
──────────────────────────────────────────────────────────
charter_id 32B H(全部内容)，宪章唯一标识
charter_version 4B uint32，从1开始
effective_ti 8B 宪章生效时间（发起方宇宙TI）
expiry_ti 8B 宪章到期时间（0=长期有效）
member_count 2B uint16，成员数量
members\[N\] N×96B 每个成员：l1_fp(32B)+l1_pubkey(64B)
governance_rules_hash 32B H(治理规则文本)
amendment_threshold 1B 修改宪章所需最低同意票数
charter_content_hash 32B H(以上所有字段)
signatures\[N\] N×64B 每个成员的SM2签名
──────────────────────────────────────────────────────────
最小配置（2个成员）：
固定字段：87B
成员列表：2×96B = 192B
签名列表：2×64B = 128B
合计：407B

**宪章签名规则：**
每个成员的签名原文：
signing_payload =
"Prime.FedCharter.v1"(19B) ∥
charter_id(32B) ∥
charter_content_hash(32B) ∥
member_l1_fingerprint(32B) // 签名方自己的指纹
signature = Sign(sk_root_L1_member, H(signing_payload))

宪章生效条件：
所有成员签名均有效
生效后charter_id成为联盟信任锚

amendment_threshold 取值：
SHOULD 满足 ceil(member_count/2) ≤ amendment_threshold ≤ member_count
若未指定，默认为 ceil(2\*member_count/3)（绝对多数）

宪章修改：
需要 ≥ amendment_threshold 个成员签署修改提案
修改提案包含：原charter_id + 变更内容 + 新charter_id
历史宪章永久保留（Append-only）

### 4.3 联盟成员互认协议

**步骤一：公钥交换**
联盟宪章包含所有成员的根公钥（l1_pubkey）
成员加入联盟时，将其根公钥写入宪章
宪章被所有成员签署后，公钥交换完成

本地存储：
每个L1节点维护 federation_trust_store：
{charter_id, member_l1_fp, member_l1_pubkey, valid_from, valid_until}
信任来源：已签署的FederationCharter（密码学可验证）

**步骤二：跨域THK验证**
当L2节点收到来自宇宙B的EEA时：

若EEA.origin_fingerprint对应已知的宇宙B的L2节点：
Step 1 查询宇宙B L2节点的NodeCertificate
Step 2 NodeCertificate的签名由宇宙B的L1根密钥签发
Step 3 宇宙B的L1根密钥在FederationCharter中可查（联盟互认）
Step 4 验证链：EEA → NodeCert → L1_B根公钥 → FederationCharter
Step 5 验证通过：该EEA在宇宙B内有效（不意味着与宇宙A的时序可比）

**步骤三：FederationMemberRecord（FMR）广播**
联盟成员发生变更（新成员加入·成员退出·根密钥更新）时：
发起方签发FMR，广播至所有联盟成员

FMR结构：
charter_id(32B) 关联的联盟宪章
event_type(1B) 0x01=加入 0x02=退出 0x03=密钥更新
member_l1_fp(32B) 变更的成员指纹
new_l1_pubkey(64B) 新公钥（仅密钥更新时）
effective_ti(8B) 变更生效时间（发起方宇宙TI）
announcement_sig(64B) 发起方签名
quorum_sigsM 其他成员的确认签名（M ≥ amendment_threshold）

**联盟成员驱逐后THK失效机制：**
驱逐决议通过后，发起方发布 FMR（event_type=0x02），附有驱逐原因哈希。
所有联盟成员 MUST 在收到 FMR 后立即将该 L1 节点的根公钥加入黑名单，
拒绝接受该节点签发的任何新 THK（包括根THK和子THK）。

历史 THK 仍有效（时序切割原则）：驱逐时间点之前签发的 THK 和 EEA
仍然可以被验证（使用历史公钥存档）。

黑名单通过 FMR 广播传播，每个成员定期拉取最新黑名单增量。

### 4.4 跨域事件的处理

**跨域协作事件的锚定规则：**
当主体A（宇宙A）与主体B（宇宙B）发生协作时：

选项一（推荐）：双宇宙各自锚定
主体A在宇宙A的L2节点生成EEA_A（TI_A时序）
主体B在宇宙B的L2节点生成EEA_B（TI_B时序）
两个EEA通过CSR关联（见下）

选项二：单宇宙锚定
双方约定使用某一方的宇宙锚定该事件
另一方接受该宇宙的时序作为参考
适用：明确的主从关系（客户→服务方）

原则：
不存在"中立第三方宇宙"强制要求
由业务层决定锚定策略

**CrossDomainContactRecord（CSR）·跨域接触面记录：**
CSR是两个因果宇宙建立因果关系的密码学记录。

结构：
字段 长度 说明
──────────────────────────────────────────────────────────
csr_id 32B H(全部字段)
charter_id 32B 关联的联盟宪章
universe_a_l1_fp 32B 宇宙A的L1节点指纹
universe_b_l1_fp 32B 宇宙B的L1节点指纹
eea_a 32B 宇宙A中的接触面EEA.AnchorID
eea_b 32B 宇宙B中的接触面EEA.AnchorID
ti_a 8B 宇宙A的TI值（冗余，加速查询）
ti_b 8B 宇宙B的TI值（冗余）
contact_type 2B 接触面类型（见ContactType枚举）
contact_hash 32B H(接触面协作内容)
sig_a 64B 宇宙A的L1节点签名（或授权的L2节点）
sig_b 64B 宇宙B的L1节点签名（或授权的L2节点）
──────────────────────────────────────────────────────────
合计：372B

sig_a签名原文：
H("Prime.CSR.v1"(12B) ∥ csr_id(32B) ∥ eea_a(32B)
∥ eea_b(32B) ∥ BE64(ti_a) ∥ BE64(ti_b) ∥ contact_hash(32B))

sig_b签名原文：
sig_a签名原文(156B) ∥ sig_a(64B) // 嵌套，B覆盖A；总计220B

CSR由L2节点签署的权限要求：
若由L2节点签署CSR，该L2节点MUST持有由L1节点签发的NodeCertificate，
且证书中 allowed_contact_signing = 1。
L1节点可委托L2节点签署CSR，但L1节点仍保留事后审计和撤销权。
委托范围应在NodeCertificate中明确（如限定特定contact_type）。

ContactType枚举：
0x0001 合同签署（双方均是当事人）
0x0002 数据交换（信息传递）
0x0003 支付清算（价值转移）
0x0004 AI协作（跨宇宙AI交互）
0x00FF 其他

**CSR的因果语义：**
CSR建立后：
宇宙A中 t_A < TI_A 的所有事件：宇宙B无法直接感知（各自独立）
宇宙B中 t_B < TI_B 的所有事件：宇宙A无法直接感知

接触面之后：
若宇宙B中发生事件E_B'（TI_B' > TI_B）
且E_B'的SemanticAnchor引用了CSR
则可证明：E_A（TI_A）≺ CSR ≺ E_B'

这是唯一需要的跨宇宙因果证明，不需要TI对齐

### 4.5 联盟退出与撤销

成员主动退出：
Step 1 发起方提交退出申请（ExitProposal）
Step 2 联盟其他成员签署确认（≥ amendment_threshold）
Step 3 生效后发布FMR（event_type=0x02）
Step 4 历史CSR永久有效（不受退出影响）
Step 5 退出生效TI之后，退出方的THK不再被联盟成员信任

成员被驱逐（严重违规）：
Step 1 联盟其他成员共同发起驱逐提案
Step 2 需要 ≥ amendment_threshold + 1 个成员签署
Step 3 立即生效（不需要被驱逐方同意）
Step 4 FMR广播（event_type=0x02，含驱逐原因哈希）
Step 5 被驱逐方THK立即失效（视同L1节点被撤销），见§4.3

联盟解散：
所有成员签署解散决议
历史记录永久保留
已签发的所有EEA和CSR继续有效（历史不可撤销）

---

## 5. 协议消息

### 5.1 gRPC服务接口（Protobuf）

```protobuf
// gnomon/v1/prime_federation.proto
syntax = "proto3";
package gnomon.v1;

// ── 分层THK服务 ──────────────────────────────────────────
service PrimeService {
  // L2节点申请KeyPackage（支持子THK）
  rpc RequestKeyPackage(KeyPackageRequest) returns (KeyPackageResponse);

  // 申请子THK（高频场景）
  rpc RequestChildTHK(ChildTHKRequest) returns (ChildTHKResponse);

  // 订阅根THK链更新（流式）
  rpc SubscribeRootTHKChain(THKSubscribeRequest) returns (stream RootTHKMessage);

  // 查询TI分配状态
  rpc QueryTIAllocation(TIQueryRequest) returns (TIQueryResponse);
}

// ── 联盟服务 ──────────────────────────────────────────────
service FederationService {
  // 发布联盟宪章（新建或更新）
  rpc PublishFederationCharter(FederationCharter) returns (GnomonResponse);

  // 查询联盟成员信息
  rpc GetFederationMember(GetMemberRequest) returns (GetMemberResponse);

  // 验证跨域EEA（联盟成员互验）
  rpc VerifyCrossUniverseEEA(CrossVerifyRequest) returns (CrossVerifyResponse);

  // 提交跨域接触面记录（CSR）
  rpc SubmitContactRecord(CrossDomainContactRecord) returns (GnomonResponse);

  // 查询两个宇宙之间的接触面历史
  rpc QueryContactHistory(ContactHistoryRequest) returns (ContactHistoryResponse);

  // 广播联盟成员变更记录（FMR）
  rpc BroadcastMemberRecord(FederationMemberRecord) returns (GnomonResponse);
}

// ── 核心消息定义 ──────────────────────────────────────────
// ★ V4.0/决策019：固定二进制布局（176B）为权威表示，内存直读。
//   protobuf 仅为 RPC 传输包装，不作为 RootTHK 的规范性定义。
message RootTHK {
  uint32 version              = 1;
  uint64 t_utc                = 2;
  uint64 t_epoch              = 3;
  uint64 ti_range_start       = 4;
  uint64 ti_range_end         = 5;
  bytes  nonce                = 6;   // 16B
  bytes  prev_root_commitment = 7;   // 32B
  bytes  time_commitment      = 8;   // 32B
  bytes  root_thk_signature   = 9;   // 64B
}

// ★ V4.0/决策019：固定二进制布局（208B）为权威表示，内存直读。
//   protobuf 仅为 RPC 传输包装。
message ChildTHK {
  uint32 version              = 1;
  bytes  parent_root_thk_id   = 2;   // 32B
  uint64 t_utc                = 3;
  uint64 ti_range_start       = 4;
  uint64 ti_range_end         = 5;
  uint32 sub_sequence         = 6;
  bytes  target_node_fp       = 7;   // 32B，全零=通用
  bytes  nonce                = 8;   // 16B
  uint32 max_issuance_delay   = 11;  // 4B，TI使用时效（秒），0=无限期
  bytes  child_commitment     = 9;   // 32B
  bytes  child_thk_signature  = 10;  // 64B
}

// ★ V4.0/决策019：固定二进制布局（216B）为权威表示，内存直读。
//   protobuf 仅为 RPC 传输包装。
message OpCertificate {
  uint32 version              = 1;
  bytes  op_cert_id           = 2;   // 32B
  bytes  issuer_root_fp       = 3;   // 32B
  bytes  op_pubkey            = 4;   // 64B
  uint64 valid_from           = 5;
  uint64 valid_until          = 6;
  uint32 key_version_op       = 7;   // uint32·@144·4B对齐
  uint32 allowed_ops          = 8;   // uint16·@148·2B对齐（proto3无uint16·uint32承载）
  bytes  reserved_future      = 10;  // 2B·MUST=0·与key_version_op+allowed_ops聚合8B
  bytes  root_sig             = 9;   // 64B·@152·8B对齐
}

message FederationCharter {
  uint32 version               = 1;
  bytes  charter_id            = 2;   // 32B
  uint32 charter_version       = 3;
  uint64 effective_ti          = 4;
  uint64 expiry_ti             = 5;
  repeated FederationMember members = 6;
  bytes  governance_rules_hash = 7;   // 32B
  uint32 amendment_threshold   = 8;
  bytes  charter_content_hash  = 9;   // 32B
  repeated bytes signatures    = 10;  // 每个成员64B
}

message FederationMember {
  bytes  l1_fingerprint = 1;  // 32B
  bytes  l1_public_key  = 2;  // 64B
  string domain_name    = 3;  // 人类可读域名（如"CN-NTSC"）
  uint64 join_ti        = 4;  // 加入时的TI（发起方宇宙）
}

// ★ V4.0/决策019：CSR 为边界案例——关键（跨宇宙因果证据）。
//   核心字段（core_contact）趋向固定布局直读。
message CrossDomainContactRecord {
  uint32 version             = 1;
  bytes  csr_id              = 2;   // 32B
  bytes  charter_id          = 3;   // 32B
  bytes  universe_a_l1_fp    = 4;   // 32B
  bytes  universe_b_l1_fp    = 5;   // 32B
  bytes  eea_a               = 6;   // 32B
  bytes  eea_b               = 7;   // 32B
  uint64 ti_a                = 8;
  uint64 ti_b                = 9;
  uint32 contact_type        = 10;  // uint16
  bytes  contact_hash        = 11;  // 32B
  bytes  sig_a               = 12;  // 64B
  bytes  sig_b               = 13;  // 64B
}

message ChildTHKRequest {
  uint32 version               = 1;
  bytes  node_fingerprint      = 2;  // 32B
  bytes  node_cert_sig         = 3;  // 64B
  bytes  parent_root_thk_id    = 4;  // 32B
  uint64 requested_ti_count    = 5;  // 申请的TI数量
  bool   pinned_to_node        = 6;  // true=target_node_fp填本节点
}

message ChildTHKResponse {
  GnomonResponse response = 1;
  ChildTHK       child_thk = 2;
}

message CrossVerifyRequest {
  uint32 version         = 1;
  bytes  eea_anchor_id   = 2;  // 32B 待验证EEA
  bytes  charter_id      = 3;  // 32B 使用哪个联盟宪章验证
  bool   check_cross_ref = 4;  // 是否检查SemanticAnchor中的跨域引用
}

message CrossVerifyResponse {
  GnomonResponse response        = 1;
  bool           valid           = 2;
  bytes          universe_l1_fp  = 3;  // 32B 所属宇宙的L1指纹
  string         universe_domain = 4;  // 人类可读域名
  uint64         ti_in_universe  = 5;  // 在所属宇宙中的TI值
  repeated bytes cross_ref_status = 6; // 跨域引用验证状态（每个引用一个字节）
  // cross_ref_status 取值：0=未检查 1=有效 2=无效 3=无法验证
}

// ── THK链验证接口 ────────────────────────────────────────
// 新增于 V3.8（P1-2），支持 verify_depth=full 的全链时间校验。

// 验证THK信任链：RootTHK → ChildTHK → KeyPackage → EEA
// 返回每个环节的验证结果，用于 full(3) 深度验证的全链时间校验路径。
rpc VerifyTHKChain(THKChainVerifyRequest) returns (THKChainVerifyResponse);

message THKChainVerifyRequest {
  uint32 version               = 1;
  bytes  eea_anchor_id         = 2;  // 32B 待验证EEA的AnchorID
  uint32 verify_depth          = 3;  // 1=minimal 2=standard 3=full
  uint64 at_ti                 = 4;  // 验证时刻TI，0=使用EEA自身TI
  uint64 current_wallclock     = 5;  // 当前物理时间（纳秒），用于时效检查
}

message THKChainVerifyResponse {
  GnomonResponse response          = 1;
  bool           valid             = 2;
  uint32         verify_depth      = 3;
  bool           root_thk_valid    = 4;   // 根THK有效性
  bool           child_thk_valid   = 5;   // 子THK有效性（含OpCertificate链）
  bool           key_pkg_valid     = 6;   // KeyPackage有效性
  bool           ti_in_range       = 7;   // TI在子THK段内
  bool           delay_check_ok    = 8;   // 时效检查通过（max_issuance_delay）
  string         delay_detail      = 9;   // 时效检查详情文本
  repeated uint32 warnings         = 10;  // 警告码列表
}

// ── THK链验证伪代码 ──────────────────────────────────────
// verify_thk_chain(eea, depth, at_ti, wallclock):
//   1. 获取 EEA → 解析 KeyPackage → 解析 ChildTHK → 解析 RootTHK
//   2. 验证 RootTHK 签名（L1根密钥）
//   3. 验证 RootTHK 链完整性（prev_root_commitment）
//   4. 验证 ChildTHK 签名（OpCertificate 链：根密钥→OpCert→操作密钥→ChildTHK）
//   5. 验证 ChildTHK.TI段 ⊆ RootTHK.TI段
//   6. 验证 KeyPackage.child_thk_commitment == ChildTHK.child_commitment
//   7. 验证 KeyPackage 签名（L1根密钥）
//   8. 验证 EEA.TI ∈ [ChildTHK.ti_range_start, ChildTHK.ti_range_end)
//   9. 若 max_issuance_delay > 0:
//        delta = EEA签发时刻 - ChildTHK.t_utc（转换为秒）
//        if delta > max_issuance_delay: return (false, "TI超过使用时效")
//  10. 返回全链验证结果
```

## 6. 安全考量

### 6.1 单域安全

时间源篡改：
防御：多源授时（北斗+NTSC+本地原子钟），取中位数
检测：THK链中ti_growth_rate异常（偏差>10%触发告警）

根密钥泄露：
防御：GM/T 0028第四级HSM·双人授权·Shamir(3,5)密钥分片
响应：KeyRevocationRecord（0x0012）立即发布
L2节点拒绝旧key_version的KeyPackage

子THK的信任传递：
子THK签名者（操作密钥）可以不同于根密钥
验证方MUST追溯到根THK，验证子THK.parent_root_thk_id有效
不能仅凭子THK签名即接受时序权威
操作密钥的有效性通过OpCertificate保证（§2.4）

子THK防重放：
L1节点记录每个父根THK下的最大sub_sequence，拒绝重复序号
验证方应缓存最近接收的子THK序号，发现重复时拒绝（E009）

### 6.2 联盟安全

恶意成员（联盟内部作恶）：
单一成员无法伪造其他成员的签名
CSR需要双方签名，单方无法构造有效的跨域接触面
驱逐机制：amendment_threshold+1成员可驱逐恶意成员

联盟宪章伪造：
FederationCharter中的所有成员签名均可独立验证
伪造宪章需要伪造所有成员的SM2签名（计算上不可行）

跨域时序欺骗：
攻击者声称宇宙A的事件E_A先于宇宙B的事件E_B
但实际不存在连接E_A和E_B的CSR
→ 防御：跨宇宙先后关系MUST通过CSR证明
没有CSR = 无法声称先后，不是"默认A先于B"

跨域验证中的引用验证：
当 CheckCrossUniverseEEA 请求中 check_cross_ref=true 时，
验证方 SHOULD 检查 EEA.SemanticAnchor 中引用的其他宇宙 Anchor
是否有效（通过对方宇宙的验证节点查询）。
若无法验证（网络不通或对方不响应），返回 W006（FEDERATION_PARTIAL），
并将 cross_ref_status 对应位置标记为 3（无法验证）。

### 6.3 联盟的认识论边界

联盟互认的保证：
"在宇宙B中，EEA_B在TI_B时刻存在且未被篡改"
这是宇宙B内部的保证

联盟互认不保证：
宇宙A和宇宙B的TI值的绝对物理时间对应关系
（两个宇宙的时钟可能有系统性偏差，这是接受的）

设计意图：
联盟只需要"因果关系互认"，不需要"绝对时间对齐"
这是比GPS时间同步更低的要求，也是更正确的设计

## 7. 测试向量

### 7.1 根THK测试向量

python

# 测试向量（使用固定输入，用于验证实现正确性）

# 注意：生产环境使用真实物理时间和CSPRNG

import hashlib

def sm3(data: bytes) -> bytes:
"""SM3（此处用SHA3-256代替演示，生产使用国密实现）"""
return hashlib.sha3_256(data).digest()

# 固定输入

t_utc           = 1748736000000000000  # 固定纳秒时间戳
t_epoch         = 1000000001           # TI起始值
ti_range_start  = 1000000001
ti_range_end    = 4600000001           # 覆盖3,600,000,000个TI
nonce           = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
l1_node_id      = bytes.fromhex("aa" \* 32)
prev_commitment = bytes.fromhex("00" \* 32)  # 第一个根THK

# time_commitment计算

def compute_time_commitment(t_utc, t_epoch, l1_node_id, nonce):
payload = (
t_utc.to_bytes(8, 'big')    +
t_epoch.to_bytes(8, 'big')  +
l1_node_id                   +  # 32B
nonce                            # 16B
)
assert len(payload) == 64
return sm3(payload)

time_commitment = compute_time_commitment(t_utc, t_epoch, l1_node_id, nonce)

# signing_payload（根THK签名原文）

def compute_root_thk_signing_payload(
t_utc, t_epoch, ti_range_start, ti_range_end,
prev_commitment, time_commitment
):
domain_tag = b"Prime.RootTHK.v1"  # 16B
payload = (
domain_tag                          +
t_utc.to_bytes(8, 'big')           +
t_epoch.to_bytes(8, 'big')         +
ti_range_start.to_bytes(8, 'big')  +
ti_range_end.to_bytes(8, 'big')    +
prev_commitment                     +  # 32B
time_commitment                        # 32B
)
assert len(payload) == 16+8+8+8+8+32+32  # = 112B
return sm3(payload)

signing_payload = compute_root_thk_signing_payload(
t_utc, t_epoch, ti_range_start, ti_range_end,
prev_commitment, time_commitment
)

print(f"time_commitment:   {time_commitment.hex()}")
print(f"signing_payload_h: {signing_payload.hex()}")

# 实现方MUST与此输出一致（使用相同的SM3实现）

### 7.2 KeyPackage测试向量

python

# KeyPackage测试向量

t_epoch         = 1000000001
valid_until     = 1003600001
grace_period_seconds = 300
issuer_node_id  = bytes.fromhex("aa" \* 32)
root_public_key_hash = bytes.fromhex("cc" \* 32)
key_version     = 1
issued_at       = 1716000000000

kp_payload = (
t_epoch.to_bytes(8, 'big')         +
valid_until.to_bytes(8, 'big')     +
grace_period_seconds.to_bytes(4, 'big') +
issuer_node_id                     +  # 32B
root_public_key_hash               +  # 32B
key_version.to_bytes(4, 'big')     +
issued_at.to_bytes(8, 'big')       +
child_thk_commitment               +  # 32B V2.4
target_node_fp                       # 32B V2.4
)
assert len(kp_payload) == 160
kp_signing_hash = sm3(kp_payload)
print(f"KeyPackage signing hash: {kp_signing_hash.hex()}")

## 8. 错误码

text
P1协议专属错误码：

E001  L1_SIG_INVALID         L1节点签名验证失败
E002  KEYPKG_EXPIRED         KeyPackage已过期
E003  KEYPKG_KEY_VERSION     KeyPackage的key_version与当前根密钥不符
E004  TI_RANGE_CONFLICT      申请的TI段与已分配段重叠
E005  CHILD_THK_PARENT_INVALID 子THK的parent_root_thk_id无效
E006  THK_CHAIN_BROKEN       THK链prev_commitment不连续
E007  NODE_NOT_REGISTERED    L2节点未注册（NodeCertificate不存在）
E008  NODE_CERT_REVOKED      L2节点证书已撤销
E009  CHILD_THK_REPLAY       子THK的sub_sequence重复（防重放失败）
E010  OP_CERT_INVALID        操作密钥证书无效或过期

联盟协议专属错误码：

E050  CHARTER_NOT_FOUND      联盟宪章不存在
E051  CHARTER_SIG_INVALID    宪章签名验证失败（不足成员签署）
E052  MEMBER_NOT_IN_CHARTER  成员不在宪章中
E053  CSR_SIG_A_INVALID      CSR的sig_a验证失败
E054  CSR_SIG_B_INVALID      CSR的sig_b验证失败
E055  MEMBER_REVOKED         联盟成员已退出或被驱逐
E056  QUORUM_NOT_MET         联盟治理决定未达法定人数

警告码：

W001  DEGRADED_MODE_ACTIVE   当前处于降级模式
W002  KEY_EXPIRY_SOON        根密钥即将过期（<30天）
W003  THK_GAP_DETECTED       THK链出现时间间隔异常
W004  CHILD_THK_PRECISION    子THK精度低于根THK（可接受）
W005  DEGRADED_EEA           目标EEA产生于降级时段
W006  FEDERATION_PARTIAL     跨域验证仅部分联盟成员确认或跨域引用无法验证

## 9. 版本历史

版本	日期	说明
V3.8	2026-06-18	P1改进：ChildTHK新增max_issuance_delay字段（4B，TI使用时效），204B→208B；child_commitment和child_thk_signature签名原文覆盖新字段；增加verify_thk_chain接口（THK链全链验证），支持verify_depth=full全链时间校验。
V4.2	2026-08-02	基线V4.1→V4.2：头尾版本号·日期·全局标注对齐至v4.2·2026-08-02。无协议内容变更。
V4.1	2026-07-20	安全修订：L1状态持久化（WAL·epoch_id·TI分配器checkpoint——重启不得从initial_counter重建）；Tier-1控制面认证模型见RFC-SEC-001 §2。
V4.0	2026-06-20	D2结案：新增§2.8 KeyPackage续期消费声明与信誉调节机制——续期MUST附带TI消费摘要，L1统计利用率并动态调节段大小；不增字段、不改二进制布局。全序/偏序措辞统一为"TI值全局可比·授权唯一性+因果偏序"（§1/§2.5/§4）。RootTHK 168B→176B修正。来源：盲测B反馈+全协议Mills审查。
V1.3	2026-06-13	KeyPackage承载子THK绑定，闭合"子THK→KeyPackage→L2"密钥链（修复文档间断裂）：KeyPackage新增child_thk_commitment(32B)+target_node_fp(32B)，160B→224B，签名载荷96B→160B覆盖绑定字段；TI语义厘清（方案③）——valid_until为凭证过期/续期信号，EEA.TemporalIndex验证基准改为子THK的ti_range；新增§2.6.1唯一凭证原则（L2只认KeyPackage，本地高速签发）；规则三改为L2对KeyPackage承载子THK的验证；规则六退化场景统一为KeyPackage宽限期，删除"L2持有根THK直接签"路径（违背密钥分层）。来源：盲测中L2实现者发现KeyPackage与子THK关系未串联的文档缺口。
V1.2	2026-06-04	收敛KeyPackage为V2.3运行时结构：160B总长、96B签名载荷，统一valid_until/exclusive窗口、grace_period_seconds、issuer_node_id、root_public_key_hash、key_version、issued_at和package_signature；明确节点绑定由NodeCertificate与同步请求链承担；修正OpCertificate为214B并消除op_cert_id内容哈希歧义。
V1.1	2026-06-03	补充子THK操作密钥信任传递（OpCertificate）；明确通用子THK使用限制；补充sub_sequence防重放机制；明确CSR由L2节点签署的权限要求（allowed_contact_signing）；补充联盟驱逐后THK失效广播机制；跨域验证增加跨域引用检查参数；新增错误码E009、E010；新增警告码W006
V1.0	2026-06	正式版·设计冻结。完整定义：分层THK（根THK+子THK）·KeyPackage·TI分配·L1节点要求·联盟基本原则·FederationCharter·CSR跨域接触面记录·gRPC服务接口·测试向量·错误码。因果宇宙互认模型（不统一TI·偏序而非全序）。

---

## 发布复核事项（非规范性）

V4.4 源规范仍有两项发布前澄清事项：

1. `KeyPackage.valid_until` 字段表将其描述为排他的 TI 值，但其他条款又按墙上时钟比较。需确认其单位和比较域。

2. 源 Protobuf 摘录在 `FederationService` 中重复声明 `VerifyCrossUniverseEEA`。正式发布的 Schema 应保留一项声明，并确认其字段编号契约。

---

*RFC-P1-001 —* RFC-P1-001 — 日冕系统（天枢）协议 v4.4· *GnomonSystem 协议基线 v4.4 · 中文 · 2026-10-21*
