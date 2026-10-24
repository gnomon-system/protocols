# RFC-P2-001 — *日冕系统（天璇）协议 v4.4* 

**GnomonSystem 协议基线 v4.4**

## 摘要

本文件定义Gnomon System的P2层——天璇协议（Polaris Protocol）。

天璇协议解决一个核心问题：**如何让任意数字事件的存在性、时序和因果关系，在不泄露业务内容的前提下，对任意第三方不可伪造、不可篡改、可独立验证？**

核心设计：

* **EventAnchor核心字段**：事件存在性锚（Event Existence Anchor），是所有上层证明的时序基础
* **ChainProof**：链式因果哈希，使任何历史插入或删除操作密码学可检测
* **VerificationProof**：递归链式哈希，支持 O(1) 复杂度的跨越式因果验证
* **SemanticAnchor**：EEA 承载 P3-P7 上层结构语义的通用接口，事件与主体·内容·授权·关系·收益的密码学绑定枢纽
* **语义隔离**：L2节点只存密码学摘要，业务原文不经任何节点

---

## 目录

术语与符号

EEA 数据结构

### 2.1 EventAnchor核心字段

### 2.2 VerificationProof（可选）

### 2.3 SemanticAnchor（可选）

### 2.4 ExtensionHeader（可选）

### 2.5 字段计算顺序

ChainProof 规范

### 3.1 计算方式

### 3.2 链式完整性验证

### 3.3 ChainProof的安全语义

### 3.4 跨L2节点的时序与因果

VerificationProof 规范

### 4.1 计算方式

### 4.2 O(1) 因果验证算法（含Checkpoint机制）

SemanticAnchor 规范

### 5.1 计算方式（SM3·224B）

### 5.2 17种组合规则

### 5.3 验证算法（含深度控制）

### 5.4 层内约束

ExtensionHeader 规范

L2节点行为规范

### 7.1 EEA签发流程

### 7.2 碰撞检测

### 7.3 Pending状态管理

### 7.4 缓存策略

撤销机制

### 8.1 RevocationRecord

### 8.2 广播与传播

### 8.3 降级EEA的处理

验证规范

### 9.0 EEA的自包含验证边界

### 9.1 验证深度

### 9.2 完整验证算法（伪代码）

### 9.3 SemanticAnchor完整验证算法（伪代码）

协议消息（Protobuf）

安全考量

测试向量

错误码与警告码

**V4.1 安全修订：Cluster 重放保护**

Cluster 请求必须包含 x-cluster-nonce 字段（HTTP 头）。接收方维护 300s TTL 的 nonce 缓存。相同 nonce 在缓存期内被拒绝。

nonce 不写入 EEA 192B 固定布局——仅作为 HTTP 层防重放机制。缓存使用 LRU·上限 100,000 条。

**V4.2 协议补全：Genesis 固定根与 Merkle 收敛**

VP_0（genesis VerificationProof）和 ChainProof_root（genesis ChainProof）已定义为协议固定常量——不可协商、不可配置。具体 hex 值见 §2.2 和 §3.3。

多节点锚点集合的 Merkle 树收敛规则由 RFC-SEC-003 §5 定义。P2 节点间复制的一致性校验 MUST 遵循 SEC-003 的 Merkle 叶节点公式和单叶规则。

版本历史

---

## 1. 术语与符号

H(·) SM3哈希函数，256位输出，𝔹\* → 𝔹²⁵⁶
Sign(sk, m) SM2签名，返回 512位签名 σ
Verify(pk, m, σ) SM2验证，返回 {0,1}
BE64(n) 64位大端整数编码，8字节
BE32(n) 32位大端整数编码，4字节
BE16(n) 16位大端整数编码，2字节
∥ 字节串拼接
0ⁿ n个全零字节

EEA Event Existence Anchor，事件存在性锚
AnchorID EEA的全局唯一标识，32B，H(五字段内容)
TI TemporalIndex，uint64单调递增时序值
ChainProof 链式因果哈希，32B
VerificationProof 递归链式哈希，32B，简称VP
SemanticAnchor 结构语义绑定哈希，32B，简称SA
ExtensionHeader 子根协议扩展头，8B固定（统一入口，含reserved_flags）

L2节点 持有KeyPackage，签发EEA的公证节点
origin_fingerprint H(L2节点SM2公钥)，32B，简称OriginFP
SequenceToken L2节点内单调递增序号，uint64，简称ST

域名约定（domain_tag）：
防止不同层签名的跨协议复用
每层签名的原文以唯一ASCII字节串开头
天璇协议：b"Polaris.Anchor.v1"（17字节）

AnchorID 的双角色约定（FactID·AnchorID）：

FactID（对外引用标识）               AnchorID（密码学内部标识）
──────────────────────────────────  ──────────────────────────────────
跨组织传递事件引用                   EEA 内部字段·签名验证
业务文档嵌入（发票旁注 FactID）        ChainProof 计算输入
审计对账（用 FactID 查到事件）         跨层引用（P3 ClaimAnchor→P2 EEA）
网络接口间传递（轻量·32B）             EEA 签发·验证·同步

两者为同一 32B 值，角色不同。
FactID 是 AnchorID 的对外名称——当 EEA 的 AnchorID 被跨组织传递、嵌入业务文档、
或作为对账凭证时，统一以 FactID 称谓，强调其"只传标识、不传内容"的语义隔离原则。

跨 L2 使用：
┌ 同一 L2 内：FactID 支持 TI 值排序（TI 单调递增保证）
└ 跨 L2：FactID 仅支持身份验证（"此事件由某 L2 签发"），不支持排序
排序需 ChainProof 因果链（见 §3.4.2）或独立外部授时

---

## 2. EEA 数据结构

### 2.1 EventAnchor核心字段（192B，固定）

EEA 基础结构由七个核心字段组成，所有字段位置和长度固定，不允许省略。
偏移 长度 字段名 类型 描述
────────────────────────────────────────────────────────────────
0 32B AnchorID bytes\[32\]
计算：H("Polaris.Anchor.v1" ∥ BE64(TI) ∥ OriginFP ∥ BE64(ST) ∥ Salt)
含义：EEA的全局唯一防篡改标识
注意：AnchorID不依赖DigitalSignature，避免签名与AnchorID形成循环依赖。

32 8B TemporalIndex uint64 BE
来源：L2节点当前KeyPackage分配的TI段内取值
约束：同一宇宙内严格单调递增（跨宇宙切换后不要求单调·顺序由 ChainProof 兜底）
TI ∈ \[子THK.ti_range_start, 子THK.ti_range_end)
语义：TI 是 L1 授权的“时序格点”（可回溯到 THK/RootTHK 的时间窗），不是每笔的墙钟时刻读数——对外表述不应说成“精确到微秒的出生时间”。

40 32B OriginFingerprint bytes\[32\]
计算：H(L2_node_SM2_public_key_bytes)
含义：签发本EEA的L2节点的密码学标识
不变量：同一节点的所有EEA具有相同OriginFP

72 8B SequenceToken uint64 BE
规则：同一OriginFP下严格单调递增，从1开始
重启不归零（持久化存储，见§7.1）
切换L1不归零（节点终身连续·见§7.2）
每签发一个EEA加1

80 32B ChainProof bytes\[32\]
计算：见§3.1
含义：与前序EEA的密码学因果链接

112 64B DigitalSignature bytes\[64\]
计算：Sign(sk_L2, e)  // e = SM3(signing_payload) 为预摘要，无 ZA pre-hash 路径（signing_payload 见§2.1.1）
signing_payload：见§2.1.1

176 16B Salt bytes\[16\]
计算：CSPRNG生成
含义：AnchorID随机盐，防止相同TI/ST组合在异常恢复场景中产生可预测AnchorID
约束：MUST由密码学安全随机数生成器产生，MUST随EEA持久化和同步
语义：Salt 是抗预测/恢复用的随机盐，不承载业务语义（不回答“何时/谁/第几笔”）。AnchorID 唯一性的主贡献是 ST 节点内永不复用 + OriginFP + TI；Salt 是兜底熵。
────────────────────────────────────────────────────────────────
合计：192B

#### 2.1.1 DigitalSignature 签名原文（137B）

signing_payload =
b"Polaris.Anchor.v1" (17B) domain_tag（防跨协议复用）
∥ AnchorID (32B) 绑定AnchorID，防AnchorID替换
∥ BE64(TemporalIndex) (8B)
∥ OriginFingerprint (32B)
∥ BE64(SequenceToken) (8B)
∥ ChainProof (32B)
∥ BE32(key_version) (4B) 节点签名公钥版本
∥ degraded_mode (1B) 0x00=正常窗口 0x01=KeyPackage grace窗口
∥ reserved_future (3B) MUST=0·与key_version+degraded_mode聚合8B控制块
total = 17+32+8+32+8+32+4+1+3 = 137B

e = SM3(signing_payload)
DigitalSignature = Sign(sk_L2, e)

**签名语义（MUST）：** e = SM3(signing_payload) 即 SM2 预摘要，签名采用**无 ZA pre-hash 路径**——SM2 内部不计算 ZA（签名方标识）、不二次 SM3（见 FMD 定义 0.0）。签名随机数 k 按 RFC-SEC-002 §2（RFC 6979 或 CSPRNG 256bit）。

**验证：**
Verify(pk_L2, e, DigitalSignature) == 1

### 2.2 VerificationProof（32B，MAY）

VerificationProof 是可选字段，追加在核心字段之后。
位置：EEA核心字段（192B）之后
长度：32B（固定，若存在）

**计算方式：**
VP_n = H(AnchorID\_{n-1} ∥ VP\_{n-1})

首个EEA（无前序）的VP_0 MUST为以下协议固定常量——不可协商、不可配置：
VP_0 = SM3(0x00 × 64)
= 46b58571be41685c253194d20ec7f82b659cc8c6b753f26d4e9ec85bc91c231e

若前序EEA没有VP字段：
VP_n = H(AnchorID\_{n-1} ∥ 0³²)
使用全零代替前序VP

**存在性规则：**

* 若L2节点支持VP（推荐SHOULD），则所有EEA都包含VP字段
* 不可部分包含（同一节点链内，要么全部包含，要么全部不含）
* 跨节点引用时，VP可以不连续

### 2.3 SemanticAnchor（32B，MAY）

SemanticAnchor 是 EEA 承载上层结构语义的核心连接枢纽，追加在 VP 之后（若VP存在），或核心字段之后（若VP不存在）。
位置：VP字段之后（若有）或核心字段之后
长度：32B（固定，若存在）
全零值：0³² 表示匿名事件，跳过验证

**计算方式（SM3·224B固定输入）：**
SA = H(
AnchorID (32B) 绑定至具体EEA，防跨EEA移植攻击
∥ P3_ref (32B) ClaimAnchor.AnchorID 或 0³²
∥ P4_ref (32B) ScrollAnchor.AnchorID 或 0³²
∥ P5_ref (32B) GrantAnchor.AnchorID 或 0³²
∥ P6_ref (32B) BondAnchor.AnchorID 或 0³²
∥ P7_ref (32B) YieldAnchor.AnchorID 或 0³²
∥ event_data_hash (32B) H(业务数据canonical序列化字节)
)
输入总长：7 × 32B = 224B（固定）

**关键设计：AnchorID 嵌入**

AnchorID 被嵌入 SA 的计算输入，使得相同的 `{P3_ref..P7_ref, event_data_hash}` 参数在不同 EEA 上产生不同的 SA，从而防止跨 EEA 移植攻击（T10）。

完整规范见 §5。

### 2.4 ExtensionHeader（8B，MAY）

偏移 长度 字段名 类型 描述
────────────────────────────────────────────────────────────────
0 2B extension_type uint16 BE 子根协议类型编码
2 1B version uint8 从1开始，单调递增
3 1B hdr_flags uint8 bit0:critical(0=可忽略 1=必须拒绝)
bit1:chain_follows(多扩展链式相关)
bit2:payload_present(0=仅信号 1=带payload)
bit3-7:reserved_future(MUST=0)
4 2B length uint16 BE payload字节数
6 1B compliance uint8 0=未声明对齐 1=uint64 8B对齐·决策017/019
2-255=保留
7 1B reserved_future uint8 MUST=0·为hdr_flags/compliance扩展预留
────────────────────────────────────────────────────────────────
合计头部：8B，payload：length字节

ExtensionHeader 之后紧跟 payload（length 字节）。允许多个连续的 ExtensionHeader。

**协议版本标识：** ExtHeader.version（EEA偏移194，固定）是协议版本的唯一权威标识。
解析器读到 EEA 后立刻定位 ExtHeader → byte\[2\] → 版本号，无需遍历签名原文找 domain_tag。
此设计与 NTP byte\[0\] 同为"固定偏移解析"模式（而非 domain_tag 的"签名内寻址"模式）。
TI/KeyPackage 等 P1 结构的版本显式化归 V5.0。

**已注册的 extension_type（P2层）：**
0x0011 DegradedModeRecord 降级模式记录
0x0012 KeyRevocationRecord 根密钥撤销记录
0x0101 FinancialEEA 金融清算事件
0x0201 GovEEA 政务协同事件
0x0311 JudicialEEA 司法存证事件

### 2.4.1 扩展对齐约定

ExtHeader 头结构固定 8B（MUST），确保扩展入口统一可解析。
子扩展 payload SHOULD 按 8 字节对齐（uint64 落 8B 边界）。
未对齐的子扩展，实现方 MUST 自行处理非对齐内存访问。
新设计的子扩展 RECOMMENDED 遵循甲-full 字段重排原则，
以获得与主干同等的 zero-copy 性能。
当前 MultiSignScroll（0x0402）、RelationTransfer（0x0604）等既有子扩展
的 payload 未强制甲-full 重排，按本约定由实现层处理。

### 2.5 字段计算顺序

EEA 各字段的计算存在依赖关系，MUST 按以下顺序执行：
Step 1 从KeyPackage获取 TI（当前可用TI，递增SequenceToken）
Step 2 计算 ChainProof（依赖前序EEA，见§3.1）
Step 3 生成 Salt（16B CSPRNG）
Step 4 计算 AnchorID = H("Polaris.Anchor.v1" ∥ BE64(TI) ∥ OriginFP ∥ BE64(ST) ∥ Salt)
Step 5 构造 signing_payload 并生成 DigitalSignature
Step 6 计算 VerificationProof（可选，依赖前序VP和前序AnchorID）
Step 7 计算 SemanticAnchor（可选，依赖AnchorID和P3-P7的ref参数）
Step 8 组装ExtensionHeader（可选）
Step 9 将完整EEA写入本地存储，返回AnchorID

\*注：DigitalSignature覆盖AnchorID和ChainProof，但DigitalSignature本身不参与AnchorID计算。
该结构避免了“AnchorID依赖签名、签名又覆盖AnchorID”的循环依赖，同时保留签名对链证明和时序字段的完整保护。

---

## 3. ChainProof 规范

### 3.1 计算方式

**标准ChainProof（有前序EEA）：**
ChainProof_n = H(
AnchorID\_{n-1} (32B) 前序EEA的AnchorID
∥ BE64(TI\_{n-1}) (8B) 前序EEA的TemporalIndex
∥ DigitalSignature\_{n-1} (64B) 前序EEA的签名
)
总输入：104B

**根EEA的ChainProof（无前序）MUST为以下协议固定常量——不可协商、不可配置：**
ChainProof_root = SM3(0x00 × 104)   // 32B AnchorID + 8B TI + 64B signature，全部为零
= 76693c862ce3571fba1a986ea58f58c645464d2469c28f197fa85db54dac4103

**跨节点ChainProof：**

若L2节点A的EEA链以节点B的某EEA为前序（跨节点因果引用），ChainProof计算方式不变，使用节点B的EEA字段值。

### 3.2 链式完整性验证算法

```python
def verify_chain(eeas: list[EEA]) -> tuple[bool, str]:
    """
    验证EEA链的完整性。
    eeas: 按TI升序排列的EEA列表
    返回: (is_valid, error_message)
    
    注意：该算法需要完整的连续EEA序列。若只有首尾EEA，
         需通过VerificationProof实现O(1)因果验证（见§4.2）。
    """
    if not eeas:
        return True, ""

    for i, eea in enumerate(eeas):
        # 1. 验证AnchorID（公式见§2.1.1 Step4：含domain_tag与Salt，不含ChainProof/签名，避免循环依赖）
        expected_anchor_id = H(
            b"Polaris.Anchor.v1"
            + BE64(eea.temporal_index)
            + eea.origin_fingerprint
            + BE64(eea.sequence_token)
            + eea.salt
        )
        if eea.anchor_id != expected_anchor_id:
            return False, f"E001: AnchorID不匹配，位置{i}"

        # 2. 验证DigitalSignature
        signing_payload = (
            b"Polaris.Anchor.v1"
            + eea.anchor_id
            + BE64(eea.temporal_index)
            + eea.origin_fingerprint
            + BE64(eea.sequence_token)
            + eea.chain_proof
            + BE32(eea.key_version)
            + bytes([eea.degraded_mode])
            + bytes(3)  # reserved_future 3B·MUST=0·与key_version+degraded_mode聚合8B控制块
        )
        pk_l2 = get_node_pubkey(eea.origin_fingerprint)  # 查询节点注册表
        if not Verify(pk_l2, SM3(signing_payload), eea.digital_signature):
            return False, f"E002: DigitalSignature无效，位置{i}"

        # 3. 验证ChainProof
        if i == 0:
            # 根EEA：ChainProof = H(0×104)
            expected_cp = H(bytes(104))
        else:
            prev = eeas[i - 1]
            expected_cp = H(
                prev.anchor_id
                + BE64(prev.temporal_index)
                + prev.digital_signature
            )
        if eea.chain_proof != expected_cp:
            return False, f"E003: ChainProof不匹配，位置{i}"

        # 4. 验证TI单调递增（同一宇宙内·跨宇宙切换后跳过）
        if i > 0 and eeas[i-1].origin_fingerprint == eea.origin_fingerprint:
            # 同一宇宙判定：EEA 本身无宇宙字段，issuer 由验证方沿 KeyPackage→ChildTHK→RootTHK 链追溯
            if universe_of(eeas[i-1]) == universe_of(eea):
                if eea.temporal_index <= eeas[i-1].temporal_index:
                    return False, f"E004: TI非单调递增，位置{i}"
            # 跨宇宙切换（issuer 不同）：TI 允许回退，顺序由 ChainProof 兜底

        # 5. 验证SequenceToken单调递增（同一OriginFP）
        if i > 0 and eeas[i-1].origin_fingerprint == eea.origin_fingerprint:
            if eea.sequence_token <= eeas[i-1].sequence_token:
                return False, f"E005: SequenceToken非单调递增，位置{i}"

    return True, ""
```

### 3.3 ChainProof 的安全语义

插入攻击防御：
若攻击者在位置k插入虚假EEA E_fake：
E_fake.chain_proof = H(E\_{k-1}.anchor_id ∥ ...)  可以正确计算
E_k.chain_proof    = H(E\_{k-1}.anchor_id ∥ ...)  原值不变
但 E_k.chain_proof ≠ H(E_fake.anchor_id ∥ ...)
→ 位置k之后所有ChainProof验证失败 → 插入被检测

删除攻击防御：
若攻击者删除位置k的EEA：
E\_{k+1}.chain_proof = H(E_k.anchor_id ∥ ...)
而 E\_{k-1} 是现在的"前序"
H(E\_{k-1}.anchor_id ∥ ...) ≠ E\_{k+1}.chain_proof
→ 删除被检测

替换攻击防御：
若攻击者将E_k替换为E_k'（修改任何字段）：
E_k'.anchor_id ≠ E_k.anchor_id（AnchorID = H(domain_tag ∥ TI ∥ OriginFingerprint ∥ SequenceToken ∥ Salt)）
E\_{k+1}.chain_proof ≠ H(E_k'.anchor_id ∥ ...)
→ 替换被检测

### 3.4 跨L2节点的时序与因果

本节回答一个实现中的核心问题：同一L1节点下的多个L2节点，
各自独立维护EEA链，它们之间的时序与因果关系如何确定。

#### 3.4.1 TI唯一性由L1段分配保证

TI（TemporalIndex）不由L2节点根据本地时钟计算，而由L1节点通过
KeyPackage分配【互不重叠】的TI段。

L1为每个L2节点分配独立的TI段区间，例如：
L2节点A：ChildTHK.ti_range ∈ \[t_a_start, t_a_end)
L2节点B：ChildTHK.ti_range ∈ \[t_b_start, t_b_end)
且区间互不重叠

L2节点签发EEA时，只能使用本节点所承载ChildTHK的TI分配段（ti_range_start\~ti_range_end）。
SequenceToken 节点终身单调递增（切 L1 不归零），保证同一 OriginFP 下 AnchorID 唯一——跨宇宙 TI 重叠由 ST 区分（碰撞键见 §7.2）。

→ 两个L2节点在【同一物理时刻】各自签署EEA时，
使用的是各自TI段内的值，TI全局唯一，永不冲突。

关键原则：TI的全局唯一性是L1段分配的结果，
不依赖L2节点本地时钟的精度或一致性。
L2节点本地时钟仅用于在授权TI段内选择取值，
不参与唯一性保证。

#### 3.4.2 无因果关系的并发事件：先后不定义

两个L2节点的EEA，若彼此【没有相互引用】（无ChainProof因果链接），
则它们的先后顺序【不被定义】，系统也不需要定义。

这是因果宇宙模型（见 P1 RFC §1 术语·§2.7 TI 可比性说明·§4 因果宇宙边界）在 L1 域内的体现：
同一L1域内的事件构成偏序（partial order），而非全序。
只有存在因果链接的事件之间，先后才有意义。

设计理由：
要求为所有并发无关事件确立全序，等价于要求全局共识，
这会引入与因果宇宙模型相悖的同步开销。
Gnomon不追求全序——无因果关系的事件，其先后本就无需仲裁。

对实现的含义：
L2节点A和B同时签署互不引用的EEA，是完全合法的并发事件。
不需要、也不应该尝试为它们确定"谁先谁后"。

#### 3.4.3 跨L2节点的因果引用

当L2节点A的某事件在因果上依赖L2节点B的事件E_B时，
通过跨节点ChainProof建立因果链接：

步骤：
① L2节点A通过节点间同步机制，按需获取E_B
（主动获取目标EEA，非全局实时广播所有节点的EEA）
② A构造新EEA E_A，其ChainProof引用E_B：
E_A.chain_proof = H(E_B.anchor_id ∥ E_B.TI ∥ E_B.digital_signature)
③ 同L2内E_B.TI < E_A.TI保证成立（ChildTHK段顺序·TI单调递增）。
跨L2引用仅保证因果顺序，不保证TI数值大小关系。
需要物理时间参照时，独立通过协议向国家授时中心获取，
不依赖协议内部t_utc——保证证明链与时间参照的信息隔离。

时序保证：
跨节点引用天然满足因果时序——
被引用者（E_B）的存在是引用者（E_A）签署的前提，
引用关系本身就编码了"E_B先于E_A"这一因果事实。

验证：
验证方使用【同一L1节点的公钥】即可验证E_A和E_B双方的签名，
以及E_A对E_B的ChainProof引用，无需额外的跨节点信任假设。

#### 3.4.4 同一L1下的L2节点无需互认

同一L1节点下的L2节点之间【不需要】建立互认关系（不使用CSR）。

原因：
· 共享同一个L1信任根，验证方用同一L1公钥即可验证所有L2的EEA
· TI段均由同一L1分配，天然可比较
· 跨节点因果引用（§3.4.3）已足以表达L2间的因果关系

CSR（CrossDomainContactRecord，见RFC-TIANSHU）仅用于
【不同L1节点】（不同因果宇宙）之间建立接触面。
同一L1域内使用CSR是不必要的。

#### 3.4.5 实现要点小结

· TI唯一性 ← L1段分配，不靠L2本地时钟
· 并发无关事件 ← 先后不定义（偏序）
· 因果依赖 ← 按需获取前序EEA + 跨节点ChainProof
· 同一L1域内 ← 无需L2互认，无需CSR
· 跨节点验证 ← 同一L1公钥即可完成

## 4. VerificationProof 规范

### 4.1 计算方式

VP_n = H(AnchorID\_{n-1} ∥ VP\_{n-1})

递归展开：
VP_0 = 46b58571be41685c253194d20ec7f82b659cc8c6b753f26d4e9ec85bc91c231e  （协议固定常量·见§2.2）
VP_1 = H(AnchorID_0 ∥ VP_0)
VP_2 = H(AnchorID_1 ∥ VP_1)
= H(AnchorID_1 ∥ H(AnchorID_0 ∥ VP_0))
VP_n = H(AnchorID\_{n-1} ∥ H(AnchorID\_{n-2} ∥ ... H(AnchorID_0 ∥ VP_0)...))
VP 是 AnchorID 序列的累积哈希，类似 Merkle 链，但不支持随机访问证明。

### 4.2 O(1) 因果验证算法（含Checkpoint机制）

问题： 证明 EEA_i 在 EEA_j 之前（i < j），不遍历中间节点。

Checkpoint 机制：
为实现真正的 O(1) 验证，L2 节点 SHOULD 每 1000 个 EEA 生成一个 VP checkpoint。
Checkpoint 值（当前 VP）写入该 EEA 的 ExtensionHeader（extension_type=0x0013），
或直接作为该 EEA 的 verification_proof 字段（若支持 VP）。

算法：

python
def verify_causality_o1(
eea_i: EEA,   # 较早的EEA（声称在前）
eea_j: EEA,   # 较晚的EEA（声称在后）
checkpoints: list\[tuple\[bytes, bytes\]\],  # \[(AnchorID, VP)\] 稀疏checkpoints
) -> tuple\[bool, str\]:
"""
O(1)因果验证：证明eea_i先于eea_j。

```
使用checkpoints（每1000个EEA一个）实现跳跃验证。
验证步数 ≈ (j-i)/1000，实际可视为常数。
"""
if eea_i.temporal_index >= eea_j.temporal_index:
    return False, "E006: TI顺序错误"

if eea_i.verification_proof is None or eea_j.verification_proof is None:
    # 降级为ChainProof遍历验证（O(n)）
    return False, "需要VP支持或提供完整中间序列"

# 从eea_i.VP出发，跳跃到最近的checkpoint
current_vp = eea_i.verification_proof
current_anchor = eea_i.anchor_id

# 使用checkpoints跳跃（假设checkpoints按时间顺序排列）
for anchor_id, vp in checkpoints:
    # 验证checkpoint的VP一致性
    expected_vp = H(current_anchor + current_vp)
    if vp != expected_vp:
        return False, "E007: Checkpoint VP验证失败"
    current_vp = vp
    current_anchor = anchor_id

# 最终验证：eea_j.VP应等于H(eea_j前序AnchorID ∥ 累积VP)
# 假设eea_j的前序AnchorID在checkpoints最后一个或通过其他方式获得
prev_anchor_of_j = get_prev_anchor(eea_j.anchor_id)  # 需要提供或从链中获得
expected_vp_j = H(prev_anchor_of_j + current_vp)
if eea_j.verification_proof != expected_vp_j:
    return False, "E008: VerificationProof验证失败，因果关系不成立"

return True, ""
```

# 简化版：若已知两者在同一节点链上，且提供了直接前序

def verify_direct_causality(eea_i: EEA, eea_j: EEA, prev_anchor_of_j: bytes) -> bool:
"""
直接验证：eea_j.VP是否与eea_i存在因果关联。
需要提供 eea_j 的直接前序 AnchorID。
"""
expected_vp = H(prev_anchor_of_j + eea_i.verification_proof)
return eea_j.verification_proof == expected_vp
适用场景：

审计场景：验证"某批次内所有事件已在T时刻之前存在"
→ 提供批次首尾的VP及中间checkpoints，O(1)验证

跨域引用：宇宙B引用宇宙A的某EEA时序位置
→ VP提供紧凑的时序证明，不需要传输完整链

司法场景：证明"合同签署（E_sign）早于纠纷发生（E_dispute）"
→ VP + checkpoint即可完成证明

## 5. SemanticAnchor 规范

### 5.1 计算方式

python
ZERO_32 = b'\\x00' \* 32

def compute_semantic_anchor(
eea_anchor_id:   bytes,           # EEA.AnchorID，32B，MUST
p3_ref:          bytes = ZERO_32, # ClaimAnchor.AnchorID 或全零
p4_ref:          bytes = ZERO_32, # ScrollAnchor.AnchorID 或全零
p5_ref:          bytes = ZERO_32, # GrantAnchor.AnchorID 或全零
p6_ref:          bytes = ZERO_32, # BondAnchor.AnchorID 或全零
p7_ref:          bytes = ZERO_32, # YieldAnchor.AnchorID 或全零
event_data_hash: bytes = ZERO_32, # H(业务数据)，32B
) -> bytes:
"""
计算SemanticAnchor。输入固定为224B，输出32B。
"""
inputs = \[eea_anchor_id, p3_ref, p4_ref, p5_ref,
p6_ref, p7_ref, event_data_hash\]
assert all(len(x) == 32 for x in inputs), "所有输入必须为32B"
payload = b"".join(inputs)
assert len(payload) == 224
return H(payload)
版本控制：

SA_version = 1（当前）：
算法：SM3(224B)
包含：AnchorID + 5个层引用 + event_data_hash

SA_version = 2（预留·后量子）：
算法：PostQuantumHash(224B)（国密局标准发布后定义）
输入结构不变（224B），仅替换哈希算法

版本标识：通过 SemanticAnchorInput.version 字段传递
历史兼容：SA_version=1的记录永久有效（时序切割）

### 5.2 17种组合规则

层组合的完整规则：

单层（2种有意义组合）：
\[P3\]  SM3(AnchorID ∥ P3 ∥ 0³² ∥ 0³² ∥ 0³² ∥ 0³² ∥ event)
语义：某主体的行动
\[P4\]  SM3(AnchorID ∥ 0³² ∥ P4 ∥ 0³² ∥ 0³² ∥ 0³² ∥ event)
语义：内容存在性（匿名）

双层（5种）：
\[P3+P4\]   语义：某主体创建了某内容
\[P3+P5\]   语义：某主体在某授权下执行操作
\[P3+P6\]   语义：某主体在某关系下行动
\[P3+P7\]   语义：某主体获得收益
\[P5+P7\]   语义：在某授权下产生收益（少用）

三层（5种）：
\[P3+P4+P5\]  语义：某主体在授权下创建内容
\[P3+P5+P6\]  语义：某主体基于关系和授权执行操作
\[P3+P4+P7\]  语义：某主体创建内容并获益（版权）
\[P3+P5+P7\]  语义：某主体在授权下执行并获益
\[P3+P6+P7\]  语义：某主体基于关系获益

四层（4种）：
\[P3+P4+P5+P6\]  语义：完整操作（无收益）
\[P3+P4+P5+P7\]  语义：授权内容+收益
\[P3+P5+P6+P7\]  语义：关系+授权+收益
\[P3+P4+P6+P7\]  语义：关系+内容+收益

五层（全层，1种）：
\[P3+P4+P5+P6+P7\]  语义：完整协作事实

特殊（全零）：
\[无\]  SA = 0³²（匿名事件·不绑定任何上层语义）

### 5.3 SA 完整验证算法

python
def verify_semantic_anchor(
eea:            EEA,
sa_input:       SemanticAnchorInput,
verify_depth:   int = 3,  # 1=minimal 2=standard 3=full
) -> VerifyResult:
"""
验证EEA的SemanticAnchor。
返回包含各层验证结果的VerifyResult。

```
注意：验证方MUST从业务系统或可信源获取sa_input参数，
     该参数不存储在L2节点中。
"""
result = VerifyResult()

# Step 1: 特殊值检查
if eea.semantic_anchor == ZERO_32:
    result.valid = True
    result.note = "匿名事件，无语义绑定"
    return result

# Step 2: 重建验证（SM3·224B）
computed_sa = compute_semantic_anchor(
    eea_anchor_id   = eea.anchor_id,
    p3_ref          = sa_input.p3_ref,
    p4_ref          = sa_input.p4_ref,
    p5_ref          = sa_input.p5_ref,
    p6_ref          = sa_input.p6_ref,
    p7_ref          = sa_input.p7_ref,
    event_data_hash = sa_input.event_data_hash,
)
if computed_sa != eea.semantic_anchor:
    return VerifyResult(valid=False, error=E030)

# Step 3: 各层Anchor存在性与类型验证（并行查询）
layer_checks = {
    3: (sa_input.p3_ref, 0x0102, "ClaimAnchor"),
    4: (sa_input.p4_ref, 0x0401, "ScrollAnchor"),
    5: (sa_input.p5_ref, 0x0501, "GrantAnchor"),
    6: (sa_input.p6_ref, 0x0601, "BondAnchor"),
    7: (sa_input.p7_ref, 0x0701, "YieldAnchor"),
}

for layer, (ref, expected_ext_type, name) in layer_checks.items():
    if ref == ZERO_32:
        continue  # 此层未引用，跳过

    # 查询L2节点存储
    anchor = query_anchor(ref)
    if anchor is None:
        result.add_error(layer, E031, f"{name}不存在")
        continue

    # 类型验证：Anchor的extension_type必须匹配层次
    if anchor.extension_type != expected_ext_type:
        result.add_error(layer, E034, f"类型不匹配：期望{expected_ext_type:#06x}")
        continue

    # 有效性验证（以EEA.TI为时间基准）
    ref_ti = eea.temporal_index
    if not is_valid_at_ti(anchor, ref_ti):
        result.add_error(layer, E032, f"{name}在TI={ref_ti}时已失效")
        continue

    result.add_layer_valid(layer, ref)

# 若verify_depth < 3，只验证必要层
if verify_depth == 1:
    # minimal：不验证SA引用
    result.clear_layer_errors()

# Step 4: 层内约束检查（SHOULD级别）
if sa_input.p3_ref != ZERO_32 and sa_input.p4_ref != ZERO_32:
    scroll = query_anchor(sa_input.p4_ref)
    if scroll and scroll.claim_anchor_ref != sa_input.p3_ref:
        result.add_warning(W010, "P4.ClaimAnchorRef与P3_ref不一致")

if sa_input.p3_ref != ZERO_32 and sa_input.p5_ref != ZERO_32:
    grant = query_anchor(sa_input.p5_ref)
    if grant:
        p3_anchor = query_anchor(sa_input.p3_ref)
        if p3_anchor and grant.grantee_fingerprint != p3_anchor.entity_fingerprint:
            result.add_warning(W010, "P5.GranteeFingerprint与P3.EntityFingerprint不一致")

if sa_input.p3_ref != ZERO_32 and sa_input.p6_ref != ZERO_32:
    bond = query_anchor(sa_input.p6_ref)
    if bond:
        p3_anchor = query_anchor(sa_input.p3_ref)
        if p3_anchor:
            fp = p3_anchor.entity_fingerprint
            if fp not in (bond.subject_a_fingerprint, bond.subject_b_fingerprint):
                result.add_warning(W010, "P3主体不在P6关系的双方中")

# Step 5: event_data_hash验证
if sa_input.event_data_hash != ZERO_32:
    if sa_input.event_data_hash != H(sa_input.raw_event_data):
        result.add_error(0, E033, "event_data_hash不匹配")

result.valid = not result.has_errors()
return result
```

### 5.4 层内约束（SHOULD）

约束一（P3+P4）：
ScrollAnchor.ClaimAnchorRef SHOULD == P3_ref
含义：内容的创建者应与事件主体一致

约束二（P3+P5）：
GrantAnchor.GranteeFingerprint SHOULD == P3_anchor.EntityFingerprint
含义：授权的被授权方应与事件主体一致

约束三（P3+P6）：
P3_anchor.EntityFingerprint SHOULD ∈ {BondAnchor.SubjectAFP, SubjectBFP}
含义：事件主体应是关系的一方

约束四（P7存在时）：
YieldAnchor.BeneficiaryClaimRef SHOULD == P3_ref
含义：收益方应与事件主体一致

以上均为SHOULD（建议）而非MUST（强制）。
违反时返回W010，不拒绝EEA。
合理例外：代理场景·多方事件·委托执行。

## 6. ExtensionHeader 规范

处理规则：

python
def process_extensions(eea_bytes: bytes, offset: int) -> list\[Extension\]:
"""解析EEA末尾的扩展头部序列。"""
extensions = [ ]
while offset < len(eea_bytes):
if offset + 8 > len(eea_bytes):          # ExtHeader=8B
raise ParseError(E_TRUNCATED)

```
    ext_type   = int.from_bytes(eea_bytes[offset:offset+2], 'big')
    version    = eea_bytes[offset+2]
    hdr_flags  = eea_bytes[offset+3]
    critical   = hdr_flags & 0x01            # bit0
    length     = int.from_bytes(eea_bytes[offset+4:offset+6], 'big')

    payload = eea_bytes[offset+8 : offset+8+length]
    if len(payload) != length:
        raise ParseError(E_TRUNCATED)

    if ext_type not in KNOWN_EXTENSION_TYPES:
        if critical:
            raise UnsupportedExtension(ext_type)
        # critical=0：忽略未知扩展，继续处理
    else:
        extensions.append(Extension(ext_type, version, payload))

    offset += 8 + length                     # ExtHeader=8B

return extensions
```

向后兼容规则：

hdr_flags.bit0 = 0（critical未置位）：
不认识此扩展类型的节点可以忽略，继续处理EEA
适用：可选增强功能（如VP·性能优化）

hdr_flags.bit0 = 1 (critical)：
不认识此扩展类型的节点MUST拒绝整个EEA
返回：E_CRITICAL_UNKNOWN（扩展类型不被支持）
适用：协议强制特性（如ClaimAnchor的identity extension）

## 7. L2节点行为规范

### 7.1 EEA签发流程

python
def sign_eea(
event_data_hash:  bytes,       # H(业务数据)，由业务系统提供
semantic_input:   SemanticAnchorInput | None,
extension_payload: bytes | None,
) -> EEA:
"""L2节点签发EEA的完整流程。"""

```
# Step 1: 检查KeyPackage有效性
kp = get_current_key_package()
if not is_valid(kp):
    raise KeyPackageExpired()
node_key_version = get_current_node_key_version(origin_fingerprint)

# Step 2: 分配TI和ST（原子操作，防并发竞争）
with ti_lock:
    ti = allocate_next_ti(kp)         # 在KP的TI段内取下一个值
    st = increment_sequence_token()    # 全局单调递增，持久化存储
    # SequenceToken必须持久化到磁盘，节点重启后从持久化值恢复
    # 防止重启后重复使用相同序号

# Step 3: 获取前序EEA信息
prev = get_last_eea()  # 本节点最新EEA
chain_proof = compute_chain_proof(prev)
degraded_mode = 1 if in_keypackage_grace_window(kp, ti) else 0

# Step 4: 生成Salt并计算AnchorID（不依赖签名）
salt = csprng(16)
anchor_id = H(
    b"Polaris.Anchor.v1"
    + BE64(ti)
    + origin_fingerprint
    + BE64(st)
    + salt
)

# Step 5: 计算DigitalSignature
signing_payload = (
    b"Polaris.Anchor.v1"
    + anchor_id
    + BE64(ti)
    + origin_fingerprint
    + BE64(st)
    + chain_proof
    + BE32(node_key_version)
    + bytes([degraded_mode])
    + bytes(3)  # reserved_future 3B·MUST=0
)
digital_sig = hsm_sign(sk_l2, SM3(signing_payload))  # HSM签名（prehash：传 e = SM3(原文)）

# Step 6: 计算VerificationProof（可选）
vp = compute_verification_proof(prev.anchor_id, prev.vp) if prev else None

# Step 7: 计算SemanticAnchor（可选）
sa = None
if semantic_input:
    sa = compute_semantic_anchor(
        eea_anchor_id   = anchor_id,
        p3_ref          = semantic_input.p3_ref,
        p4_ref          = semantic_input.p4_ref,
        p5_ref          = semantic_input.p5_ref,
        p6_ref          = semantic_input.p6_ref,
        p7_ref          = semantic_input.p7_ref,
        event_data_hash = semantic_input.event_data_hash,
    )

# Step 9: 写入本地存储
eea = EEA(
    anchor_id          = anchor_id,
    temporal_index     = ti,
    origin_fingerprint = origin_fingerprint,
    sequence_token     = st,
    chain_proof        = chain_proof,
    digital_signature  = digital_sig,
    verification_proof = vp,
    semantic_anchor    = sa,
    key_version        = node_key_version,
    degraded_mode      = degraded_mode,
)
store.write(eea)

# Step 10: 更新碰撞检测索引
collision_index.add(ti, st, anchor_id)

return eea
```

### 7.2 碰撞检测

规则： 同一 L2 节点（OriginFP）下，同一 (TI, ST) 二元组只能有一个 EEA。
TI 跨宇宙可重叠（偏序·见 P1 §4），ST 节点终身连续（切 L1 不归零），
两者共同保证 AnchorID 唯一——碰撞键是 (OriginFP, TI, ST)，不是 (OriginFP, TI)。

语义（职责）： 碰撞检测防的是 AnchorID 碰撞（即 ST 被意外复用），不是防 TI 复用。
TI 跨宇宙可重叠（偏序）；同宇宙内同一 TI 也允许多笔（由 ST 区分）——
AnchorID 唯一性由 (TI, OriginFP, ST, Salt) 四元组保证，其中 ST 永不复用是关键。
因此碰撞检测是"安全网"而非业务逻辑：正常不触发（ST 永不复用），
仅在 ST 持久化失败/回退导致 AnchorID 真碰撞时才触发。
碰撞检测不是另立一套“ST 主键”——存储主键、对外引用（FactID）一律是 AnchorID；ST 只是 AnchorID 的组成字段之一。

python
def detect_collision(ti: int, origin_fp: bytes, st: int) -> bool:
"""
碰撞检测：同一OriginFP下，(TI, ST) 是否已被使用。
返回 True 表示碰撞（已存在），False 表示安全。
"""
# 第一层：Bloom Filter（内存，<1μs，误报率0.01%）
if not bloom_filter.possibly_contains(origin_fp + BE64(ti) + BE64(st)):
return False  # 确定不存在，安全

```
# 第二层：精确查询（内存HashSet，<10μs）
return (origin_fp, ti, st) in exact_collision_set
```

def handle_collision(ti: int, origin_fp: bytes, st: int):
"""碰撞处理：(TI, ST) 已被使用，自动切换到下一个 TI。"""
# 记录碰撞日志（审计用）
audit_log.record(COLLISION_DETECTED, origin_fp, ti, st)
# SequenceToken仍然递增
# 返回下一个可用TI
return allocate_next_ti_skip_collision()
Bloom Filter 参数（推荐）：

热窗口大小：最近1小时内的TI数（\~60,000 TPS × 3600s ≈ 2.16亿条）
误报率：0.01%（p=0.0001）
所需内存：约600MB（可接受）
精确HashSet作为第二层确认

### 7.3 Pending 状态管理

python
def create_pending_anchor(
anchor_type:      int,     # 3-7 对应P3-P7
anchor_data:      bytes,   # 序列化的Anchor（含EEA）
missing_fields:   list\[dict\],  # \[{field_name, signer_fingerprint}\]
timeout_ti:       int,     # 超时TI（pending_since + 24h×TI数）
) -> bytes:                    # 返回anchor_id
"""创建Pending状态的Anchor。"""
anchor_id = extract_anchor_id(anchor_data)
pending_store.write(PendingAnchor(
anchor_id      = anchor_id,
anchor_type    = anchor_type,
anchor_data    = anchor_data,
missing_fields = missing_fields,
status         = PENDING,
pending_since  = current_ti(),
pending_timeout = timeout_ti,
))
return anchor_id

def complete_pending_anchor(
anchor_id:         bytes,
field_name:        str,
late_signature:    bytes,  # 64B 补签
signer_claim_ref:  bytes,  # 32B 补签方ClaimAnchor
sign_ti:           int,    # 补签时的TI
) -> bool:
"""
补签：将缺失字段填入Pending Anchor，若完整则激活。

```
late_signature 的签名原文构造规则：
    original_sign_payload = 原始签名原文（与正常签发时的签名原文一致）
    late_sign_payload = original_sign_payload + b"LateSign.v1" + BE64(sign_ti)
    late_signature = Sign(signer_sk, H(late_sign_payload))

验证方应重构此原文并验证签名。
"""
pending = pending_store.get(anchor_id)
if pending is None or pending.status != PENDING:
    return False
if current_ti() > pending.pending_timeout:
    pending.status = EXPIRED
    pending_store.update(pending)
    return False

# 填入缺失字段
pending.fill_field(field_name, late_signature, signer_claim_ref, sign_ti)
pending.remove_missing(field_name)

# 若所有缺失字段已填入，激活Anchor
if not pending.missing_fields:
    activate_anchor(pending)
    pending.status = ACTIVE
    pending_store.update(pending)

return True
```

def purge_expired_pending():
"""定时任务：清除超时的Pending Anchor。"""
expired = pending_store.query_expired(current_ti())
for anchor in expired:
anchor.status = EXPIRED
audit_log.record(PENDING_EXPIRED, anchor.anchor_id)
pending_store.bulk_update(expired)

### 7.4 缓存策略

三层缓存（详见GNOMON-PERF-001 §3.4）：

L1缓存（进程内存，<1ms，约32GB）：
存储：最近1小时的EEA验证结果
Key：AnchorID
Value：{valid, verified_at_ti, layer_results}
TTL：min(ValidUntil - current_ti, 3600s)
失效：收到RevocationRecord立即清除

L2缓存（Redis集群，<5ms，约128GB）：
存储：最近7天的Anchor（EEA·ClaimAnchor）
撤销状态：全量常驻，< 200MB

L3存储（PostgreSQL，<50ms）：
存储：全量历史，按TI分区
7天热分区：NVMe SSD
历史归档：HDD/对象存储

缓存一致性：
RevocationRecord到达 → 立即清除L1·L2缓存
KeyPackage到期 → 不清除缓存（历史EEA仍有效）

## 8. 撤销机制

### 8.1 RevocationRecord

RevocationRecord 是 Gnomon System 的状态变更机制。没有删除，只有撤销标记（Append-only）。

字段                      长度    说明
──────────────────────────────────────────────────────────
revocation_id             32B    H(全部字段)
claim_anchor_id           32B    被撤销的ClaimAnchor（全零=按entity_fp批量）
entity_fingerprint        32B    被撤销主体的EntityFingerprint
attribute_type            2B     0=撤销所有类型
revocation_time           8B     TI，撤销生效时间
revocation_reason         1B     0x01=安全风险 0x02=主动注销
0x03=法律强制 0x04=级联撤销
issuer_fingerprint        32B    发起撤销的机构指纹
revocation_sig            64B    发起机构SM2签名
override_grace            1B     0=遵守宽限期 1=立即生效
regulation_reference      32B    H(法规文件)，强制撤销时必填
──────────────────────────────────────────────────────────
合计：约200B
时序切割语义：

RevocationRecord.revocation_time = T_revoke（TI值）

已发生的事件（EEA.TI ≤ T_revoke）：
验证以EEA.TI为基准：
ClaimAnchor在EEA.TI时有效 → 该事件的主体证明仍然有效
不追溯：撤销不使历史已完成的协作失效

未来的事件（EEA.TI > T_revoke）：
验证时发现ClaimAnchor已撤销 → E032，拒绝

### 8.2 广播与传播

python

# 广播截止时间：30分钟对应的TI数（假设1 TI = 1μs）

# 30 min = 30 × 60 × 1,000,000 μs = 1,800,000,000 TI

BROADCAST_DEADLINE_TI = 1_800_000_000  # 约1.8×10⁹ TI

def broadcast_revocation(rr: RevocationRecord) -> BroadcastResult:
"""
RevocationRecord广播：Push+Pull双模式。
SLA：30分钟内覆盖99%的L2节点。
详见工程挑战规范 §2.3。
"""
result = BroadcastResult()
all_nodes = get_registered_l2_nodes()

```
# Push模式：并行广播至所有已知节点
futures = []
for node in all_nodes:
    future = async_push(node.endpoint, rr)
    futures.append((node, future))

# 等待响应（超时10秒）
for node, future in futures:
    try:
        resp = future.result(timeout=10)
        if resp.accepted:
            result.covered_nodes.add(node.fingerprint)
            if resp.duplicate:
                result.already_known.add(node.fingerprint)
    except TimeoutError:
        result.failed_nodes.add(node.fingerprint)

# 记录广播状态
revocation_store.update_broadcast_status(
    rr.revocation_id,
    coverage_count = len(result.covered_nodes),
    broadcast_deadline = current_ti() + BROADCAST_DEADLINE_TI,
)

# Pull模式补充（不依赖Push成功）
# 其他节点每3分钟主动拉取最新RevocationRecord
# 见 SyncService.PullRevocationsSince

# 检查SLA
coverage_rate = len(result.covered_nodes) / len(all_nodes)
if coverage_rate < 0.99:
    schedule_retry(rr, failed_nodes=result.failed_nodes)

return result
```

def verify_revocation_status(
anchor_id:     bytes,
at_ti:         int,
) -> RevocationStatus:
"""
快速撤销状态查询。
使用revocation_index（内存表），<1ms响应。
"""
# 第一层：Bloom Filter（0.01ms）
if not revocation_bloom.possibly_contains(anchor_id):
return NOT_REVOKED

```
# 第二层：精确查询（内存HashTable，0.1ms）
rr = revocation_index.get(anchor_id)
if rr is None:
    return NOT_REVOKED

# 时序切割：撤销时间 vs 查询时间
if rr.revocation_time <= at_ti:
    return REVOKED_AT_TI(rr.revocation_time)
else:
    return NOT_YET_REVOKED  # 撤销发生在at_ti之后，该时刻仍有效
```

### 8.3 降级 EEA 的处理

python
def handle_degraded_eea(eea: EEA, verifier_policy: VerifierPolicy) -> VerifyResult:
"""处理degraded_mode=1的EEA。"""
if not eea.degraded_mode:
return None  # 正常EEA，不在此处理

```
result = VerifyResult()
result.add_warning(W005, f"EEA产生于降级时段，TI精度可能降低")

# 查询降级记录（DegradedModeRecord）
degraded_record = query_degraded_record(eea.origin_fingerprint, eea.temporal_index)
if degraded_record:
    result.degraded_period = (
        degraded_record.degraded_start_ti,
        degraded_record.degraded_end_ti,
    )
    result.mapping_available = (degraded_record.mapped_at is not None)

# 依据验证方策略决定是否接受
if verifier_policy == STRICT:
    # 司法·金融高安全场景：拒绝降级EEA
    result.valid = False
    result.error = E_DEGRADED_NOT_ACCEPTED
elif verifier_policy == STANDARD:
    # 标准场景：接受但标注
    result.valid = True
else:
    # 宽松场景（如日志记录）：接受
    result.valid = True

return result
```

## 9. 验证规范

### 9.0 EEA的自包含验证边界

本节明确一个EEA在脱离签发节点后，【能独立验证什么】、
【需要补充什么信息才能验证】，以及一个关键区分：流转的是证明，
不是业务内容。这是Gnomon"无需许可验证"特性的精确边界。

#### 9.0.1 自包含的部分（仅凭EEA本身 + L1公钥即可验证）

EEA一旦由L2节点签发，以下验证可【脱离签发节点】独立完成，
验证方只需持有该L2节点的公钥（经L1的KeyPackage/NodeCertificate背书）：

✓ 签名有效性：用L2公钥验证DigitalSignature
✓ AnchorID完整性：重算H(domain_tag∥TI∥OriginFP∥ST∥Salt)并比对
✓ 时序真实性：验证TI落在该L2所承载ChildTHK的TI分配段（ti_range）内
✓ 单点存在性：证明"该事件在该TI由该节点签署且未被篡改"

关键性质：
· 无需回源到签发节点
· 无需全网共识
· 任何持有L1公钥的验证方均可独立验证
这与依赖全局账本的系统（如区块链）有本质区别——
Gnomon的验证依赖密码学链本身，不依赖账本。

#### 9.0.2 需要补充信息的部分

以下验证【无法仅凭单个EEA完成】，验证方需主动获取补充信息：

撤销状态检查：
EEA本身不携带撤销信息。
验证方需查询RevocationRecord（见§8）判断引用的Anchor是否已撤销。
注意：撤销不追溯——以EEA.TI为时序切割基准（见§9.x时序切割）。

ChainProof链式验证：
验证因果链完整性需要前序EEA。
单个EEA只能证明"我引用了某前序的哈希"，
要验证前序真实存在，需获取前序EEA（或使用VP/checkpoint，见§4）。

SemanticAnchor语义验证：
L2节点不存储P3-P7的引用参数（语义隔离）。
验证方需由当事方提供SemanticAnchorInput（7个引用值）才能重建SA并验证。
SA非零但未提供输入参数时，返回E035（见§5.3）。

跨层完整性（full验证）：
需并行查询所有非零Pn_ref对应的上层Anchor（见§9.1 verify_depth=3）。

#### 9.0.3 流转的是证明，不是业务内容

EEA及各层Anchor中【不包含业务原文】，只包含SM3摘要：

ContentHash·AttributeHash·ScopeHash·RelationHash·YieldHash...
全部是哈希承诺，不可逆推原文。

含义：
· EEA可以公开流转、全网验证——因为它不泄露任何业务内容
· 验证方拿到EEA能确认"某事发生过·谁签的·未被篡改·何时"
· 但要知道"具体内容是什么"，必须从当事方获取原文，
自行计算SM3哈希与Anchor中的承诺比对

这正是语义隔离的设计目的：
证明（哈希）可公开流转，隐私内容（原文）留在当事方手里。
L2节点作为"公证处"，只见证摘要，不持有内容。

#### 9.0.4 边界小结

能独立验证（证明类）：签名·AnchorID·时序·单点存在性
需补充信息：撤销状态(RevocationRecord)·链式(前序EEA/VP)·语义(引用参数)
流转对象：证明（哈希承诺），非业务原文
信任根：同一L1公钥即可验证其下所有L2签发的EEA

### 9.1 验证深度

verify_depth = 1（minimal）：
验证：EEA.DigitalSignature + AnchorID
不验证：ChainProof连续性 · SemanticAnchor引用
适用：高频实时场景（每次操作）
延迟：<1ms

verify_depth = 2（standard）：
验证：以上 + ChainProof + VerificationProof（若有）+ P3_ref有效性
适用：日常业务验证
延迟：<10ms（含ClaimAnchor查询）

verify_depth = 3（full）：
验证：以上 + 所有非零Pn_ref + 层内约束检查 + event_data_hash + THK链时间校验
全链时间校验路径：
1. 验证 EEA.DigitalSignature（P2 签名）
2. 验证 KeyPackage 由 L1 正确签名，EEA.TI ∈ \[KP承载子THK的ti_range_start, ti_range_end)
3. 验证 ChildTHK 由 RootTHK 正确签名（含OpCertificate链），KeyPackage.TI段 ⊆ ChildTHK.TI段
4. 验证 RootTHK 的 time_commitment 与物理时间声明一致
5. 若启用 max_issuance_delay：验证 (EEA签发时刻 - ChildTHK签发时刻) ≤ max_issuance_delay
适用：监管审计·司法存证·合规检查
延迟：<100ms（并行查询所有引用层 + THK链）
并行要求：所有Pn_ref查询MUST并行执行，不得串行等待

### 9.2 完整 EEA 验证算法（伪代码）

python
def verify_eea_full(
eea:           EEA,
verify_depth:  int = 3,
at_ti:         int | None = None,  # None=使用eea.temporal_index
sa_input:      SemanticAnchorInput | None = None,  # 必须提供（若SA非零）
) -> VerifyResult:
"""
完整EEA验证算法。
at_ti：验证时刻（用于时序切割），默认为EEA自身的TI。
sa_input：SemanticAnchor输入参数，若eea.semantic_anchor非零则MUST提供。
"""
result = VerifyResult()
check_ti = at_ti if at_ti is not None else eea.temporal_index

```
# ── 基础验证（所有深度均执行）────────────────────────────

# B1: AnchorID完整性
expected_anchor_id = H(
    b"Polaris.Anchor.v1"
    + BE64(eea.temporal_index)
    + eea.origin_fingerprint
    + BE64(eea.sequence_token)
    + eea.salt
)
if eea.anchor_id != expected_anchor_id:
    return VerifyResult(valid=False, error=E001)

# B2: L2节点认证
node_cert = get_node_certificate(eea.origin_fingerprint)
if node_cert is None:
    return VerifyResult(valid=False, error=E002)
if not is_valid_cert(node_cert, check_ti):
    return VerifyResult(valid=False, error=E002)

# B3: KeyPackage版本
if eea.key_version != get_current_key_version(eea.origin_fingerprint):
    # 允许历史版本（时序切割），只验证密钥当时有效
    if not was_valid_key_version(eea.key_version, eea.temporal_index):
        return VerifyResult(valid=False, error=E003)

# B4: DigitalSignature
pk_l2 = node_cert.public_key
signing_payload = (
    b"Polaris.Anchor.v1"
    + eea.anchor_id
    + BE64(eea.temporal_index)
    + eea.origin_fingerprint
    + BE64(eea.sequence_token)
    + eea.chain_proof
    + BE32(eea.key_version)
    + bytes([eea.degraded_mode])
    + bytes(3)  # reserved_future 3B·MUST=0
)
if not Verify(pk_l2, SM3(signing_payload), eea.digital_signature):
    return VerifyResult(valid=False, error=E004)

# B5: TI在ChildTHK分配段内
child_thk = get_child_thk_from_keypackage(kp)
if child_thk and not (child_thk.ti_range_start <= eea.temporal_index < child_thk.ti_range_end):
    result.add_warning(W007, "TI超出ChildTHK分配段（ti_range）")

# B6: 降级模式检查
if eea.degraded_mode:
    degraded_result = handle_degraded_eea(eea, verifier_policy)
    result.merge(degraded_result)
    if not degraded_result.valid:
        return result

if verify_depth < 2:
    result.valid = True
    return result

# ── Standard验证（depth >= 2）────────────────────────────

# S1: ChainProof验证
prev_eea = get_prev_eea(eea.origin_fingerprint, eea.sequence_token - 1)
if prev_eea is None:
    expected_cp = H(bytes(104))  # 根EEA
else:
    expected_cp = H(
        prev_eea.anchor_id
        + BE64(prev_eea.temporal_index)
        + prev_eea.digital_signature
    )
if eea.chain_proof != expected_cp:
    return VerifyResult(valid=False, error=E005)

# S2: SequenceToken单调性
if prev_eea and eea.sequence_token <= prev_eea.sequence_token:
    return VerifyResult(valid=False, error=E006)

# S3: VerificationProof（若有）
if eea.verification_proof and prev_eea and prev_eea.verification_proof:
    expected_vp = H(prev_eea.anchor_id + prev_eea.verification_proof)
    if eea.verification_proof != expected_vp:
        result.add_warning(W008, "VerificationProof与前序不一致")

if verify_depth < 3:
    result.valid = True
    return result

# ── Full验证（depth == 3）─────────────────────────────────

# F1: SemanticAnchor验证（若有）
if eea.semantic_anchor and eea.semantic_anchor != ZERO_32:
    if sa_input is None:
        return VerifyResult(valid=False, error=E035, 
            msg="SemanticAnchor非零但未提供输入参数")
    sa_result = verify_semantic_anchor(eea, sa_input, verify_depth=3)
    result.merge(sa_result)
```

（V4.1 Cluster nonce 修订声明·已在 §变更摘要 中保留·此处不再重复）

```
# F2: THK链时间校验（新增于V3.8）
# 验证信任链：RootTHK → ChildTHK → KeyPackage → EEA
thk_result = verify_thk_chain(
    eea             = eea,
    depth           = verify_depth,
    at_ti           = check_ti,
    current_wallclock = get_current_wallclock(),  # 当前物理时间（纳秒）
)
result.merge(thk_result)

# verify_thk_chain 内部逻辑（伪代码）：
#   def verify_thk_chain(eea, depth, at_ti, wallclock):
#       # 1. 解析信任链
#       kp = get_key_package(eea.origin_fingerprint, eea.key_version)
#       if kp is None: return (False, "KeyPackage不存在")
#       child_thk = get_child_thk_by_commitment(kp.child_thk_commitment)
#       if child_thk is None: return (False, "ChildTHK不存在")
#       root_thk = get_root_thk_by_commitment(child_thk.parent_root_thk_id)
#       if root_thk is None: return (False, "RootTHK不存在")
#
#       # 2. 验证 RootTHK 签名（L1根密钥）
#       if not verify_root_thk(root_thk): return (False, "RootTHK签名无效")
#
#       # 3. 验证 RootTHK 链完整性
#       prev_root = get_prev_root_thk(root_thk)
#       if prev_root and root_thk.prev_root_commitment != prev_root.time_commitment:
#           return (False, "RootTHK链断裂")
#
#       # 4. 验证 ChildTHK（OpCertificate链：根密钥→OpCert→操作密钥→ChildTHK）
#       op_cert = get_op_certificate(child_thk)
#       if not op_cert or not verify_op_cert(op_cert):
#           return (False, "OpCertificate无效")
#       if not verify_child_thk(child_thk, op_cert.op_pubkey):
#           return (False, "ChildTHK签名无效")
#
#       # 5. 验证 ChildTHK.TI段 ⊆ RootTHK.TI段
#       if not (root_thk.ti_range_start <= child_thk.ti_range_start and
#               child_thk.ti_range_end <= root_thk.ti_range_end):
#           return (False, "ChildTHK TI段超出RootTHK范围")
#
#       # 6. 验证 KeyPackage ↔ ChildTHK 绑定
#       if kp.child_thk_commitment != child_thk.child_commitment:
#           return (False, "KeyPackage与ChildTHK绑定不匹配")
#
#       # 7. 验证 EEA.TI ∈ ChildTHK.TI段
#       if not (child_thk.ti_range_start <= eea.temporal_index < child_thk.ti_range_end):
#           return (False, "EEA.TI不在ChildTHK TI段内")
#
#       # 8. 时效检查（若启用 max_issuance_delay）
#       if child_thk.max_issuance_delay > 0:
#           delta_seconds = (wallclock - child_thk.t_utc) / 1_000_000_000  # 纳秒→秒
#           if delta_seconds > child_thk.max_issuance_delay:
#               return (False, f"TI超过使用时效: {delta_seconds}s > {child_thk.max_issuance_delay}s")
#
#       return (True, "THK链验证通过")

result.valid = not result.has_critical_errors()
return result
```

### 9.3 SemanticAnchor完整验证算法（伪代码）

见 §5.3。

## 10. 协议消息（Protobuf）

protobuf
// gnomon/v1/polaris.proto
syntax = "proto3";
package gnomon.v1;

// ── 核心数据结构 ──────────────────────────────────────────
message EEA {
uint32 version             = 1;
bytes  anchor_id           = 2;   // 32B
uint64 temporal_index      = 3;
bytes  origin_fingerprint  = 4;   // 32B
uint64 sequence_token      = 5;
bytes  chain_proof         = 6;   // 32B
bytes  digital_signature   = 7;   // 64B
bytes  salt                = 13;  // 16B CSPRNG，参与 AnchorID 计算，MUST 随 EEA 持久化
bytes  verification_proof  = 8;   // 32B，可选
bytes  semantic_anchor     = 9;   // 32B，可选，全零=匿名
repeated EEAExtension extensions = 10;
uint32 key_version         = 11;
bool   degraded_mode       = 12;
}

message EEAExtension {
uint32 extension_type = 1;
uint32 version        = 2;
uint32 hdr_flags      = 3;   // uint8位图 proto3用uint32承载 bit0=critical
bytes  payload        = 4;
}

message SemanticAnchorInput {
uint32 version          = 1;  // SA计算版本，当前=1
bytes  eea_anchor_id    = 2;  // 32B MUST
bytes  p3_ref           = 3;  // 32B ClaimAnchorID，全零=无
bytes  p4_ref           = 4;  // 32B ScrollAnchorID，全零=无
bytes  p5_ref           = 5;  // 32B GrantAnchorID，全零=无
bytes  p6_ref           = 6;  // 32B BondAnchorID，全零=无
bytes  p7_ref           = 7;  // 32B YieldAnchorID，全零=无
bytes  event_data_hash  = 8;  // 32B H(业务数据)
bytes  raw_event_data   = 9;  // 可选，用于event_data_hash验证
}

// ── 天璇服务 ──────────────────────────────────────────────
service PolarisService {
// 提交EEA（业务系统→L2节点）
rpc SubmitEEA(SubmitEEARequest) returns (SubmitEEAResponse);

// 批量提交（双向流）
rpc SubmitEEABatch(stream SubmitEEARequest) returns (stream SubmitEEAResponse);

// 查询单个EEA
rpc GetEEA(GetEEARequest) returns (GetEEAResponse);

// 按TI范围查询（流式返回）
rpc QueryEEAByRange(QueryEEARequest) returns (stream EEA);

// 验证EEA（含深度控制）
rpc VerifyEEA(VerifyEEARequest) returns (VerifyEEAResponse);

// 验证因果关系（O(1) VP路径）
rpc VerifyCausality(VerifyCausalityRequest) returns (VerifyCausalityResponse);

// 订阅EEA实时流（监管节点·审计节点）
rpc SubscribeEEAStream(EEAStreamRequest) returns (stream EEA);

// 补签Pending Anchor
rpc CompletePendingAnchor(CompletePendingRequest) returns (GnomonResponse);
}

message SubmitEEARequest {
uint32              version        = 1;
EEA                 eea            = 2;
SemanticAnchorInput semantic_input = 3;  // 可选，用于SA验证
}

message SubmitEEAResponse {
GnomonResponse response      = 1;
bytes          anchor_id     = 2;   // 32B 确认写入
uint64         stored_at_ti  = 3;
}

message VerifyEEARequest {
uint32              version        = 1;
bytes               anchor_id      = 2;   // 32B
uint32              verify_depth   = 3;   // 1=minimal 2=standard 3=full
SemanticAnchorInput semantic_input = 4;   // 可选（若SA非零则必须）
uint64              at_ti          = 5;   // 验证时刻，0=使用EEA自身TI
}

message VerifyEEAResponse {
GnomonResponse       response       = 1;
bool                 valid          = 2;
uint32               verify_depth   = 3;
repeated LayerResult layer_results  = 4;
repeated uint32      warnings       = 5;
bool                 degraded_mode  = 6;
}

message LayerResult {
uint32 layer      = 1;  // 2=P2 3=P3 4=P4 5=P5 6=P6 7=P7
bool   valid      = 2;
uint32 error_code = 3;
bytes  anchor_id  = 4;  // 32B
}

message VerifyCausalityRequest {
uint32         version                    = 1;
bytes          earlier_anchor_id          = 2;  // 32B 声称在前的EEA
bytes          later_anchor_id            = 3;  // 32B 声称在后的EEA
repeated bytes intermediate_anchor_ids   = 4;  // 中间节点AnchorID（可稀疏）
repeated bytes checkpoint_vps            = 5;  // 对应checkpoint的VP（可选）
}

message VerifyCausalityResponse {
GnomonResponse response  = 1;
bool           causally_before = 2;  // earlier确实在later之前
string         method    = 3;  // "VP"=O(1) "ChainProof"=O(n)
}

message EEAStreamRequest {
uint32 version           = 1;
bytes  subscriber_fp     = 2;  // 32B 订阅方指纹
bytes  subscriber_cert   = 3;  // 64B 授权证书签名
uint64 from_ti           = 4;  // 从此TI开始推送
uint32 extension_type    = 5;  // 0=所有，>0=过滤特定子根协议
}

message CompletePendingRequest {
uint32 version            = 1;
bytes  anchor_id          = 2;  // 32B Pending Anchor
string missing_field_name = 3;
bytes  late_signature     = 4;  // 64B
bytes  signer_claim_ref   = 5;  // 32B 补签方ClaimAnchor
uint64 sign_ti            = 6;
}

## 11. 安全考量

### 11.1 ChainProof 安全边界

ChainProof 防护的攻击：
✅ 历史插入：在位置k插入 → 后续ChainProof全部失效
✅ 历史删除：删除位置k → 位置k+1的ChainProof失效
✅ 历史替换：修改任意字段 → AnchorID变化 → 后续ChainProof失效

ChainProof 不防护的场景：
✗ L2节点截断链尾（只保留前N个EEA）
→ 缓解：监管节点实时订阅独立备份
✗ 全新伪造链（从创世开始重建）
→ 缓解：NodeCertificate的valid_from限制签名时间
时序切割：历史公钥对应历史签名

### 11.2 SemanticAnchor 安全性

已防御（V1.0）：
✅ 跨EEA移植（T10）：AnchorID嵌入224B输入
✅ 降层攻击（T11）：extension_type类型检查
✅ 时间回溯（T12）：以EEA.TI为验证时间基准

需注意：
SA是SM3哈希，L2节点不验证SA的引用有效性
（L2节点不知道P3_ref等参数）
SA语义验证由验证方负责（持有SemanticAnchorInput参数）
验证方MUST从业务系统或可信源获取SA输入参数。

### 11.3 语义隔离

L2节点存储内容：
AnchorID（32B）
TemporalIndex（8B）
OriginFingerprint（32B）
SequenceToken（8B）
ChainProof（32B）
DigitalSignature（64B）
SemanticAnchor（32B，若有）

L2节点不存储：
业务数据原文（event_data_hash只存哈希）
SemanticAnchorInput参数（P3_ref等由业务系统持有）
任何可还原业务语义的内容

保证：即使L2节点完全被攻击者控制，
攻击者也无法从L2节点存储中获知任何业务内容。

## 12. 测试向量

### 12.1 EEA 基础字段测试向量

python

# 所有输入使用固定值，实现方MUST产生相同输出

import hashlib

def sm3(data: bytes) -> bytes:
# 生产环境必须使用国密SM3，此处使用SHA3-256仅用于演示
return hashlib.sha3_256(data).digest()

# 固定输入

TI              = 1000000001
ORIGIN_FP       = bytes.fromhex("ab" \* 32)   # SM3(L2公钥)，固定测试值
ST              = 1
PREV_ANCHOR_ID  = bytes.fromhex("00" \* 32)   # 根EEA，前序全零
PREV_TI         = 0
PREV_SIG        = bytes.fromhex("00" \* 64)
KEY_VERSION     = 1
DEGRADED_MODE   = 0
SALT            = bytes.fromhex("cd" \* 16)

# Step 1: ChainProof

chain_proof = sm3(PREV_ANCHOR_ID + PREV_TI.to_bytes(8,'big') + PREV_SIG)
print(f"ChainProof: {chain_proof.hex()}")

# 期望值：sha3_256(0×104) 的实际输出

# Step 2: AnchorID（不依赖签名）

anchor_id = sm3(
b"Polaris.Anchor.v1"
+ TI.to_bytes(8,'big')
+ ORIGIN_FP
+ ST.to_bytes(8,'big')
+ SALT
)

# Step 3: signing_payload（137B）

signing_payload = (
b"Polaris.Anchor.v1"         # 17B
+ anchor_id                  # 32B
+ TI.to_bytes(8,'big')       # 8B
+ ORIGIN_FP                  # 32B
+ ST.to_bytes(8,'big')       # 8B
+ chain_proof                # 32B
+ KEY_VERSION.to_bytes(4,'big')   # 4B
+ bytes(\[DEGRADED_MODE\])     # 1B
+ bytes(3)                   # reserved_future 3B·MUST=0
)
raw_len = 17+32+8+32+8+32+4+1+3
assert raw_len == 137, f"签名原文长度错误：{raw_len}"
print(f"signing_payload_hash: {signing_payload.hex()}")

# Step 4: DigitalSignature

# digital_sig = SM2_Sign(sk_l2, SM3(signing_payload))  # prehash：传 e = SM3(原文)

### 12.2 SemanticAnchor 测试向量

python

# P3+P4+P5 组合测试向量

ANCHOR_ID    = bytes.fromhex("11" \* 32)  # EEA.AnchorID
P3_REF       = bytes.fromhex("22" \* 32)  # ClaimAnchor.AnchorID
P4_REF       = bytes.fromhex("33" \* 32)  # ScrollAnchor.AnchorID
P5_REF       = bytes.fromhex("44" \* 32)  # GrantAnchor.AnchorID
ZERO_32      = bytes(32)
EVENT_HASH   = sm3(b"test_contract_canonical_bytes")

sa_input_224 = (
ANCHOR_ID   # 32B，EEA绑定
+ P3_REF    # 32B
+ P4_REF    # 32B
+ P5_REF    # 32B
+ ZERO_32   # 32B，P6不引用
+ ZERO_32   # 32B，P7不引用
+ EVENT_HASH # 32B
)
assert len(sa_input_224) == 224

sa = sm3(sa_input_224)
print(f"SemanticAnchor \[P3+P4+P5\]: {sa.hex()}")

# 全零（匿名事件）

sa_anon = bytes(32)
print(f"SemanticAnchor \[匿名\]: {sa_anon.hex()}")

### 12.3 ChainProof 连续性测试向量

python

# 3个EEA的链式验证

EEA_0_anchor_id = bytes.fromhex("aa" \* 32)
EEA_0_ti        = 1000000001
EEA_0_sig       = bytes.fromhex("bb" \* 64)

# EEA_1 的ChainProof

cp_1 = sm3(EEA_0_anchor_id + EEA_0_ti.to_bytes(8,'big') + EEA_0_sig)
EEA_1_anchor_id = bytes.fromhex("cc" \* 32)
EEA_1_ti        = 1000000002
EEA_1_sig       = bytes.fromhex("dd" \* 64)

# EEA_2 的ChainProof

cp_2 = sm3(EEA_1_anchor_id + EEA_1_ti.to_bytes(8,'big') + EEA_1_sig)

print(f"EEA_1 ChainProof: {cp_1.hex()}")
print(f"EEA_2 ChainProof: {cp_2.hex()}")

## 13. 错误码与警告码

P2天璇协议错误码：

E001  ANCHOR_ID_MISMATCH         AnchorID计算不匹配（字段被篡改）
E002  NODE_CERT_INVALID          L2节点证书无效或已撤销
E003  KEY_VERSION_INVALID        key_version与历史记录不符
E004  DIGITAL_SIG_INVALID        DigitalSignature验证失败
E005  CHAIN_PROOF_BROKEN         ChainProof链不连续（插入/删除/替换）
E006  SEQUENCE_TOKEN_INVALID     SequenceToken非单调递增
E007  VP_MISMATCH                VerificationProof不一致
E008  TI_OUT_OF_RANGE            TI超出ChildTHK的TI分配段（ti_range_start\~ti_range_end）
E009  TI_NOT_MONOTONIC           TI非单调递增（同一宇宙内·跨宇宙切换后允许回退）

SA相关错误码：
E030  SA_MISMATCH                SemanticAnchor重建值不匹配
E031  SA_REF_NOT_FOUND           引用的Anchor不存在
E032  SA_REF_EXPIRED             引用的Anchor在事件发生时已失效
E033  SA_EVENT_HASH_MISMATCH     event_data_hash与业务数据不符
E034  SA_ANCHOR_TYPE_WRONG       Pn_ref的extension_type与层次不符
E035  SA_INPUT_MISSING           SemanticAnchor非零但未提供输入参数

警告码：
W005  DEGRADED_EEA               EEA产生于降级时段，TI精度可能降低
W007  TI_OUT_OF_KEYPKG_RANGE     TI超出ChildTHK分配段（V4.0：TI核实基于ChildTHK.ti_range而非KeyPackage）
W008  VP_INCONSISTENT            VP与前序节点不连续（跨节点链可忽略）
W010  SA_SHOULD_CONSTRAINT       SemanticAnchor层内SHOULD约束未满足
W011  YIELD_DISPUTED             被引用的YieldAnchor存在争议记录
W012  ZKP_DEGRADED               ZKP不被支持，降级为commitment验证
W013  PENDING_REF                SemanticAnchor引用了Pending状态的Anchor
W014  REVOCATION_BROADCAST_DELAY 撤销广播超时（>30分钟未完成）

（V4.1 Cluster nonce 修订声明·已在 §变更摘要 中保留·此处不再重复）

## 14. 版本历史

版本	日期	说明

V4.2	2026-08-02	协议补全：VP_0 + ChainProof_root 固定为协议常量（不可协商 hex 值）。Merkle 收敛规则跨引用 SEC-003 §5。V4.1 Cluster nonce 保留。
V3.8	2026-06-18	P1-2改进：verify_depth=full(3)增加THK链全链时间校验（5步验证路径：EEA签名→KeyPackage→ChildTHK→RootTHK→max_issuance_delay时效检查）；§9.2验证算法增加F2:THK链时间校验伪代码；§9.1 full描述更新。
V1.2.3	2026-06-13	修正§3.2 verify_chain伪代码AnchorID重建公式对齐§2.1.1权威(含domain_tag/Salt,不含ChainProof/签名)。协议定义§2.1一直正确,仅伪代码错。来源:审核D06。
V1.2.2	2026-06-06	新增§9.0 EEA的自包含验证边界（自包含验证项·需补充信息项·证明非内容流转原则）。源自工程验证讨论。
V1.2.1	2026-06-06	新增§3.4跨L2节点的时序与因果（TI段分配保证唯一性·无因果并发事件偏序·跨节点ChainProof引用·同一L1域内无需L2互认）。源自工程验证中的实现者反馈。
V1.2	2026-06-04	修正AnchorID与DigitalSignature循环依赖：EventAnchor核心扩展为192B并新增Salt(16B)，AnchorID改为H(domain_tag∥TI∥OriginFingerprint∥SequenceToken∥Salt)；含VerificationProof的EEA为224B；同步更新字段顺序、测试向量和上层Anchor尺寸。
V1.1	2026-06-03	澄清字段计算顺序中的签名循环；补充O(1)因果验证的checkpoint机制；明确SequenceToken持久化要求；补充Late Signature具体格式（b"LateSign.v1"）；定义BROADCAST_DEADLINE_TI具体值并引用工程挑战；说明SA验证需要外部输入参数（新增E035）；其他小优化
V1.0	2026-06	正式版·设计冻结。完整定义：旧版EEA结构·ChainProof·VerificationProof·SemanticAnchor·ExtensionHeader·L2节点签发流程·碰撞检测·Pending状态·撤销机制·验证算法伪代码·Protobuf消息·测试向量·错误码。

---

## 发布复核事项（非规范性）

V4.4 源规范仍有一项发布前互操作澄清事项：

规范称 `ExtensionHeader.version` 位于 EEA 绝对字节偏移 194，同时又规定 ExtensionHeader 位于可选 32 字节 VP 之后。无 VP 时该头部从核心结构后的偏移 192 开始，版本字节位于 194；含 VP 时头部从偏移 224 开始，版本字节位于 226。需确认偏移是绝对偏移还是相对于可选字段尾部，并明确解析器如何在固定偏移规则下定位该头部。

---

*RFC-P2-001 — 日冕系统（天璇）协议 v4.4 · GnomonSystem 协议基线 v4.4 · 中文 · 2026-10-21*
