# XSec API 设计

## 定位

XSec 是跨平台的数据加密库。它负责生成和管理数据加密密钥（DEK），使用一种或多种认证方式保护 DEK，并为调用方提供稳定的加密与解密接口。

XSec 不负责保存业务密文。调用方可以将 `encrypt` 返回的密文写入本地文件、数据库或服务器。`XSecStorage` 只保存 XSec 自身的持久化状态，例如被包装的 DEK、密码派生参数、保护器信息和格式版本。

## 设计约束

- 对外只提供一个有状态主体 `XSec<S>`，不引入 `Vault`、`LockedVault` 或 `UnlockedVault`。
- 一个 `XSecStorage` 实例只对应一个 XSec 密钥库。
- XSec 的持久化状态序列化为单个 blob，并通过一次原子写入完成更新。
- 所有公开核心类型使用 `XSec` 前缀，避免导入业务项目后产生名称冲突。
- 存储、系统认证和远程 KMS 等 I/O 操作使用异步接口。
- 异步 API 直接绑定 Tokio，必须在 Tokio runtime 中调用。
- AES-GCM 等纯计算操作使用同步接口。
- Argon2id 计算保持同步实现；异步流程通过 `tokio::task::spawn_blocking` 将其调度到阻塞线程。
- DEK、派生密钥和解密结果必须使用 `SecretBox` 或 `Zeroizing` 管理。
- 安全默认值不可由调用方绕过。底层 nonce 接口不属于公开 API。

## 安全边界

XSec 提供以下安全保证：

- 业务明文使用随机 DEK 和 AEAD 算法加密。
- 密文头部和用户 AAD 参与完整性认证。
- DEK 以 wrapped key 形式持久化，只有解锁后才以明文形式进入内存。
- metadata 或业务密文被修改时，解析、解锁或解密必须失败。
- 锁定、销毁和 `Drop` 时清理 XSec 持有的敏感内存。

XSec 基于以下信任前提：

- 操作系统、进程地址空间、随机数源和当前运行的 XSec 代码可信。
- 调用方提供的第三方 `XSecProtector` 可以接触明文 DEK，属于受信任代码。
- 同一个持久化对象由单个写入方管理。第一版不处理多端同步和并发写入冲突。

XSec 不提供以下保证：

- 不保证 Storage 的可用性，攻击者仍可删除或破坏 metadata 和业务密文。
- 不防止攻击者用旧的合法 metadata 替换当前版本。防回滚需要可信版本计数器或服务端协议。
- 密码保护器的抗破解能力受密码强度和 Argon2id 参数限制。获得 metadata 的攻击者可以离线猜测密码。
- `destroy` 只请求 Storage 删除当前 metadata，不保证磁盘、备份、快照或远端副本已被物理擦除。
- XSec 只清理自己持有的敏感内存，不负责清理调用方创建的明文副本。
- 无法防御已控制当前进程、能够读取解锁后内存或替换程序代码的攻击者。

## 公开类型

crate 根导出以下类型：

```rust
pub use error::{XSecError, XSecResult};
pub use protector::XSecProtector;
#[cfg(feature = "password-protector")]
pub use protector::XSecPasswordProtector;
pub use storage::XSecStorage;
pub use xsec::XSec;
```

内置 Storage 和系统保护器通过对应 feature 导出：

```rust
#[cfg(feature = "file-storage")]
pub use storage::XSecFileStorage;

#[cfg(feature = "system-protector")]
pub use protector::XSecSystemProtector;
```

`XSecSystemProtector` 的公开 API、identity、payload 和平台分发规则见
[`SYSTEM_PROTECTOR.md`](SYSTEM_PROTECTOR.md)。

## XSec

`XSec<S>` 是唯一的状态主体。storage、metadata 和 DEK 由一个状态枚举持有，不另外保存彼此独立的 `Option` 字段。

```rust
pub struct XSec<S> {
    state: XSecState<S>,
}

enum XSecState<S> {
    Empty,
    Uninitialized { storage: S },
    Locked { storage: S, metadata: Metadata },
    Unlocked {
        storage: S,
        metadata: Metadata,
        key: SecretBox<[u8; 32]>,
    },
    Destroyed { storage: S },
}
```

| 状态            | Storage | Metadata | DEK |
| --------------- | ------: | -------: | --: |
| `Empty`         |      否 |       否 |  否 |
| `Uninitialized` |      是 |       否 |  否 |
| `Locked`        |      是 |       是 |  否 |
| `Unlocked`      |      是 |       是 |  是 |
| `Destroyed`     |      是 |       否 |  否 |

状态枚举必须排除 `Locked` 但没有 metadata、`Unlocked` 但没有 DEK、`Destroyed` 仍持有 metadata 等非法组合。

### 构造、加载和创建

```rust
impl<S: XSecStorage> XSec<S> {
    pub fn new() -> Self;

    pub async fn load(&mut self, storage: S) -> XSecResult<()>;

    pub async fn create<P: XSecProtector>(
        &mut self,
        protector: &P,
    ) -> XSecResult<()>;
}
```

`new` 不执行 I/O，返回 `Empty` 状态。

`load` 只允许在 `Empty` 状态调用，并取得 storage 的所有权。storage 中没有 metadata 时进入 `Uninitialized { storage }`；存在合法 metadata 时严格解析并进入 `Locked { storage, metadata }`。非 `Empty` 状态调用返回 `XSecError::AlreadyLoaded`。加载或解析失败时实例保持 `Empty`，传入的 storage 被释放，重试时调用方需要重新构造 storage。

`create` 只允许在 `Uninitialized` 状态调用，并执行以下操作：

- 生成随机 DEK。
- 使用 protector 包装 DEK。
- 生成包含第一个 protector 的完整 metadata blob。
- 通过状态中的 storage 原子保存 metadata。
- 保存成功后进入 `Unlocked { storage, metadata, key }`。

随机数生成、protector 包装、metadata 编码和 storage 保存必须先在局部变量上全部完成。只有所有操作成功后才能一次性替换状态；任一步骤失败时实例保持 `Uninitialized`。

`Empty` 状态调用 `create` 返回 `XSecError::StorageNotLoaded`；已初始化状态调用返回 `XSecError::AlreadyExists`。第一版仍要求调用方遵守单写者约束；若 Storage 支持 create-if-absent，`create` 应使用该原子语义。

典型入口流程：

```rust
let mut xsec = XSec::new();
xsec.load(storage).await?;

if xsec.is_initialized() {
    xsec.unlock(&protector).await?;
} else {
    xsec.create(&protector).await?;
}
```

### 状态查询、锁定和解锁

```rust
impl<S: XSecStorage> XSec<S> {
    pub fn is_loaded(&self) -> bool;
    pub fn is_initialized(&self) -> bool;
    pub fn is_locked(&self) -> bool;
    pub fn is_destroyed(&self) -> bool;

    pub async fn unlock<P: XSecProtector>(
        &mut self,
        protector: &P,
    ) -> XSecResult<()>;

    pub fn lock(&mut self) -> XSecResult<()>;
}
```

`is_loaded` 在 `Empty` 时返回 `false`，其余状态返回 `true`。`is_initialized` 只在 `Locked` 和 `Unlocked` 时返回 `true`。`is_locked` 在除 `Unlocked` 外的所有状态返回 `true`。

`unlock` 只允许在 `Locked` 状态调用。它根据 `protector.kind()` 查找保护器记录，恢复 DEK，验证原始 metadata MAC，并在全部成功后进入 `Unlocked { storage, metadata, key }`。未初始化返回 `XSecError::NotInitialized`，认证失败返回 `XSecError::AuthenticationFailed`，已解锁时重复调用返回 `XSecError::AlreadyUnlocked`。

`lock` 将 `Unlocked { storage, metadata, key }` 转换为 `Locked { storage, metadata }` 并清除 DEK。`Uninitialized`、`Locked` 和 `Destroyed` 状态调用时幂等成功；`Empty` 状态返回 `XSecError::StorageNotLoaded`。

### 加密和解密

```rust
impl<S: XSecStorage> XSec<S> {
    pub fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> XSecResult<Vec<u8>>;

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
    ) -> XSecResult<Zeroizing<Vec<u8>>>;

    pub fn encrypt_with_aad(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> XSecResult<Vec<u8>>;

    pub fn decrypt_with_aad(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> XSecResult<Zeroizing<Vec<u8>>>;
}
```

`encrypt` 和 `decrypt` 使用空的用户 AAD。`encrypt_with_aad` 和 `decrypt_with_aad` 将密文绑定到调用方提供的业务上下文。

AAD 会参与完整性认证，但不会被加密。适合放入 AAD 的内容包括租户 ID、用户 ID、记录 ID 和字段名。密码、token 或无法稳定重建的数据不得放入 AAD。

只有 `Unlocked` 状态能够加解密。`Empty` 返回 `XSecError::StorageNotLoaded`，`Uninitialized` 返回 `XSecError::NotInitialized`，`Locked` 返回 `XSecError::Locked`，`Destroyed` 返回 `XSecError::Destroyed`。

XSec 每次加密都生成新的随机 nonce。`encrypt_with_nonce` 和 `decrypt_with_nonce` 仅供 crate 内部使用。

### 管理密钥保护器

```rust
impl<S: XSecStorage> XSec<S> {
    pub fn key_protector_kinds(
        &self,
    ) -> impl Iterator<Item = &str>;

    pub async fn add_key_protector<P: XSecProtector>(
        &mut self,
        protector: &P,
    ) -> XSecResult<()>;

    pub async fn remove_key_protector(
        &mut self,
        kind: &str,
    ) -> XSecResult<()>;

    pub async fn replace_key_protector<P: XSecProtector>(
        &mut self,
        kind: &str,
        protector: &P,
    ) -> XSecResult<()>;
}
```

保护器管理只允许在 `Unlocked` 状态执行。`add_key_protector` 不负责首次初始化，也不生成 DEK；第一个 protector 必须由 `create` 写入。

每种 `kind` 最多保存一个保护器。`key_protector_kinds` 返回当前 metadata 中的保护器类型，调用方可以据此选择密码、生物识别或 KMS 解锁流程。XSec 解锁前无法验证整份 metadata 的真实性，因此该列表在成功解锁前只能作为界面提示，不能作为安全决策依据。

`add_key_protector` 使用新的保护方式包装当前 DEK。相同 `kind` 已存在时返回 `XSecError::ProtectorAlreadyExists`。`remove_key_protector` 按 `kind` 删除保护器，但必须保证至少保留一种可用的解锁方式。`replace_key_protector` 使用新的保护器重新包装同一个 DEK，可用于修改密码或迁移认证方式；新保护器的 `kind` 已被其他记录占用时，返回 `XSecError::ProtectorAlreadyExists`。

保护器变更必须先在临时 metadata 上完成。只有 storage 保存成功后，XSec 才替换内存中的 metadata；保存失败时当前实例保持原有 metadata，不自动重试。

保护器变更不会重新加密业务数据。

### 销毁和取回 Storage

```rust
impl<S: XSecStorage> XSec<S> {
    pub async fn destroy(&mut self) -> XSecResult<()>;

    pub fn into_storage(self) -> Option<S>;
}
```

`destroy` 删除 storage 中的完整 metadata，并清除内存中的 DEK。删除失败时保留当前状态，允许调用方重试；成功后进入 `Destroyed { storage }`。重复调用直接成功，`Empty` 状态调用返回 `XSecError::StorageNotLoaded`。

`into_storage` 消费 `XSec`。`Empty` 返回 `None`，其余状态返回 `Some(storage)`。

## XSecStorage

`XSecStorage` 负责读写一个完整、不可解释的 XSec metadata blob。Storage 不解析 blob，不接触明文 DEK，也不保存业务密文。

```rust
pub trait XSecStorage: Send + Sync {
    fn load(
        &self,
    ) -> impl Future<
        Output = XSecResult<Option<Vec<u8>>>,
    > + Send + '_;

    fn save<'a>(
        &'a self,
        data: &'a [u8],
    ) -> impl Future<
        Output = XSecResult<()>,
    > + Send + 'a;

    fn delete(
        &self,
    ) -> impl Future<
        Output = XSecResult<()>,
    > + Send + '_;
}
```

### load

`load` 读取当前完整 blob：

- 从未创建过 XSec 数据时返回 `Ok(None)`。
- 数据存在时返回完整 blob。
- 网络、权限或设备错误返回 `XSecError::Storage`。
- Storage 不负责判断 blob 是否损坏。

### save

`save` 原子替换完整 blob：

- 每次接收完整 blob，不提供追加或局部更新。
- 成功返回时，新 blob 必须完整可读。
- 写入失败时，旧 blob 必须保持完整，不得留下部分更新状态。

文件系统实现应使用同目录临时文件、文件同步、原子 rename 和父目录同步。HTTP 实现应由服务端在单次请求中替换完整 blob。数据库实现应在单个事务中更新完整 blob。

### delete

`delete` 删除完整 blob。目标不存在时也返回成功，保证重试安全。

第一版不处理多个客户端同时写入同一个持久化对象。调用方或服务端必须保证单写者语义。

## XSecProtector

`XSecProtector` 负责包装和解包 DEK。它不负责保存 metadata，也不参与业务数据加密。XSec 只保存保护器的 `kind` 和不透明 payload。

```rust
pub trait XSecProtector: Send + Sync {
    fn kind(&self) -> &'static str;

    fn wrap_key<'a>(
        &'a self,
        key: &'a SecretBox<[u8; 32]>,
    ) -> impl Future<
        Output = XSecResult<Vec<u8>>,
    > + Send + 'a;

    fn unwrap_key<'a>(
        &'a self,
        payload: &'a [u8],
    ) -> impl Future<
        Output = XSecResult<SecretBox<[u8; 32]>>,
    > + Send + 'a;
}
```

`kind` 返回稳定的保护器类型标识，用于确认实现能否处理对应 payload。标识属于持久化协议，发布后不得修改。v1 的 `kind` 只能包含 ASCII 小写字母、数字、点、下划线和连字符，必须匹配 `[a-z0-9][a-z0-9._-]*`，长度不得超过 128 bytes。同一个 metadata 中不允许出现两个相同的 `kind`。

payload 格式由 Protector 自己管理，必须包含格式版本并兼容已发布的旧版本。需要认证的算法标识、版本、KDF 参数和系统密钥引用都必须绑定到 payload 的完整性校验中。

密码保护器的 payload 包含格式版本、Argon2id 参数、salt、nonce 和加密后的 DEK。系统保护器的 payload 规则见 [`SYSTEM_PROTECTOR.md`](SYSTEM_PROTECTOR.md)。

### metadata 完整性

每个 Protector 负责认证自己的 payload。XSec 还必须对完整 metadata 做整体认证，防止攻击者删除、替换或重新排列保护器记录。

v1 metadata 使用以下 canonical binary encoding：

```text
metadata_magic          [6 bytes] = "XSecMD"
format_version          u16 big-endian = 1
algorithm               u16 big-endian = 1 (AES-256-GCM)
protector_count         u16 big-endian

repeat protector_count times:
    kind_length         u16 big-endian
    kind                [kind_length bytes]
    payload_length      u32 big-endian
    payload             [payload_length bytes]

metadata_mac            [32 bytes]
```

保护器记录必须按 `kind` 的原始 ASCII bytes 严格升序存储。解析器必须拒绝重复 `kind`、乱序记录、无效 `kind`、长度溢出、字段截断和 `metadata_mac` 后的额外数据。payload 是不透明 bytes，按原始内容参与认证。v1 不允许未知字段；增加字段时必须提升 `format_version`。

canonical encoding 同时是 Storage 保存的实际编码。创建和更新 metadata 时，XSec 必须先排序并编码保护器记录，再计算 MAC。读取时必须对原始编码执行严格解析，不得接受非 canonical 编码，也不得解析后重新序列化来生成 MAC 输入。

metadata 认证密钥按以下方式派生：

```text
metadata_auth_key = HKDF-SHA256(
    salt = empty,
    ikm = DEK,
    info = "xsec:metadata-auth:v1",
    output_length = 32
)
```

`salt = empty` 表示 RFC 5869 中未提供 salt 的行为。metadata MAC 定义为：

```text
metadata_mac = HMAC-SHA256(
    key = metadata_auth_key,
    message = metadata_blob_without_mac
)
```

`metadata_blob_without_mac` 是完整 metadata blob 去掉末尾 32 bytes 后的原始字节。验证时必须使用 constant-time comparison。

`open` 只能执行长度、格式、canonical encoding 和结构校验。`unlock` 恢复 DEK 后，对原始 `metadata_blob_without_mac` 验证 metadata MAC，验证通过后才能进入 `Unlocked` 状态。MAC 不匹配时返回 `XSecError::Corrupted`。

旧 metadata 连同有效 MAC 一起回滚时仍能通过验证。第一版不提供防回滚能力。

## Password Protector

```rust
pub struct XSecPasswordProtector {
    // Internal fields are private.
}

impl XSecPasswordProtector {
    pub fn new(
        password: SecretBox<Vec<u8>>,
    ) -> Self;
}
```

默认使用 Argon2id。新建 metadata 时保存实际使用的 KDF 参数，解锁时读取持久化参数，不依赖当前默认值。

v1 新建密码保护器时使用以下固定参数，调用方不能覆盖：

| 参数               |    默认值 |
| ------------------ | --------: |
| memory cost        | 65536 KiB |
| time cost          |         3 |
| parallelism        |         1 |
| salt length        |  16 bytes |
| derived key length |  32 bytes |

密码保护器在解析持久化 payload 后、启动 Argon2id 前，必须执行以下检查：

| 项目               |            v1 接受范围 |
| ------------------ | ---------------------: |
| payload length     |          不超过 64 KiB |
| memory cost        |       19456–262144 KiB |
| time cost          |                   2–10 |
| parallelism        |                    1–8 |
| salt length        |            16–64 bytes |
| nonce length       | 必须等于算法规定的长度 |
| derived key length |        必须为 32 bytes |

memory cost 还必须满足 Argon2id 对 parallelism 的结构约束。参数越界、整数转换溢出或长度不匹配时，必须在分配 KDF 工作内存前返回 `XSecError::Corrupted`；版本不受支持时返回 `XSecError::UnsupportedVersion`。不得尝试使用更弱参数或猜测性解析。

XSec 对完整 metadata 额外设置 1 MiB 的大小上限、16 个保护器的数量上限、128 bytes 的 `kind` 长度上限和 64 KiB 的单个 payload 上限。`open` 必须先检查这些限制，再分配由 metadata 字段控制的可变长度缓冲区。内置 Storage 也应在读取文件或 HTTP 响应时限制最大 blob 大小，避免在解析前无界分配内存。

Argon2id 是阻塞计算。`XSecPasswordProtector` 在异步 wrap/unwrap 流程中通过 `tokio::task::spawn_blocking` 执行 Argon2id。XSec 的异步 API 必须运行在 Tokio runtime 中。

## 密文格式

业务密文采用自描述二进制格式。v1 由以下字段组成：

```text
magic                  [6 bytes] = "XSecCT"
format_version         u16 big-endian = 1
algorithm              u16 big-endian = 1 (AES-256-GCM)
key_id                 [16 bytes]
nonce_length           u8
nonce                  [nonce_length bytes]
ciphertext_and_tag
```

实现中的 `Ciphertext` 表示完整的密文对象，由 `CiphertextHeader` 和
`ciphertext_and_tag` 组成。`CiphertextHeader` 的解析只接受 Header 本身，
不会解析或持有后续的加密 payload；完整密文的切分由 `Ciphertext` 负责。

`magic` 用于快速识别 XSec 密文。`format_version` 和 `algorithm` 用于格式演进。`key_id` 为后续数据密钥轮换保留；v1 不支持密钥轮换，因此 16 bytes 必须全部为零，解析器必须拒绝其他值。nonce 由 XSec 生成。

`header_bytes` 指密文中从 `magic` 开始到 `nonce` 结束的原始连续字节，不是单独存储的字段。AES-GCM 接收的完整 AAD 按以下格式构造：

```text
combined_aad =
    "xsec:data-aad:v1"
    || u32_be(header_bytes.length)
    || header_bytes
    || u64_be(user_aad.length)
    || user_aad
```

固定域分离标识无需额外长度字段。两个长度字段使用无符号大端编码，并在转换前检查溢出和实现规定的输入上限。长度分帧保证 `(header_bytes, user_aad)` 的不同组合不会产生相同的 `combined_aad`。

用户 AAD 不写入密文，调用方负责在解密时提供相同内容。`encrypt` 和 `decrypt` 使用长度为零的用户 AAD。解密时必须直接使用密文中的原始 `header_bytes` 构造 `combined_aad`，不得解析后重新序列化头部。

解析器必须先检查总长度、各字段长度、版本和算法，再读取可变长度字段。AES-256-GCM 的 v1 密文必须使用 12-byte nonce；其他 nonce 长度返回 `XSecError::InvalidCiphertext`。不支持的版本或算法不得做猜测性解析。Metadata 使用 `XSecMD` Magic，业务密文使用 `XSecCT` Magic；两者均为 6 bytes。

## 错误模型

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum XSecError {
    NotFound,
    AlreadyExists,
    StorageNotLoaded,
    AlreadyLoaded,
    NotInitialized,
    Locked,
    Destroyed,
    AlreadyUnlocked,
    AuthenticationFailed,
    Corrupted,
    InvalidCiphertext,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    ProtectorNotFound,
    ProtectorAlreadyExists,
    LastProtector,
    Storage {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    Protector {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    Crypto,
}

pub type XSecResult<T> = std::result::Result<T, XSecError>;
```

`XSecError` 使用 `#[non_exhaustive]`，允许后续增加错误类型。外部依赖的具体错误不直接成为公开 enum 成员，避免依赖升级改变 XSec 的公共 API。

认证失败不暴露底层密码校验、系统认证或密文校验细节。损坏数据与尚未初始化必须使用不同错误。

## 同步与异步边界

| 操作                                 | 接口形式                                         | 原因                               |
| ------------------------------------ | ------------------------------------------------ | ---------------------------------- |
| `XSecStorage::load/save/delete`      | async                                            | 文件、网络和数据库 I/O             |
| `XSecProtector::wrap_key/unwrap_key` | async                                            | 可能触发系统认证或远程 KMS         |
| AES-GCM encrypt/decrypt              | sync                                             | 纯内存计算                         |
| 密文编码和解析                       | sync                                             | 纯内存计算                         |
| Argon2id                             | sync computation + `tokio::task::spawn_blocking` | CPU 和内存密集型计算               |
| `XSec::load/create/unlock/destroy`   | async                                            | 编排 Storage、Protector 或阻塞任务 |
| `XSec::new/encrypt/decrypt/lock`     | sync                                             | 不执行 I/O                         |

## 不公开的接口

以下内容保留在 crate 内部：

- 原始 DEK 的 get/set 接口。
- `encrypt_with_nonce` 和 `decrypt_with_nonce`。
- metadata 的序列化结构及字段名称。
- 密文解析过程中的可变中间结构。
- AES-GCM、Argon2id 的底层工具函数。
- nonce、key length 等实现常量。
- 平台保护器的系统 API 适配细节。
- 保护器记录和 metadata 的序列化结构。

## 暂不纳入

- `Vault`、`LockedVault`、`UnlockedVault` 和 `VaultStatus`。
- `dyn XSecStorage` 和 `dyn XSecProtector`。
- 流式加密和流式解密。
- 多端同步、并发写入检测和冲突合并。
- 自动降级到更弱的认证方式。
- 数据密钥轮换。

数据密钥轮换需要保留旧 DEK 或提供业务密文迁移协议。第一版只支持重新包装同一个 DEK，不提供含义模糊的 `rotate_key`。

## 使用示例

```rust
use secrecy::SecretBox;
use xsec::{
    XSec,
    XSecFileStorage,
    XSecPasswordProtector,
    XSecResult,
};

async fn run() -> XSecResult<()> {
    let storage = XSecFileStorage::new("data/account.xsec.meta");
    let password = SecretBox::new(Box::new(b"correct horse battery staple".to_vec()));
    let protector = XSecPasswordProtector::new(password);

    let mut xsec = XSec::new();
    xsec.load(storage).await?;

    if xsec.is_initialized() {
        xsec.unlock(&protector).await?;
    } else {
        xsec.create(&protector).await?;
    }
    let ciphertext = xsec.encrypt_with_aad(
        b"alice@example.com",
        b"user:123/profile/email",
    )?;

    xsec.lock()?;
    xsec.unlock(&protector).await?;

    let plaintext = xsec.decrypt_with_aad(
        &ciphertext,
        b"user:123/profile/email",
    )?;

    assert_eq!(plaintext.as_slice(), b"alice@example.com");
    Ok(())
}
```
