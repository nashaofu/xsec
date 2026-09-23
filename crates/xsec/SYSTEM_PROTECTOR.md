# XSecSystemProtector 设计

## 定位

`XSecSystemProtector` 使用当前操作系统提供的密钥保护能力包装和解包 DEK。调用方只依赖一个公开类型，不感知 Keychain、Android Keystore、Windows CNG 等底层模型。

`XSecSystemProtector` 在所有平台上遵守同一条安全语义：

- DEK 只以 wrapped key 形式进入 metadata。
- 系统侧持久化密钥不可导出。
- 解包 DEK 时必须由系统验证当前用户。
- 平台无法满足这些条件时返回明确错误，不得降级到更弱的保护方式。

密码回退由调用方通过 `XSecPasswordProtector` 单独配置，`XSecSystemProtector` 不自动切换保护器。

## 公开 API

`XSecProtector` 的定义保持不变。`XSecSystemProtector` 是它的具体实现：

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

```rust
pub struct XSecSystemProtector {
    // Platform backend and derived key identifier are private.
}

impl XSecSystemProtector {
    /// 创建系统保护器，不执行 I/O。
    pub fn new(
        identity: impl Into<String>,
    ) -> Self;

    /// 检查系统保护能力和用户验证配置。
    ///
    /// 该方法不创建或修改持久化密钥，也不触发用户认证。检查结果只用于预检，
    /// backend 可创建并立即释放非持久化探测密钥。
    pub async fn check_availability(
        &self,
    ) -> XSecResult<()>;

    /// 删除该 identity 对应的 Windows Hello Credential。
    ///
    /// 删除是幂等的；对象不存在时返回成功。
    pub async fn delete(&self) -> XSecResult<()>;
}

impl XSecProtector for XSecSystemProtector {
    fn kind(&self) -> &'static str {
        "system"
    }

    // wrap_key and unwrap_key use the private platform backend.
}
```

crate 根只导出统一类型：

```rust
#[cfg(feature = "system-protector")]
pub use protector::XSecSystemProtector;
```

不得公开平台枚举、平台专用 Protector、原生密钥句柄或底层认证配置。

## identity

`identity` 是当前 XSec Storage 对应的稳定逻辑身份：

- 相同 Storage 必须始终使用相同 `identity`。
- 不同 Storage 应使用不同 `identity`。
- `identity` 不是用户身份、认证凭据或秘密。
- 调用方不需要遵守平台原生密钥的命名限制。
- `identity` 不得包含依赖显示文案或运行时随机值等不稳定内容。

实现不得直接使用原始 `identity` 作为平台密钥名称。平台密钥名称按以下方式派生：

```text
platform_key_id =
    hex(SHA256(
        "xsec:system-protector:v1"
        || u32_be(identity.length)
        || identity
    ))
```

长度字段使用无符号大端编码。当前实现限制 `identity` 最多为 4096 个 UTF-8 字节，超出时构造函数会拒绝继续。metadata 和系统密钥名称中都不保存原始 `identity`。

## 平台分发

平台选择发生在 crate 内部，并在编译期完成。公开类型不保存 `dyn` backend，也不执行运行时平台判断。

```rust
mod system {
    #[cfg(target_vendor = "apple")]
    mod apple;

    #[cfg(target_os = "android")]
    mod android;

    #[cfg(target_os = "windows")]
    mod windows;

    #[cfg(not(any(
        target_vendor = "apple",
        target_os = "android",
        target_os = "windows",
    )))]
    mod unsupported;

    // The selected module provides the private Backend type.
}
```

各平台依赖必须放在对应的 Cargo target dependency 下。`system-protector` 是唯一公开 feature，调用方不选择具体 backend。

不支持的平台仍可构造 `XSecSystemProtector`，但 `check_availability`、`wrap_key` 和 `unwrap_key` 必须返回 `XSecError::SystemProtectorUnavailable`。不得使用 `XSecError::Crypto` 表示平台不支持。

移动平台需要宿主运行时或 UI context 时，由平台绑定层在 crate 内部处理。原生 Activity、窗口句柄和认证对象不得进入公共 API。

## kind 和 payload

所有平台统一返回：

```text
kind = "system"
```

平台差异写入私有 payload envelope：

```text
magic                  [6 bytes] = "XSecSP"
format_version         u16 big-endian = 1
identity_hash          [32 bytes]
persistent_challenge   [16 bytes]
nonce                  [12 bytes]
wrapped_dek            [48 bytes] (AES-256-GCM ciphertext + tag)
```

`identity_hash` 使用与平台密钥名称相同的长度分帧输入计算。当前 payload 是固定长度，解析器必须拒绝未知版本、字段截断和 payload 后的额外数据。

AES-256-GCM 的 AAD 是从 magic 到 nonce 结束的完整 header，必须绑定以下内容的完整性：

- envelope 版本。
- `identity_hash`。
- persistent challenge 和 nonce。
- wrapped DEK。

Windows backend 当前使用 16 字节随机 persistent challenge，与 `biometric/`
参考实现一致。完整 envelope header 都作为
AES-256-GCM AAD；wrapped DEK 本身由 GCM tag 认证。

metadata 移到其他操作系统后，当前 backend 无法处理原 payload 时返回 `XSecError::IncompatibleSystemProtector`。调用方可使用其他 Protector 解锁，再替换 `system` 记录。

v1 的 metadata 最多保存一个 `kind = "system"` 的记录，与单设备、单写者约束保持一致。多设备同时保留多个系统保护器不在 v1 范围内。

## 操作语义

### new

`new` 只保存并派生 `identity`，不得访问系统密钥服务，不得创建密钥，也不得触发用户认证。

### check_availability

`check_availability` 检查：

- 当前平台是否有可用 backend。
- 系统密钥服务是否可用。
- 用户是否配置了满足要求的本地验证方式。
- backend 是否能够提供不可导出的持久化密钥。

该方法不得创建或修改持久化系统密钥，也不得触发用户认证。平台没有只读 capability API 时，backend 可创建并立即释放非持久化探测密钥，以验证硬件密钥和认证策略的创建能力。检查结果可能在返回后失效，`wrap_key` 和 `unwrap_key` 必须独立验证前置条件。

### wrap_key

Windows Hello backend 的首次创建流程为：

```text
创建或打开 KeyCredential
    ↓
生成持久化随机 challenge
    ↓
RequestSignAsync(challenge)
    ↓
SHA-256(signature) 后使用 HKDF-SHA-256 派生 KEK
    ↓
使用 AES-256-GCM 包装 DEK
```

`wrap_key` 必须在 `RequestSignAsync` 返回 `Success` 并得到非空签名后才允许产生最终
payload。Windows Hello 自己持有私钥并执行签名。

Windows Hello 私钥不得导出到 Rust 内存。由签名派生的 KEK 只允许在一次
wrap/unwrap 调用期间短暂存在于 Rust 内存，并必须使用 `Zeroizing` 清理。

### unwrap_key

`unwrap_key` 严格解析 payload，核对 envelope 和 identity hash，随后执行：

```text
解析 XSecSP payload
    ↓
读取 payload 中的 persistent challenge
    ↓
RequestSignAsync(challenge)
    ↓
Windows Hello 返回成功的 signature
    ↓
从 signature 派生相同 KEK
    ↓
使用 AES-256-GCM 解包 DEK
```

不得把签名结果直接当作 DEK。Windows Hello 的签名操作本身由系统 Credential
provider 执行。

用户验证必须约束实际的解包操作。不得先执行一个独立的认证或签名请求，再使用不受该次认证约束的另一把密钥解包。

Windows 实现不得另建可独立调用 `NCryptDecrypt` 的 CNG 包装密钥。Windows Hello
签名经 SHA-256 和 HKDF-SHA-256 派生 KEK，使用户验证与 DEK 解包形成密码学绑定。
`NCRYPT_UI_POLICY` 或通用 CNG 密钥保护界面不等同于 Windows Hello。

XSec 不区分 key 是否已经存在于进程内存，也不实现 Bitwarden 的 AFU 临时解锁路径。
每次 `wrap_key` 和 `unwrap_key` 都统一执行 Windows Hello `RequestSignAsync`，再派生
KEK 并包装或解包 DEK。进程内 secure memory 属于上层调用方的职责。

Windows WinRT 操作使用真正的 Rust async 等待，不在异步 API 内调用阻塞式 `.get()`。

### 兼容性

当前实现写入统一 `XSecSP` envelope v1。项目尚未发布，不提供旧实验 payload 的兼容或迁移；格式变化直接通过版本号拒绝，调用方需要重新注册 system protector。

Windows Hello PRF 遵循 `biometric/` 参考实现：对持久化 challenge 请求签名，再对
签名做 SHA-256。该设计依赖同一 Credential 对同一 challenge 产生稳定签名；发布前
必须在目标 Windows 版本上完成首次注册、进程重启后解锁以及绕过测试。

## 错误模型

系统保护器使用平台无关的错误：

```rust
SystemProtectorUnavailable
SystemAuthenticationNotConfigured
IncompatibleSystemProtector
SystemKeyNotFound
SystemKeyInvalidated
AuthenticationCancelled
AuthenticationFailed
```

平台 SDK 的具体错误放入现有的 `XSecError::Protector` source，不直接成为公开 enum 成员。认证失败不得暴露使用了 PIN、生物识别还是其他设备凭据。

## 使用示例

```rust
let protector = XSecSystemProtector::new(
    "com.example.app/account-123/primary",
);

protector.check_availability().await?;

if xsec.is_initialized() {
    xsec.unlock(&protector).await?;
} else {
    xsec.create(&protector).await?;
}
```

示例中的 `identity` 只展示结构，不要求使用反向域名格式。业务应从稳定、非敏感且能唯一标识当前 Storage 的数据生成 `identity`。

## 暂不纳入

- 公开平台名称和 backend 类型。
- 调用方选择 Keychain、CNG 或 Keystore 算法。
- 自动降级到密码保护器。
- 同一 metadata 保存多个平台的 `system` 记录。
- 系统密钥迁移和多设备同步。
- 将平台原生 UI context 暴露给 XSec 核心 API。
