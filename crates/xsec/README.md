# XSec

XSec 是一个跨平台数据加密库。它生成并管理数据加密密钥（DEK），使用密码或调用方提供的系统/KMS 保护器包装 DEK，并提供稳定的 AES-256-GCM 加解密接口。

业务密文由调用方保存；`XSecStorage` 只保存 XSec 自身的 metadata。

## 特性

- 随机 DEK 与随机 nonce 的 AES-256-GCM 数据加密
- 与密文头一起认证的用户 AAD
- Argon2id 密码保护器（固定安全参数，阻塞计算由 Tokio 调度）
- canonical binary metadata 与 HKDF/HMAC-SHA256 整体认证
- Metadata 使用 `XSecMD` 标识，业务密文使用 `XSecCT` 标识
- 可扩展的异步 `XSecStorage` 和 `XSecProtector`
- 敏感密钥与解密结果使用 `SecretBox` / `Zeroizing`
- `file-storage` 默认 feature 提供单 blob 原子文件存储
- `password-protector` 默认 feature 提供 Argon2id 密码保护器

`XSecStorage` 和 `XSecProtector` 只定义抽象接口。具体实现位于对应子模块，并通过 feature 按需编译：`storage/file.rs`、`protector/password.rs`。

## 快速开始

```rust
use secrecy::SecretBox;
use xsec::{XSec, XSecFileStorage, XSecPasswordProtector, XSecResult};

#[tokio::main]
async fn main() -> XSecResult<()> {
    let storage = XSecFileStorage::new("data/account.xsec");
    let password = SecretBox::new(Box::new(b"correct horse battery staple".to_vec()));
    let protector = XSecPasswordProtector::new(password);
    let mut xsec = XSec::create(storage).await?;
    xsec.add_key_protector(&protector).await?;
    xsec.unlock(&protector).await?;
    let ciphertext = xsec.encrypt_with_aad(b"alice@example.com", b"user:123/profile/email")?;
    xsec.lock()?;
    xsec.unlock(&protector).await?;
    let plaintext = xsec.decrypt_with_aad(&ciphertext, b"user:123/profile/email")?;
    assert_eq!(plaintext.as_slice(), b"alice@example.com");
    Ok(())
}
```

完整格式、安全边界和 API 契约见 [`API_DESIGN.md`](API_DESIGN.md)。

## 安全边界

- 密码强度决定 metadata 被窃取后的离线猜测难度。
- `create` 返回锁定状态且尚未持久化的实例，不生成或暂存 DEK；首次添加密钥保护器时才生成 DEK 并保存 metadata。之后必须使用已添加的保护器解锁。
- `destroy` 删除当前 Storage 中的 metadata，但不保证磁盘、备份或快照已物理擦除。
- v1 不提供回滚保护、数据密钥轮换、多端同步或并发写入冲突处理。
- 第三方 `XSecProtector` 能接触明文 DEK，必须视为受信任代码。

## License

Apache-2.0
