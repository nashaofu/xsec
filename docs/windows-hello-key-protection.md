# XSec Windows Hello 本地密钥保护方案

## 1. 目标

本文档定义 XSec 在 Windows 上使用 Windows Hello 保护本地主密钥的方案。

目标如下：

- XSec 主密钥只以密文形式保存在本地 Store；
- Windows Hello 不被用作 AES 密钥派生材料；
- `RequestSignAsync` 的结果只作为签名使用，不作为对称密钥使用；
- 真正的本地密钥访问边界位于 CNG/KSP 的私钥操作；
- 不支持系统级用户验证时禁止静默降级；
- 保留密码 protector 作为独立恢复路径。

## 2. 安全边界

`RequestSignAsync` 产生的是 Windows Hello 私钥对 challenge 的签名。它适合用于身份认证和 challenge-response，但应用代码可以被修改或跳过，因此不能单独保护本地主密钥。

本地方案必须满足：

```text
直接调用 CNG/KSP 私钥解密
    -> 系统/provider 自己要求 Windows Hello
```

如果删除应用层的 `RequestSignAsync` 和签名验证后，仍然可以直接完成 CNG 解密，则该环境只能被标记为“应用层 Windows Hello 授权”，不能宣称为系统级 Windows Hello 密钥保护。

## 3. 总体流程

```text
随机生成 XSec 主密钥
        |
        v
CNG/KSP 公钥加密主密钥
        |
        v
Store 保存密文和元数据
        |
        v
NCryptDecrypt 解密
        |
        v
系统/provider 强制 Windows Hello
        |
        v
恢复 XSec 主密钥
```

纯本地场景不使用 `local_share`、`server_share` 或服务端分片。所有数据都在本地时，分片无法形成独立的信任边界，只会增加复杂度。

## 4. Store 数据

Store 只保存 CNG 密文和非敏感元数据，例如：

```json
{
  "version": 2,
  "algorithm": "Windows-CNG",
  "provider": "Microsoft Platform Crypto Provider",
  "key_name": "xsec-master-key",
  "encrypted_key": "...",
  "public_key_hash": "...",
  "requires_user_verification": true
}
```

Store 不得保存：

- CNG 私钥；
- Windows Hello 私钥；
- PIN 或生物识别数据；
- 明文 XSec 主密钥；
- `RequestSignAsync` 的签名结果；
- 由签名结果派生的长期 AES 密钥。

## 5. 初始化流程

以下为逻辑伪代码，具体 Rust/Win32 绑定不在本文档展开。

```text
InitializeWindowsHelloProtection():
    supported = KeyCredentialManager.IsSupportedAsync()
    if not supported:
        return WindowsHelloNotSupported

    result = KeyCredentialManager.RequestCreateAsync(
        credentialName,
        KeyCredentialCreationOption.FailIfExists
    )
    if result.Status != Success:
        return MapKeyCredentialStatus(result.Status)

    helloCredential = result.Credential
    publicKey = helloCredential.RetrievePublicKey()
    attestation = helloCredential.GetAttestationAsync()  # 可选

    provider = NCryptOpenStorageProvider(
        "Microsoft Platform Crypto Provider"
    )

    cngKey = NCryptCreatePersistedKey(
        provider,
        algorithm = "RSA",
        keyName = "xsec-master-key"
    )

    NCryptSetProperty(cngKey, "Export Policy", NonExportable)
    NCryptSetProperty(cngKey, "Key Usage", Decryption)
    NCryptSetProperty(cngKey, "UI Policy", RequireUserAuthentication)

    status = NCryptFinalizeKey(cngKey)
    if status == NTE_NOT_SUPPORTED:
        return ProviderNotSupported
    if status != Success:
        return CngKeyCreationFailed

    masterKey = RandomBytes(32)
    encryptedMasterKey = NCryptEncrypt(
        cngKey,
        masterKey,
        padding = OAEP
    )

    Store.save(metadata, encryptedMasterKey)
    return Success
```

创建密钥或配置强制用户验证失败时，不能回退到软件 KSP、普通 Credential Manager 或仅有应用层授权的实现。

## 6. 解锁流程

```text
UnlockXsec():
    metadata = Store.load()
    ValidateVersion(metadata.version)
    ValidateAlgorithm(metadata.algorithm)
    ValidateProvider(metadata.provider)

    provider = NCryptOpenStorageProvider(metadata.provider)
    cngKey = NCryptOpenKey(provider, metadata.key_name)

    masterKey = NCryptDecrypt(
        cngKey,
        metadata.encrypted_key,
        padding = OAEP
    )

    if length(masterKey) != 32:
        return AuthenticationFailed

    return XSec.Initialize(masterKey)
```

`NCryptDecrypt` 本身必须触发或要求 Windows Hello。不能把安全性建立在以下顺序上：

```text
RequestSignAsync
    -> 应用层验签
    -> 普通本地解密
```

## 7. `RequestSignAsync` 的可选用途

如果需要额外的本地业务确认，可以使用随机 challenge：

```text
AuthorizeOperation(operation):
    challenge = RandomBytes(32)
    message = Encode(
        protocol = "xsec/windows-hello/v2",
        operation = operation,
        credentialName = credentialName,
        challenge = challenge
    )

    result = KeyCredentialManager.OpenAsync(credentialName)
    if result.Status != Success:
        return AuthenticationFailed

    signResult = result.Credential.RequestSignAsync(message)
    if signResult.Status != Success:
        return MapKeyCredentialStatus(signResult.Status)

    signature = signResult.Result
    if not VerifySignature(publicKey, message, signature):
        return InvalidSignature

    return Success
```

禁止：

```text
SHA-256(signature) -> AES key
```

也禁止仅通过“签名非空”判断授权成功。必须使用已登记公钥执行真实验签。

如果使用 `UserConsentVerifier.RequestVerificationAsync`，它只能提供额外的显式用户确认，不能替代 CNG/KSP 的系统级密钥保护。

## 8. 删除和重置

删除流程：

```text
删除 Store metadata
KeyCredentialManager.DeleteAsync(credentialName)
NCryptOpenKey(provider, keyName)
NCryptDeleteKey(cngKey)
```

Windows Hello 被重置、密钥丢失或 provider 返回密钥无效时，旧的加密数据必须保持不可解密。不能自动生成新主密钥覆盖旧数据。

## 9. 错误处理

建议区分以下错误：

```text
WindowsHelloNotSupported
WindowsHelloNotConfigured
WindowsHelloCanceled
WindowsHelloLocked
ProviderNotSupported
UserVerificationRequired
AuthenticationFailed
KeyNotFound
Corrupted
Crypto
```

`NTE_NOT_SUPPORTED` 等表示 provider 不支持所需安全策略时，必须映射为 `ProviderNotSupported`，不能吞掉或静默降级。

## 10. 必须验证的安全属性

### 静态检查

- 不存在固定 challenge；
- 不存在 `SHA-256(signature)` 作为长期密钥；
- 不存在 software KSP fallback；
- 不存在明文主密钥、私钥或签名日志；
- Windows API 只存在于 target-gated 模块；
- portable core 不暴露 Windows 类型。

### Windows 实机测试

```text
创建 Windows Hello credential
创建 CNG/KSP key
确认 provider 类型
确认私钥不可导出
正常 NCryptDecrypt -> 要求 Windows Hello
取消 Hello -> 解密失败
错误 PIN -> 解密失败
设备锁定 -> 解密失败
重置 Windows Hello -> 旧密钥失效
删除 credential -> 旧 payload 不可解密
```

### 绕过测试

```text
移除 UserConsentVerifier 调用
移除 RequestSignAsync 调用
移除应用层签名验证
直接调用 NCryptDecrypt
确认仍然需要 Windows Hello 或返回失败
```

如果直接调用 `NCryptDecrypt` 可以成功，则该环境不满足系统级 Windows Hello 保护要求。

## 11. Windows API 清单

Windows Hello API：

- `KeyCredentialManager.IsSupportedAsync`
- `KeyCredentialManager.RequestCreateAsync`
- `KeyCredentialManager.OpenAsync`
- `KeyCredentialManager.DeleteAsync`
- `KeyCredential.RequestSignAsync`
- `KeyCredential.RetrievePublicKey`
- `KeyCredential.GetAttestationAsync`
- `UserConsentVerifier.RequestVerificationAsync`

CNG/KSP API：

- `NCryptOpenStorageProvider`
- `NCryptCreatePersistedKey`
- `NCryptSetProperty`
- `NCryptFinalizeKey`
- `NCryptOpenKey`
- `NCryptEncrypt`
- `NCryptDecrypt`
- `NCryptDeleteKey`
- `NCryptFreeObject`

## 12. 验收标准

该方案只有在以下条件全部满足时，才能称为 Windows Hello 本地密钥保护：

1. XSec 主密钥只以 CNG 密文形式保存在本地；
2. CNG 私钥不可导出；
3. 使用目标平台 provider；
4. provider 能强制用户验证；
5. `NCryptDecrypt` 本身受到 Hello 约束；
6. 删除应用层授权代码后仍不能无验证解密；
7. 不支持强制验证时不会静默降级；
8. 密码 protector 仍可独立工作。

## 13. 参考资料

- [Windows Hello 概述](https://learn.microsoft.com/zh-cn/windows/apps/develop/security/windows-hello)
- [创建 Windows Hello 登录应用](https://learn.microsoft.com/zh-cn/windows/apps/develop/security/windows-hello-login)
- [创建 Windows Hello 登录服务](https://learn.microsoft.com/zh-cn/windows/apps/develop/security/windows-hello-auth-service)
