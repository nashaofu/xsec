# XSec Workspace

这是 XSec 的 Cargo workspace：

- `crates/xsec`：跨平台数据加密库。
- `crates/xsec-cli`：基于 `xsec` 的命令行程序。

## 构建和测试

```text
cargo check --workspace
cargo test --workspace
```

## CLI

Cargo 包名为 `xsec-cli`，生成的可执行文件名为 `xsec`。

初始化密码保护的项目存储：

```text
cargo run -p xsec-cli --bin xsec -- init
```

在支持的平台上，可在初始化后为同一个 DEK 添加 system protector：

```text
cargo run -p xsec-cli --bin xsec -- protector add system --identity your-project-id
```

不再需要 system protector 时可将其删除：

```text
cargo run -p xsec-cli --bin xsec -- protector remove system
```

将 `.env` 中的每个值分别加密到 `.xsec`，再解密并注入子进程：

```text
cargo run -p xsec-cli --bin xsec -- encrypt -i .env -o .xsec
cargo run -p xsec-cli --bin xsec -- run -f .xsec -- your-command
```

读取、设置和删除单个环境变量：

```text
cargo run -p xsec-cli --bin xsec -- get API_TOKEN -f .xsec
cargo run -p xsec-cli --bin xsec -- set API_TOKEN -f .xsec
cargo run -p xsec-cli --bin xsec -- set API_TOKEN "$API_TOKEN" -f .xsec
cargo run -p xsec-cli --bin xsec -- del API_TOKEN -f .xsec
```

`set` 会在目标环境文件不存在时自动创建该文件。

默认文件职责：

```text
.env                明文输入，不应提交
.xsec               保留 dotenv 结构的逐值加密环境文件
.xsec.production    生产环境密文
.xsec.keys          被保护的 DEK 及 Protector metadata 存储文件，不应提交
```

`.xsec` 中的密文值使用 `xsec:<base64url-no-padding>` 格式，`xsec:` 是密文保留前缀。

库的 API 设计和安全边界见 [`crates/xsec/API_DESIGN.md`](crates/xsec/API_DESIGN.md)。
CLI 的完整用法见 [`crates/xsec-cli/README.md`](crates/xsec-cli/README.md)。
