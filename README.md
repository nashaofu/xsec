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

初始化密码保护的项目 metadata：

```text
cargo run -p xsec-cli --bin xsec -- init
```

将完整的 `.env` 文档加密为 `.xsec`，再解密并注入子进程：

```text
cargo run -p xsec-cli --bin xsec -- env encrypt -i .env -o .xsec
cargo run -p xsec-cli --bin xsec -- run -f .xsec -- your-command
```

默认文件职责：

```text
.env                明文输入，不应提交
.xsec               默认环境密文
.xsec.production    生产环境密文
.xsec.meta          被保护的 DEK 和 Protector metadata，不应提交
```

库的 API 设计和安全边界见 [`crates/xsec/API_DESIGN.md`](crates/xsec/API_DESIGN.md)。
CLI 的完整用法见 [`crates/xsec-cli/README.md`](crates/xsec-cli/README.md)。
