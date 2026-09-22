# XSec Workspace

这是 XSec 的 Cargo workspace：

- `crates/xsec`：跨平台数据加密库。
- `crates/xsec-cli`：基于 `xsec` 的命令行程序。

## 构建和测试

```text
cargo check --workspace
cargo test --workspace
```

运行 CLI：

```text
cargo run -p xsec-cli -- init target/example.xsec change-me
```

库的 API 设计和安全边界见 [`crates/xsec/API_DESIGN.md`](crates/xsec/API_DESIGN.md)。
