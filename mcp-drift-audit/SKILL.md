---
name: mcp-drift-audit
description: 静态审计 MCP 配置中的可变依赖引用（npm/npx 无版本 pin、latest、范围版本），零执行、不改配置、输出 Markdown 报告。用于 MCP 配置上线前、CI 门禁或安全复核。
---

# MCP Drift Audit

静态审计 Model Context Protocol 配置里的**依赖可变性**：一个配置在评审通过之后，
是否可能因为 `@latest` 或无版本引用而解析到**不同的代码**。

## 何时使用

- 新增 / 修改 `.mcp.json`、`mcp.json`、Cursor / VS Code / Claude 的 MCP 配置之后
- 把 MCP 配置纳入 CI 或上线评审之前
- 安全复核：确认已评审的配置不会静默升级到未审代码

## 核心原则

1. **零执行**：只读配置文本，绝不运行配置里的 `command`。
2. **漂移 ≠ 漏洞**：可变引用是「复现性/评审边界」信号，不是恶意或漏洞证据。
3. **不猜版本**：只建议 pin 到团队**实际审过**的版本。
4. **不泄密**：报告不含 token、header、环境变量值。

## 分类规则

| 选择器 | 分类 | 含义 |
|---|---|---|
| `pkg@1.2.3` | PINNED | 版本固定；传递依赖与安装钩子仍需单独审 |
| `pkg` / `@scope/pkg` | HIGH | 后续解析可取到不同代码 |
| `pkg@latest` | HIGH | 显式可变 |
| `^1.2.0` / `~1.2.0` / `>=` / `*` | MEDIUM | 允许范围内可变 |
| 本地路径 / 脚本 / 二进制 | REVIEW | 版本规则不适用，需人工判断 |

`-y` / `--yes` 只作上下文，不单独构成风险。

## 用法

```bash
python scripts/audit_mcp_drift.py --root . --output-md mcp_drift_report.md
```

参数（以脚本 `--help` 为准）：

- `--root`：扫描根目录（默认当前目录）
- `--output-md`：Markdown 报告输出路径

退出码非 0 表示发现 HIGH 级可变引用，可直接用于 CI 门禁。

## 输出

Markdown 表格：配置路径 / MCP server / 包引用 / 分类 / 原因 / 建议下一步，
并声明「本次审计未执行任何 MCP server」。

## 边界

- 只覆盖 npm/npx 风格的包引用；不覆盖 Python `uvx` 以外的运行时、二进制、远程 URL。
- 不评估 prompt injection、工具投毒、OAuth、服务实现缺陷。
- 干净结果**不等于**完整的 MCP 安全评估。
