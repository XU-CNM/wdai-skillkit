# Attribution

本仓库代码为**独立实现**，由 XU-CNM 编写，以 MIT 许可证发布。
下列来源提供了方法论与设计思路的启发，**未直接复制其代码**；如后续引入任何第三方代码，
将在本文件与本目录中保留其原始许可证与版权声明。

## 方法论启发

| 本仓库组件 | 启发来源 | 许可证 |
|---|---|---|
| `mcp-drift-audit` | `mcp-dependency-drift-audit`（分类模型：PINNED / HIGH / MEDIUM / REVIEW；零执行原则） | MIT |
| `agent-eval-rubric` | `evaluation` 与 `advanced-evaluation`（多维 rubric、复杂度分层、结果导向评测） | MIT |
| `skill-enable-gate` | `skill-audit` 与 `skill-security-audit`（启用前静态审查、fail-closed、示例语境降级） | MIT / CC0-1.0 |

上述方法论条目来自 [agentic-awesome-skills](https://github.com/) 聚合库中的社区技能。
本仓库仅吸收其公开描述的方法论，具体代码与文本均为原创。

## 边界声明

- 本仓库不包含任何攻击性工具、漏洞利用代码或绕过安全控制的实现。
- 三个工具均默认只读、零执行；不运行被检查对象中的任何命令。
- 检查结果为**工程信号**，不构成安全认证、合规结论或法律意见。

## 商标

项目名称与仓库内容不代表任何第三方组织的官方立场或背书。
