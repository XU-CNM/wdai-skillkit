# WDAI Skillkit

**面向 AI 可信验证 / 安全监理场景的三件可复用工具**：MCP 依赖漂移审计、Agent 评测 rubric、技能启用安全门。
全部零外部依赖、纯 Python 标准库、默认只读、可直接进 CI。

## 为什么是这三个

| 工具 | 解决的问题 | 强需求场景 |
|---|---|---|
| `mcp-drift-audit` | MCP 配置评审后可能静默解析到新代码 | 供应链安全、上线评审、CI 门禁 |
| `agent-eval-rubric` | Agent 输出质量无法复算、无回归基线 | 模型/提示词版本对比、评测流水线 |
| `skill-enable-gate` | 第三方技能批量启用前缺少统一准入 | 技能市场、团队技能仓、合规审查 |

三者共享同一套工程立场：**零执行、fail-closed、结论可追溯、不把检查结果当安全证书**。

## 快速开始

```bash
git clone https://github.com/XU-CNM/wdai-skillkit.git
cd wdai-skillkit

# 1. MCP 依赖漂移
python mcp-drift-audit/scripts/audit_mcp_drift.py --root . --output-md drift.md

# 2. 评测 rubric
python agent-eval-rubric/scripts/eval_agent_rubric.py \
  --rubric rubric.json --scores scores.json --threshold 0.7

# 3. 技能启用门控
AGENT_SKILLS_DIR=./skills python skill-enable-gate/scripts/check_enable_sop.py
```

Python 3.10+，无需 `pip install`。

## 目录

```
mcp-drift-audit/     SKILL.md + scripts/audit_mcp_drift.py
agent-eval-rubric/   SKILL.md + scripts/eval_agent_rubric.py
skill-enable-gate/   SKILL.md + scripts/check_enable_sop.py
```

每个目录都是一个标准 Agent Skill：`SKILL.md` 提供触发条件与方法论，`scripts/` 提供可执行实现。

## 设计边界（请先读）

- **静态检查不等于安全证明**。未命中已知模式，不代表运行时安全。
- **漂移不是漏洞**。可变版本是复现性信号，除非另有证据。
- **评测不是判决**。自动评分需用 held-out 人工标签校准；高风险决策保留人工复核。
- **技能门控不执行任何代码**，因此也无法发现运行时才暴露的依赖与远程行为。

## 许可证

代码：MIT（见 `LICENSE`）。
方法论启发来源与署名见 `ATTRIBUTION.md`。
