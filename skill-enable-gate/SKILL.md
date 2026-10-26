---
name: skill-enable-gate
description: Agent 技能启用前的静态安全门：检查 frontmatter 完整性、指令覆盖、凭据读取、编码负载、管道下载、自复制、白名单外网络外发与 offensive 标记，fail-closed 输出 pass/review/block。
category: security
tags: [security, audit, skill-gate, supply-chain]
---

# Skill Enable Gate

在把第三方 Agent Skill 放进启用目录**之前**做一次零执行的静态门控。

## 何时使用

- 从 GitHub / 市场批量拉取技能后，挑一批准备启用
- 团队要一条可进 CI 的技能准入校验
- 安全复核：确认启用区没有明显的指令覆盖、凭据读取、下载执行

## 判定模型

以下为**检测示例**（规则清单，用于识别而非执行）：

每个技能输出一个状态：`pass` / `review` / `block`。

| 规则 | 判定 |
|---|---|
| frontmatter 缺 `name` 或 `description` | block |
| 指令覆盖（`ignore previous instructions` 等） | block |
| 凭据读取 + 网络外发组合 | block |
| 管道下载后直接执行 | block |
| 编码负载（base64 后执行） | block |
| 自复制 / 全局安装 | block |
| offensive 标记或索引 `risk=offensive` | block（一票否决） |
| 安全/防御类技能正文里的**示例语境** | 降级为 review，不算攻击行为 |
| 白名单外的外部 fetch | review |

**fail-closed**：任一技能 block 即整体退出码非 0，适合直接做 CI 门禁。

## 用法

```bash
# 扫描目录（默认取 AGENT_SKILLS_DIR 或仓库内 .user_skills）
AGENT_SKILLS_DIR=/path/to/skills python scripts/check_enable_sop.py

# 显式指定
python scripts/check_enable_sop.py --skills-dir ./skills --index skills_index.json
```

输出 JSON：逐技能状态、命中规则、汇总计数，以及 `index_loaded` / `offensive_ids_loaded`。

## 关键纪律

1. **零执行**：只读 SKILL.md 文本，不 import、不运行技能里的任何代码。
2. **示例不是行为**：防御类文档描述攻击模式是正常的，不能因关键词命中就判为恶意。
3. **一票否决可追溯**：offensive 判定必须能指出命中的 id 或索引条目。
4. **不自动放行 review**：review 需要人工裁决，工具不替人做决定。

## 边界

- 静态检查无法证明运行时安全（依赖、远程服务、模型行为都不在范围内）。
- 不检测 Prompt Injection 的实际触发，只检测明显的静态模式。
- 一个绿色结果只说明「未命中已知模式」，不是安全证书。
