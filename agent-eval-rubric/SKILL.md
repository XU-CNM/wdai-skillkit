---
name: agent-eval-rubric
description: 用多维 rubric 对 Agent/LLM 输出做加权评测：权重校验、缺失维度处理、复杂度分层、阈值判定。零 LLM 调用、可离线复算，用于回归评测与人工校准前的自动初筛。
---

# Agent Eval Rubric

把「Agent 输出好不好」变成**可复算的数字**，而不是一段主观评价。

## 何时使用

- 需要给 Agent / LLM 输出做回归评测或版本对比
- 已有多个评分维度（准确率、完整性、引用、工具效率…），要合成一个总分
- 需要把评测接入 CI，但不想每次调用外部模型

## 设计原则

1. **结果导向**：评「是否达成目标」，不评「是否走了某条路径」。
2. **多维而非单指标**：单一分数会掩盖系统性失败。
3. **权重显式**：权重必须非负且和为正，非法输入直接报错（fail-closed）。
4. **缺失维度按 0 计**，不静默补齐；多余/越界维度拒绝。
5. **复杂度分层**：简单 / 中等 / 复杂 / 极复杂分别统计，避免长任务掩盖短任务退化。

## 用法

```bash
# 单次评测
python scripts/eval_agent_rubric.py --rubric rubric.json --scores scores.json --threshold 0.7

# 输出 JSON：各维度得分、加权总分、是否通过、缺失维度
```

`rubric.json` 结构（维度名 → 权重）：

```json
{
  "factual_accuracy": 0.35,
  "completeness": 0.25,
  "citation_accuracy": 0.20,
  "source_quality": 0.10,
  "tool_efficiency": 0.05,
  "process_quality": 0.05
}
```

`scores.json`：维度名 → 0..1 分值。

## 校准纪律

- 自动评分只是**初筛**：结论必须用 held-out 人工标签校准后才可用于对外。
- 自报置信度与位置一致性是**诊断量**，不是校准概率。
- 95% 方差解释类的结论是特定实验的关联，不是通用因果规律。

## 边界

- 不做 LLM 调用，也不生成评分理由；理由与证据由调用方提供。
- 不替代人工评审；高风险决策保留人工复核。
