"""Agent 评测多维 rubric 加权聚合（AAS evaluation 技能落地，2026-10-24）。

对应 evaluation 技能方法论：
    - 多维 rubric：事实准确/完整性/引用准确/来源质量/工具效率等维度，
      每维 0.0-1.0 评分 + 权重；
    - 权重必须为非负且总和为正（evaluation 技能：validate nonnegative
      weights with a positive sum）；
    - 通过阈值按用例要求设定（技能示例默认 0.7）；
    - 复杂度分层：simple/medium/complex/very_complex 测试集设计辅助。

本模块为纯函数，不调用任何 LLM；评测判定由调用方按 rubric 产出维度评分后
调用本模块聚合。自报置信度/评分是诊断量，非校准概率（口径见
docs/evaluation/judge-rubric.md 与 agent-eval-framework.md）。

用法：
    python scripts/eval_agent_rubric.py \
        --rubric '{"factual_accuracy":0.4,"completeness":0.3,"tool_efficiency":0.3}' \
        --scores '{"factual_accuracy":0.9,"completeness":0.7,"tool_efficiency":0.6}' \
        [--threshold 0.7]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_THRESHOLD = 0.7
COMPLEXITY_LEVELS = ("simple", "medium", "complex", "very_complex")


class RubricError(ValueError):
    """rubric/权重校验失败（fail-closed：宁可报错不做非法聚合）。"""


def validate_weights(weights: Dict[str, float]) -> None:
    """校验权重：全为非负、至少一项 >0、数值有限。非法即抛 RubricError。"""
    if not isinstance(weights, dict) or not weights:
        raise RubricError("权重必须是非空 dict")
    for dim, w in weights.items():
        try:
            wf = float(w)
        except (TypeError, ValueError):
            raise RubricError(f"维度 {dim!r} 权重非数值: {w!r}")
        if wf < 0 or wf != wf or wf in (float("inf"), float("-inf")):
            raise RubricError(f"维度 {dim!r} 权重非法（需 0<=w<inf）: {w!r}")
    if sum(float(w) for w in weights.values()) <= 0:
        raise RubricError("权重总和必须为正")


def weighted_overall(scores: Dict[str, float], weights: Dict[str, float]) -> float:
    """加权聚合 0.0-1.0 总分。缺失维度按 0 计（fail-closed），多出维度拒绝。"""
    validate_weights(weights)
    extra = set(scores) - set(weights)
    if extra:
        raise RubricError(f"scores 含未定义维度: {sorted(extra)}")
    total = 0.0
    for dim, w in weights.items():
        s = scores.get(dim, 0.0)
        try:
            sf = float(s)
        except (TypeError, ValueError):
            raise RubricError(f"维度 {dim!r} 评分非数值: {s!r}")
        if not (0.0 <= sf <= 1.0):
            raise RubricError(f"维度 {dim!r} 评分需在 [0,1]: {s!r}")
        total += w * sf
    return total / sum(float(w) for w in weights.values())


def assess_passed(overall: float, threshold: float = DEFAULT_THRESHOLD) -> bool:
    """通过判定：overall >= threshold。"""
    return overall >= threshold


def complexity_level(description: str, tool_calls: Optional[int] = None) -> str:
    """测试集复杂度分层辅助（evaluation 技能）：按调用数与歧义粗分。

    simple: 单次工具调用/事实查询；medium: 多次调用+比较逻辑；
    complex: 大量调用+聚合/合成；very_complex: 长交互+深度推理。
    仅作登记辅助，不替代人工分层。
    """
    d = description.lower()
    if tool_calls is not None:
        if tool_calls <= 1:
            return "simple"
        if tool_calls <= 5:
            return "medium"
        if tool_calls <= 15:
            return "complex"
        return "very_complex"
    if any(k in d for k in ("extended", "deep", "synthesis", "research", "长交互", "深度推理")):
        return "very_complex"
    if any(k in d for k in ("aggregate", "summary", "分析", "汇总", "synthesis")):
        return "complex"
    if any(k in d for k in ("compare", "comparison", "multi", "比较", "多步")):
        return "medium"
    return "simple"


def _load_json_arg(value: str) -> dict:
    """接受 JSON 字符串或 JSON 文件路径（兼容 Windows BOM）。"""
    p = Path(value)
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8-sig"))
    return json.loads(value)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Agent 多维 rubric 加权聚合（纯函数）")
    ap.add_argument("--rubric", required=True,
                    help='JSON 字符串或文件路径: {"dim": weight, ...}')
    ap.add_argument("--scores", required=True,
                    help='JSON 字符串或文件路径: {"dim": score, ...}')
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    args = ap.parse_args(argv)

    try:
        weights = _load_json_arg(args.rubric)
        scores = _load_json_arg(args.scores)
        overall = weighted_overall(scores, weights)
        passed = assess_passed(overall, args.threshold)
    except (json.JSONDecodeError, RubricError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    out = {
        "overall": round(overall, 4),
        "threshold": args.threshold,
        "passed": passed,
        "dimensions": {d: round(float(scores.get(d, 0.0)), 4) for d in weights},
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
