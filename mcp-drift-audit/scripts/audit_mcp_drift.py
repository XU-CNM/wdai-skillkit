"""MCP 配置依赖漂移静态审计（AAS mcp-dependency-drift-audit 方法论落地，2026-10-24）。

目的：审计 MCP 启动引用（.mcp.json / .cursor/mcp.json 等配置文件，以及本项目
代码内硬编码的 npm/npx/uvx 启动命令）的**包引用可变性**，在审批/CI 前发现
"配置被审查后，同一引用可能解析到不同代码"的漂移风险。

纪律（对应技能 Rules）：
    - **只读配置文本**，绝不执行配置里的 command/args（不启动 MCP server）；
    - 漂移分类是"复现性/审查漂移信号"，不是漏洞/恶意/受损证明；
    - 敏感值（token/密钥/私有 header）不进入报告；
    - 不猜要 pin 的版本——只建议"pin 团队实际审查过的确切版本"。

用法：
    python scripts/audit_mcp_drift.py [--root <项目根>] [--output-md <out.md>]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

#: 常见 MCP 配置文件名（技能列出的已知路径 + 本项目代码内引用）
KNOWN_MCP_FILES = [
    ".mcp.json",
    ".github/mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".windsurf/mcp.json",
]

#: 代码内启动引用模式（npm/npx/uvx 拉起 MCP server 的硬编码命令）。
#: group(1)=包名（含可选 @scope/ 前缀，名称不含 @）；group(2)=版本/选择器。
_INLINE_BIN = r"(?:[A-Za-z0-9_.\-]+|[\\/][^\s'\"]+|\.\.[\\/][^\s'\"]+)"
INLINE_REF_PATTERNS = [
    re.compile(r"(?:uvx|npx)\s+((?:@[^/\s]+/)?[\w.\-]+)(?:@([^\s'\"]+))?"),
    re.compile(r"npm\s+(?:exec|run)\s+([\w\-./]+)"),
    # 列表形式：["uvx", "windows-mcp", "serve", ...]
    re.compile(r'"(?:uvx|npx)"\s*,\s*"((?:@[^/"]+/)?[\w.\-]+)(?:@([^"\']+))?"'),
]

#: npm/npx 包引用分类（技能 Step 3 分类表）
PINNED_RE = re.compile(r"@\d+\.\d+\.\d+$")          # package@1.2.3
MUTABLE_RE = re.compile(r"@(latest|next|canary)$")    # @latest / @next
RANGE_RE = re.compile(r"@(\^|~|>=|>|<|<=|\*)")        # @^1.2.0 / @~1.2.0 / @*


def classify_reference(pkg: str) -> Tuple[str, str]:
    """按技能分类表返回 (classification, why)。

    - PINNED DIRECT: 版本固定；传递依赖/注册表完整性/安装钩子仍需单独审查
    - HIGH: 裸包名或 @latest，后续解析可能选到不同代码
    - MEDIUM: 范围选择器，允许范围内解析可变化
    - REVIEW: 本地路径/脚本/二进制/未知可执行，版本漂移规则不适用
    """
    if not pkg:
        return "REVIEW", "空引用（需人工确认）"
    if re.match(r"^(\.{1,2})?[\\/]", pkg) or re.match(r"^[A-Za-z]:[\\/]", pkg):
        return "REVIEW", "本地路径/文件引用，版本漂移规则不适用"
    if PINNED_RE.search(pkg):
        return "PINNED DIRECT", "版本固定；传递依赖/注册表完整性/安装钩子仍需审查"
    if MUTABLE_RE.search(pkg):
        return "HIGH", "选择器显式可变，后续解析可选中不同包代码"
    if RANGE_RE.search(pkg):
        return "MEDIUM", "范围选择器，允许范围内解析可变化"
    return "HIGH", "裸包名，后续解析可选中不同包代码"


def _extract_from_config(path: Path) -> List[Dict[str, Any]]:
    """从 .mcp.json 等配置提取 server→command 引用（只读 JSON 文本）。"""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return [{
            "config": str(path), "server": "<parse-error>",
            "reference": "<unreadable>", "classification": "REVIEW",
            "why": "配置文件无法解析（非 JSON/编码/IO 错误），需人工检查",
            "next_step": "人工读原文；不执行其中命令",
        }]
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        return []
    rows: List[Dict[str, Any]] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = str(cfg.get("command", ""))
        args = cfg.get("args", [])
        pkg = cmd
        if args:
            pkg = f"{cmd} {' '.join(str(a) for a in args)}"
        # 仅对 npm/npx/uvx 类引用分类；本地二进制/脚本走 REVIEW
        m = None
        for pat in INLINE_REF_PATTERNS:
            m = pat.search(pkg)
            if m:
                break
        if m:
            cls, why = classify_reference(m.group(1) + (f"@{m.group(2)}" if m.group(2) else ""))
            next_step = (
                "pin 团队实际审查过的确切版本并刻意更新"
                if cls in ("HIGH", "MEDIUM") else "按本地/二进制路径单独审查"
            )
        else:
            cls, why, next_step = "REVIEW", "非 npm/npx/uvx 包引用，漂移规则不适用", "按启动方式单独审查"
        rows.append({
            "config": str(path), "server": str(name),
            "reference": pkg, "classification": cls,
            "why": why, "next_step": next_step,
        })
    return rows


def _extract_inline(root: Path) -> List[Dict[str, Any]]:
    """扫描 scripts/ 下代码内硬编码的 uvx/npx 启动引用（本项目的 wmcp_office 形态）。"""
    rows: List[Dict[str, Any]] = []
    scripts_dir = root / "scripts"
    if not scripts_dir.is_dir():
        return rows
    for py in sorted(scripts_dir.glob("*.py")):
        if py.name == "audit_mcp_drift.py":
            continue  # 自身 docstring 描述该工具，跳过自匹配
        try:
            text = py.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        in_docstring = False
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            # 三引号 docstring 状态机：跳过文档块，只扫真实代码行
            if stripped.startswith(('"""', "'''")):
                # 行内即开即闭（如 docstring 单行形式）不进入状态
                if stripped.count('"""') + stripped.count("'''") >= 2:
                    continue
                in_docstring = not in_docstring
                continue
            if in_docstring:
                if '"""' in stripped or "'''" in stripped:
                    in_docstring = False
                continue
            if stripped.startswith("#"):
                continue
            if "serve" not in line and "mcp" not in line.lower():
                continue
            for pat in INLINE_REF_PATTERNS:
                m = pat.search(line)
                if not m:
                    continue
                pkg = m.group(1) + (f"@{m.group(2)}" if m.group(2) else "")
                cls, why = classify_reference(pkg)
                rows.append({
                    "config": f"{py.relative_to(root)}:{i}",
                    "server": "(inline launch)",
                    "reference": pkg,
                    "classification": cls,
                    "why": why,
                    "next_step": (
                        "pin 团队实际审查过的确切版本并刻意更新"
                        if cls in ("HIGH", "MEDIUM") else "按启动方式单独审查"
                    ),
                })
                break
    return rows


def audit(root: Path) -> Dict[str, Any]:
    """执行静态漂移审计；不执行任何 MCP server。"""
    rows: List[Dict[str, Any]] = []
    for rel in KNOWN_MCP_FILES:
        p = root / rel
        if p.is_file():
            rows.extend(_extract_from_config(p))
    rows.extend(_extract_inline(root))
    counts: Dict[str, int] = {}
    for r in rows:
        counts[r["classification"]] = counts.get(r["classification"], 0) + 1
    return {
        "root": str(root),
        "scanned_configs": [str(root / f) for f in KNOWN_MCP_FILES if (root / f).is_file()],
        "rows": rows,
        "classification_counts": counts,
        "executed_servers": 0,
        "disclaimer": (
            "口径：静态读配置文本，未执行任何 MCP server；漂移分类是复现性/"
            "审查漂移信号，非漏洞/恶意证明；建议 pin 团队实际审查过的确切版本，"
            "不猜版本。"
        ),
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="MCP 配置依赖漂移静态审计（零执行）"
    )
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    ap.add_argument("--output-md", type=Path, default=None)
    args = ap.parse_args(argv)

    report = audit(args.root)
    print(json.dumps(
        {k: v for k, v in report.items() if k != "rows"},
        ensure_ascii=False, indent=2,
    ))
    for r in report["rows"]:
        print(f"  [{r['classification']}] {r['config']} | {r['server']} | {r['reference']}")
    if args.output_md is not None:
        lines = [
            "# MCP 依赖漂移审计报告",
            "",
            f"- 扫描配置：{report['scanned_configs'] or '（无 .mcp.json 族文件）'}",
            f"- 引用总数：{len(report['rows'])}　分类分布：{report['classification_counts']}",
            f"- 执行 MCP server 数：{report['executed_servers']}（零执行）",
            "",
            "| 配置位置 | server | 引用 | 分类 | 原因 | 建议下一步 |",
            "|---|---|---|---|---|---|",
        ]
        for r in report["rows"]:
            lines.append(
                f"| {r['config']} | {r['server']} | `{r['reference']}` | "
                f"{r['classification']} | {r['why']} | {r['next_step']} |"
            )
        lines.append("")
        lines.append("> " + report["disclaimer"])
        args.output_md.parent.mkdir(parents=True, exist_ok=True)
        args.output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"report -> {args.output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
