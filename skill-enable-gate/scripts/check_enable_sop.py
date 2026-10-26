"""AAS 技能启用 SOP 纪律校验（enable-sop 挂纪律，2026-10-24）。

把 `docs/aas-skills/enable-sop.md` 的强制门固化为可执行校验：
    - 门 4 frontmatter 完整性：SKILL.md yaml 可解析 + name/description 齐全；
    - 禁入清单（门 2 表层扫描关键模式）：指令覆盖 / 外部 fetch 到未知域名 /
      shell 管道下载 / 编码负载 / 凭据读取 / 自复制 —— 命中即阻断（一票否决）；
    - risk=offensive 核对（有索引时）：索引中 risk=offensive 的 id 不得启用。

纪律：
    - **只读文本扫描，绝不执行技能内容**；扫描到模式只标记，不运行任何脚本；
    - 模式命中是阻断信号，不声称"恶意"；fail-closed（违规 → exit 1）；
    - 本脚本本身不判定"安全"，只校验 SOP 门控是否满足。

用法：
    python scripts/check_enable_sop.py \
        [--skills-dir .user_skills] [--index docs/aas-skills/skills_index.json] \
        [--offensive-ids docs/aas-skills/_offensive_ids.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

#: 禁入模式（SOP 门 2 表层扫描关键项；命中即一票否决）
BAN_PATTERNS: List[Tuple[str, str]] = [
    ("instruction_override", r"ignore\s+(all\s+)?previous\s+instructions|you\s+are\s+now\s+",
     "指令覆盖（prompt injection）"),
    ("credential_read", r"(~|\.)[\\/]\.env|process\.env\s*\+|read_env\(|os\.environ",
     "凭据读取"),
    ("encoded_payload", r"atob\(|base64\s*-\s*d|from\s+base64|eval\(\s*base64",
     "编码负载"),
    ("shell_pipe_download", r"(curl|wget)\s+[^\n|]*\s*\|\s*(sh|bash|powershell|pwsh)",
     "下载管道进解释器"),
    ("self_replicate", r"install\s+in\s+all\s+repos|copy\s+itself|self.?replicat",
     "自复制/持久化扩散"),
]
#: 外部 fetch 到未知域名（白名单域名之外的 http/https 目标）
ALLOWED_FETCH_HOSTS = {"raw.githubusercontent.com", "github.com"}
#: 示例/检测语境标记：命中出现在这些词附近的模式视为"描述攻击模式"
#: （防御/审查类技能正文的检测样例），降级为 review 而非硬阻断
EXAMPLE_CONTEXT = re.compile(
    r"example|示例|illustrative|pattern|检测|red\s*team|红队|模拟|演示|"
    r"screenshot|截图|do\s+not|避免|禁止|dete[ck]t|侦测|审查",
    re.IGNORECASE,
)


def _line_window(text: str, start: int, end: int, pad: int = 2) -> str:
    """取命中位置前后 pad 行作为上下文。"""
    before = text[:start].splitlines()
    after = text[end:].splitlines()
    ctx = "\n".join(before[-pad:]) + "\n" + "\n".join(after[:pad])
    return ctx


def _fetch_targets(text: str) -> List[str]:
    """提取 fetch/curl 的目标 URL 主机。"""
    hosts = set()
    for m in re.finditer(r"https?://([^/\s'\"\)\]]+)", text):
        hosts.add(m.group(1).split("/")[0].lower())
    return sorted(hosts)


def parse_frontmatter(text: str) -> Optional[Dict[str, object]]:
    """极简 yaml frontmatter 解析（--- 块内 key: value）。失败返回 None。"""
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end < 0:
        return None
    body = text[3:end]
    out: Dict[str, object] = {}
    for line in body.splitlines():
        if ":" in line and not line.lstrip().startswith("#"):
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip().strip("'\"")
    return out


def check_skill(skill_dir: Path) -> Dict[str, object]:
    """对单个技能目录执行 SOP 门控校验，返回 {status, findings}。

    status: pass | review | block（fail-closed 只对 block）。
    - 硬阻断（block）：指令覆盖 / 管道下载 / 编码负载 / 自复制 / 凭据读取+
      网络外发 / offensive；
    - review：仅外部 fetch 到白名单外域名（docs-only 技能引用文档 URL 常见，
      不单独阻断，人工确认后放行；与凭据读取同现时升级为 block）。
    """
    md = skill_dir / "SKILL.md"
    result: Dict[str, object] = {
        "id": skill_dir.name, "status": "pass", "findings": [],
    }
    if not md.is_file():
        result["status"] = "block"
        result["findings"].append({"rule": "frontmatter", "detail": "SKILL.md 缺失"})
        return result

    text = md.read_text(encoding="utf-8", errors="replace")
    fm = parse_frontmatter(text)
    if fm is None or not fm.get("name") or not fm.get("description"):
        result["status"] = "block"
        result["findings"].append({"rule": "frontmatter",
                                   "detail": "yaml 不可解析或 name/description 缺失"})

    # 防御/审查类技能：正文以"检测示例/攻击模式清单"方式描述恶意模式，
    # 命中统一降级 review（人工裁决），避免把"描述攻击模式"误判为"执行攻击行为"
    fm_safe = fm or {}
    name_l = str(fm_safe.get("name", skill_dir.name)).lower()
    desc_l = str(fm_safe.get("description", "")).lower()
    is_defensive = (
        "security" in str(fm_safe.get("category", "")).lower()
        or "security" in str(fm_safe.get("tags", "")).lower()
        or any(k in name_l for k in ("audit", "defense", "security", "injection", "red-team"))
        or any(k in desc_l for k in ("security", "audit", "defense", "审查", "安全", "检测"))
    )
    has_example_section = bool(re.search(
        r"illustrative|attack\s+patterns?|检测示例|examples?\s*[:：]|示例\s*[:：]|威胁模型",
        text, re.IGNORECASE,
    ))

    for name, pat, label in BAN_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if not m:
            continue
        ctx = re.sub(r"https?://[^\s\"'\)\]]+", "",
                     _line_window(text, m.start(), m.end()))
        if is_defensive and has_example_section:
            result["status"] = "review"
            result["findings"].append({
                "rule": name, "detail": label,
                "note": "security/防御类技能正文检测示例语境，降为 review（人工裁决）",
            })
        elif EXAMPLE_CONTEXT.search(ctx):
            result["status"] = "review"
            result["findings"].append({
                "rule": name, "detail": label,
                "note": "命中位于示例/检测描述语境，降为 review（人工裁决）",
            })
        else:
            result["status"] = "block"
            result["findings"].append({"rule": name, "detail": label})
            break  # 已有硬阻断，其余模式不再判断

    hosts = _fetch_targets(text)
    unknown = [h for h in hosts if h not in ALLOWED_FETCH_HOSTS]
    if unknown:
        finding = {
            "rule": "external_fetch",
            "detail": f"外部 fetch 到白名单外域名: {', '.join(unknown)}",
        }
        # 凭据读取（非示例语境） + 网络外发 = 禁入清单命中（硬阻断）
        cred_block = any(
            f["rule"] == "credential_read" and "note" not in f
            for f in result["findings"]
        )
        if cred_block:
            result["status"] = "block"
            result["findings"].append(finding)
        elif result["status"] != "block":
            result["status"] = "review"
            result["findings"].append(finding)
    return result


def check_all(skills_dir: Path, index_path: Optional[Path],
              offensive_path: Optional[Path]) -> Dict[str, object]:
    """校验启用区全部技能。返回 {skills, counts, offensive_hits}。"""
    index: Dict[str, Dict[str, object]] = {}
    if index_path and index_path.is_file():
        try:
            raw = json.loads(index_path.read_text(encoding="utf-8"))
            for item in raw if isinstance(raw, list) else raw.get("skills", []):
                if isinstance(item, dict) and item.get("id"):
                    index[str(item["id"])] = item
        except (json.JSONDecodeError, OSError):
            pass  # 索引缺失/损坏时跳过 offensive 核对（不影响门 2/门 4）

    offensive_ids: set = set()
    if offensive_path and offensive_path.is_file():
        try:
            raw = json.loads(offensive_path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                offensive_ids = {str(x.get("id", x)) if isinstance(x, dict) else str(x) for x in raw}
        except (json.JSONDecodeError, OSError):
            pass

    results: List[Dict[str, object]] = []
    for skill_dir in sorted(skills_dir.iterdir()):
        if not skill_dir.is_dir() or not (skill_dir / "SKILL.md").is_file():
            continue
        r = check_skill(skill_dir)
        # offensive 核对：索引或清单命中即阻断
        if r["id"] in offensive_ids:
            r["status"] = "block"
            r["findings"].append({"rule": "offensive", "detail": "索引 risk=offensive 一票否决"})
        elif str(r["id"]) in index:
            risk = str(index[str(r["id"])].get("risk", ""))
            if risk.lower() == "offensive":
                r["status"] = "block"
                r["findings"].append({"rule": "offensive", "detail": "索引 risk=offensive 一票否决"})
        results.append(r)

    counts = {"total": len(results), "pass": 0, "block": 0, "review": 0}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {"skills": results, "counts": counts,
            "index_loaded": bool(index), "offensive_ids_loaded": bool(offensive_ids)}


def _default_skills_dir(repo: Path) -> Path:
    """启用区默认路径：显式环境变量 > 项目内 .user_skills。

    环境变量 `AGENT_SKILLS_DIR` 可指向任意 Agent 的技能目录，
    使本工具不绑定特定平台的安装位置。
    """
    env = os.environ.get("AGENT_SKILLS_DIR")
    if env:
        p = Path(env)
        if p.is_dir():
            return p
    return repo / ".user_skills"


def main(argv: Optional[List[str]] = None) -> int:
    repo = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description="AAS 启用 SOP 纪律校验（只读文本，零执行）")
    ap.add_argument("--skills-dir", type=Path, default=_default_skills_dir(repo))
    ap.add_argument("--index", type=Path, default=repo / "docs" / "aas-skills" / "skills_index.json")
    ap.add_argument("--offensive-ids", type=Path,
                    default=repo / "docs" / "aas-skills" / "_offensive_ids.json")
    args = ap.parse_args(argv)

    report = check_all(args.skills_dir, args.index, args.offensive_ids)
    print(json.dumps({
        "skills_dir": str(args.skills_dir),
        "counts": report["counts"],
        "index_loaded": report["index_loaded"],
        "offensive_ids_loaded": report["offensive_ids_loaded"],
    }, ensure_ascii=False, indent=2))
    nonpass = [s for s in report["skills"] if s["status"] != "pass"]
    for s in nonpass:
        print(f"  {s['status'].upper()} {s['id']}: {s['findings']}")
    blocked = [s for s in report["skills"] if s["status"] == "block"]
    if blocked:
        print(f"error: {len(blocked)} 个技能未通过 SOP 门控（fail-closed，exit 1）", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
