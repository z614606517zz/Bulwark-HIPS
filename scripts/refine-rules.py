#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把行为规则包与代码内置规则(DefaultRules.cpp)对齐,产出精简包。

全量导入会产生大量重复,并静默改变产品行为:内置规则对 certutil 下载 / bitsadmin / -enc /
DownloadString 等有合法运维用途的手法判 Ask,生成的规则却是 Block + hardOverride,会把询问变成拦截。

处理策略:
  * 内置已覆盖且裁决相同  -> 丢弃(纯冗余)
  * 内置判 Ask 而本包判 Block -> 降级为 Ask 并去掉 hardOverride,尊重内置意图
  * 内置未覆盖            -> 保留(这才是真正补上的检测盲区)
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES = ROOT / "cpp" / "shared" / "src" / "engine" / "DefaultRules.cpp"
ACT_STR = {0: "Allow", 1: "Block", 2: "Ask"}
BLOCK, ASK = 1, 2
RANK = {1: 2, 2: 1, 0: 0}


def parse_builtin(src: str):
    """抽取 helper(list, "pattern", VerdictAction::X, "note") 形式的内置规则。"""
    out = {}
    for m in re.finditer(r'\b\w+\s*\(\s*list\s*,\s*"((?:[^"\\]|\\.)*)"\s*,\s*VerdictAction::(\w+)', src):
        pat = m.group(1).replace("\\\\", "\\").lower()
        act = {"Allow": 0, "Block": 1, "Ask": 2}.get(m.group(2))
        if act is None:
            continue
        if pat not in out or RANK[act] > RANK[out[pat]]:
            out[pat] = act
    return out


def tokens(pat: str):
    return [t for t in re.split(r"\*+", (pat or "").replace("\\\\", "\\").lower()) if t]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", type=Path,
                    default=ROOT / "scripts" / "rules-data" / "bulwark-rules-behavior.json")
    ap.add_argument("--out", type=Path,
                    default=ROOT / "scripts" / "rules-data" / "bulwark-rules-behavior-refined.json")
    args = ap.parse_args()

    builtin = parse_builtin(DEFAULT_RULES.read_text(encoding="utf-8", errors="replace"))
    pack = json.loads(args.pack.read_text(encoding="utf-8"))
    print("内置规则: %d 条   输入包: %d 条" % (len(builtin), len(pack)))

    kept, dropped, downgraded = [], [], []
    for r in pack:
        mine = (r["commandLinePattern"] or r["targetPattern"] or r["actorPattern"] or "").lower()
        mt = tokens(mine)
        covering = None
        for bp, ba in builtin.items():
            bt = tokens(bp)
            if bt and all(t in mine for t in bt):
                if covering is None or RANK[ba] > RANK[covering[1]]:
                    covering = (bp, ba)

        if covering is None:
            kept.append(r)
            continue

        bp, ba = covering
        if ba == r["action"]:
            dropped.append((r, bp, ba))
        elif r["action"] == BLOCK and ba == ASK:
            r = dict(r)
            r["action"] = ASK
            r["hardOverride"] = False
            r["note"] = r["note"] + " · 已按内置规则意图对齐为询问(内置: Ask)"
            downgraded.append((r, bp))
            kept.append(r)
        else:
            kept.append(r)

    print()
    print("丢弃(与内置重复) : %d" % len(dropped))
    print("降级(尊重内置意图) : %d" % len(downgraded))
    print("保留             : %d" % len(kept))

    if downgraded:
        print()
        print("已降级为 Ask 的规则:")
        for r, bp in downgraded:
            print("   - %s" % r["note"][:96])
            print("     (内置 %s 判 Ask)" % bp[:60])

    args.out.write_text(json.dumps(kept, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    b = sum(1 for r in kept if r["action"] == BLOCK)
    a = sum(1 for r in kept if r["action"] == ASK)
    h = sum(1 for r in kept if r["hardOverride"])
    print()
    print("输出: %s" % args.out)
    print("精简包: %d 条 (Block=%d Ask=%d hardOverride=%d)" % (len(kept), b, a, h))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
