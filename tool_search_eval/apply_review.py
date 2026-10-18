# 검토 화면(아티팩트)의 표시를 pairs.jsonl 에 되돌린다 — 맞음은 reviewed, 고침은 정답 · 질의를 바꾸고 reviewed, 빼기는 그 줄을 지운다
"""HWAXPortal docs/followups-1017 결정 21(10-18 '검토 화면을 만들어 달라').

표시는 검토 화면의 저장소 `marks/<쌍 id>` 에 쌍마다 하나다 — `{verdict: ok|fix|drop, gold?, query?, memo?, at, by?}`.
Claude 가 ArtifactData `list`(out_dir)로 내려받은 폴더를 이 스크립트에 준다.

  python3 tool_search_eval/apply_review.py --marks <내려받은 폴더>/marks            # 무엇이 바뀌는지만 본다
  python3 tool_search_eval/apply_review.py --marks <내려받은 폴더>/marks --write    # pairs.jsonl 에 쓴다

- 맞음 → `reviewed: true`. 고침 → `gold`(앱키:원래 이름 하나 이상) · `query`(두 글자 이상)를 바꾸고 `reviewed: true`.
  빼기 → 그 줄을 지운다(무엇을 지웠는지는 git 이력이 남긴다). 메모가 있으면 `review_memo` 로 싣는다.
- 평가셋에 없는 id · 모르는 표시 · 꼴이 틀린 고침은 건너뛰고 끝에 센다(말없이 버리지 않는다).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
KEY_RE = re.compile(r"^[^:\s]+:\S+$")


def load_marks(folder: Path) -> dict[str, dict]:
    """`<id>.json` 마다 표시 하나. 내려받은 꼴이 `{id, data, version}` 이면 data 를, 아니면 통째를 표시로 본다."""
    out: dict[str, dict] = {}
    for f in sorted(folder.glob("*.json")):
        doc = json.loads(f.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and isinstance(doc.get("data"), dict) and "verdict" not in doc:
            out[str(doc.get("id") or f.stem)] = doc["data"]
        else:
            out[f.stem] = doc
    return out


def apply(pairs: list[dict], marks: dict[str, dict]) -> tuple[list[dict], dict]:
    """표시를 쌍에 입힌 새 목록과 보고 — 원래 목록은 바꾸지 않는다."""
    rep = {"ok": [], "fix": [], "drop": [], "skipped": []}
    known = {p["id"] for p in pairs}
    for mid in sorted(set(marks) - known):
        rep["skipped"].append((mid, "평가셋에 없는 id"))
    out = []
    for p in pairs:
        m = marks.get(p["id"])
        if not m:
            out.append(p)
            continue
        v = m.get("verdict")
        q = dict(p)
        memo = str(m.get("memo") or "").strip()
        if v == "drop":
            rep["drop"].append((p["id"], p["query"]))
            continue
        if v == "fix":
            gold = m.get("gold")
            query = str(m.get("query") or p["query"]).strip()
            if not isinstance(gold, list) or not gold or not all(isinstance(g, str) and KEY_RE.match(g) for g in gold):
                rep["skipped"].append((p["id"], f"고침의 정답이 '앱키:원래 이름' 목록이 아니다: {gold!r}"))
                out.append(p)
                continue
            if len(query) < 2:
                rep["skipped"].append((p["id"], "고침의 질의가 두 글자 미만"))
                out.append(p)
                continue
            rep["fix"].append((p["id"], p["query"], query, p["gold"], gold))
            q["query"], q["gold"] = query, list(dict.fromkeys(gold))
        elif v == "ok":
            rep["ok"].append(p["id"])
        else:
            rep["skipped"].append((p["id"], f"모르는 표시 {v!r}"))
            out.append(p)
            continue
        q["reviewed"] = True
        if memo:
            q["review_memo"] = memo
        out.append(q)
    return out, rep


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--marks", required=True, help="ArtifactData list(out_dir)로 내려받은 marks 폴더")
    ap.add_argument("--pairs", default=str(HERE / "pairs.jsonl"))
    ap.add_argument("--write", action="store_true", help="주지 않으면 바뀌는 것만 보인다")
    args = ap.parse_args()
    folder = Path(args.marks)
    if not folder.is_dir():
        sys.exit(f"표시 폴더가 없다: {folder} — ArtifactData list(out_dir)로 내려받은 marks 폴더를 준다")
    path = Path(args.pairs)
    pairs = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    marks = load_marks(folder)
    new, rep = apply(pairs, marks)
    print(f"표시 {len(marks)}개 — 맞음 {len(rep['ok'])} · 고침 {len(rep['fix'])} · 빼기 {len(rep['drop'])} · 건너뜀 {len(rep['skipped'])}"
          f" — {len(pairs)}쌍 → {len(new)}쌍")
    for pid, q0, q1, g0, g1 in rep["fix"]:
        print(f"  고침 {pid}: " + (f"질의 {q0!r} → {q1!r} · " if q0 != q1 else "") + f"정답 {g0} → {g1}")
    for pid, q in rep["drop"]:
        print(f"  빼기 {pid}: {q!r}")
    for pid, why in rep["skipped"]:
        print(f"  건너뜀 {pid}: {why}")
    if not args.write:
        print("(--write 를 주지 않아 pairs.jsonl 은 그대로다)")
        return 0
    path.write_text("".join(json.dumps(p, ensure_ascii=False) + "\n" for p in new), encoding="utf-8")
    print(f"썼다 — {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
