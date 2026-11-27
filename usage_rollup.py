# 게이트웨이 감사 기록(audit.jsonl)을 KST 날마다 접어 두고 기간으로 내는 이용 통계 창구의 셈(HWAXPortal docs/ops-dashboard M2 · OD-12)
"""포털 관리자 '이용 통계' 가 날마다 접어 가는 원천이다 — 포털 컨테이너는 이 원장을 열 수 없어 공유 비밀 창구(/usage-rollup)로 묻는다.

  · 감사 원장은 덧붙이기만 하고 돌리지 않는다(무기한). 물을 때마다 훑지 않게 **읽은 자리**(바이트)를 적어 두고 그 뒤의 줄만 접는다. 원장이
    줄었거나 머리가 달라졌으면(잘림 · 바꿔치기) 접은 표를 비우고 처음부터 다시 접는다. 줄바꿈이 아직 없는 끝 줄은 다음에 읽는다.
  · 접은 표는 sqlite 하나다 — 셈과 읽은 자리를 한 트랜잭션으로 적는다(중간에 죽어도 두 번 세지 않는다). 파일은 0600 이다(사람별 줄이 든다).
  · 한 번에 접는 시간에 기한이 있다(BUDGET_S). 넘기면 접은 데까지만 내고 complete=false 와 scanned_through(파일 차례로 마지막에 접은 줄의
    시각)로 말한다 — 다음 물음이 잇는다. 덜 접은 답의 수는 모자랄 수 있다(포털은 complete 인 답만 접어 둔다).
  · 날은 KST 로 가른다(원장의 ts 는 UTC). 사람은 소문자 메일이다.
  · 도구 이름은 원래 이름으로 접는다(E-2 — 겹침 접두 · 호출 별칭). 떠 있는 경로표(resolve)가 아는 이름은 그 답을, 모르는 이름은 접두 규칙
    (백엔드 키에서 하이픈을 뺀 것 + '_')을 쓴다. 주소가 든 이름(rest_call · resources/read)은 주소를 뗀다. 모르는 도구(호출자가 적은 글자)는
    '(unknown)' 한 칸이다 — 요청이 정한 글자를 통계에 싣지 않는다.
  · 뺄 계정(exclude)은 물을 때 건다 — 접은 표는 호출자까지 갈라 두어 호출 수 · 지연 · 사람 줄 모두에서 빠진다.
  · 호출자가 빈 줄의 `audit_for`(그 호출이 누구의 일에서 나왔나 — 에이전트 서버가 서비스 자격 호출에 실은 감사 전용 머리, 검증하지 않은 주장)는
    따로 갈라 둔다 — 사람 줄은 actors_for · actor_tools_for 로 따로 내고, 이름 없는 줄(anon)에서는 뺀다. 뺄 계정은 이 칸에도 건다(OD-52).
  · 싣지 않는 것 — IP · 오류 글 · 메모 · 대화 열쇠(corr) · 요청 ID. 실패는 앱 쪽 · 관문 쪽 둘로만 가른다.

이 모듈은 표준 라이브러리만 읽는다(게이트웨이 모듈을 읽지 않는다 — 시험이 따로 돈다).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from contextlib import closing
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

CONTRACT = 1
SCHEMA_VERSION = "2"            # 접은 표의 꼴 — 다르면 표를 버리고 원장 처음부터 다시 접는다(원장에서 다시 지을 수 있는 셈이라 잃는 것이 없다)
KST = timezone(timedelta(hours=9))
MAX_RANGE_DAYS = 400            # 포털 이용 통계의 가장 긴 기간(HWAXPortal backend/app/usage_stats.py MAX_DAYS)
DEFAULT_RANGE_DAYS = 3          # 비우면 오늘까지 사흘 — 포털이 날마다 다시 접는 창
BUDGET_S = 20.0                 # 한 물음이 원장을 접는 데 쓰는 시간의 위쪽 — 넘기면 complete=false
CHUNK_LINES = 20000             # 이만큼 접을 때마다 적는다(읽은 자리와 함께)
BIG_CHARS = 100_000             # 큰 응답 — 돌려준 글자 수가 이 이상(Claude Code 가 MCP 결과를 파일로 빼거나 자르는 문턱과 같은 자리)
EXCLUDE_MAX = 200
ACTOR_TOOLS_MAX = 5
# 지연 칸의 위 끝(ms) — 마지막 칸은 상한이 없다. 분위수는 칸 안 선형 보간 어림이다.
LAT_LE_MS = (5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000, 120000, 300000, 600000)
# 상태 묻기 도구(원래 이름) — 호출 수를 부풀리므로 따로 표시한다. 에이전트 서버 status_wait.BUILTIN 과 심의 상태 도구, 그리고 '_status' 로 끝나는 이름.
STATUS_TOOLS = frozenset(("get_task", "job_status", "get_job_status", "get_job", "docforge_status", "doe_status", "study_get",
                          "deliberate_status", "deliberate_batch_status"))
STATUS_SUFFIX = "_status"
# 관문 쪽 실패 — 게이트웨이가 백엔드에 보내기 전에 막았거나(권한 · 울타리 · 모르는 도구) 사람 자격을 받지 못했다. 그 밖의 실패는 앱 쪽이다.
GATE_ERRORS = ("forbidden", "unknown tool", "read-only", "panel-denied", "invoke-denied", "service-denied", "backend removed",
               "unauthorized", "method not allowed", "bad request", "per-user", "assertion")
FIELDS = ("caller", "via", "ip", "chars", "audit_for")       # 처음 나온 날을 싣는 칸(그 전 날의 그 칸은 '없음' 이 아니라 '기록 전' 이다)

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS calls (day TEXT NOT NULL, backend TEXT NOT NULL, tool TEXT NOT NULL, via TEXT NOT NULL,"
    " outcome TEXT NOT NULL, caller TEXT NOT NULL, for_user TEXT NOT NULL, n INTEGER NOT NULL, chars INTEGER NOT NULL,"
    " chars_max INTEGER NOT NULL, cache INTEGER NOT NULL, big INTEGER NOT NULL,"
    " PRIMARY KEY (day, backend, tool, via, outcome, caller, for_user)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS lat (day TEXT NOT NULL, backend TEXT NOT NULL, tool TEXT NOT NULL, via TEXT NOT NULL,"
    " caller TEXT NOT NULL, for_user TEXT NOT NULL, le INTEGER NOT NULL, n INTEGER NOT NULL,"
    " PRIMARY KEY (day, backend, tool, via, caller, for_user, le)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS auth (day TEXT NOT NULL, reason TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (day, reason)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL) WITHOUT ROWID",
)
_HEAD_BYTES = 256               # 원장 머리의 지문 — 덧붙이기만 하는 파일이라 머리는 바뀌지 않는다
_LOCK = threading.Lock()        # 접기는 한 번에 하나(같은 프로세스 안) — 둘이 같은 자리에서 읽어 두 번 세지 않게
_NAME_OK = re.compile(r"[A-Za-z0-9_.:/ -]{1,96}")
_HTTP_HEADS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "OTHER")
_HTTP_NAME = re.compile(r"[A-Z]{3,7} /[a-z-]{1,20}")
_VIA_OK = re.compile(r"[a-z-]{1,20}")
_REASON_OK = re.compile(r"[a-z-]{1,40}")
_AUTH_TOOL = re.compile(r"[A-Z]{3,7} /mcp/?")
_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
_FOR_OK = re.compile(r"[^@\s,;]{1,100}@[^@\s,;]{1,100}")      # 게이트웨이가 audit_for 에 적는 꼴(gateway._AUDIT_FOR_RE)


def kst_day(ts) -> str | None:
    """감사 줄의 ts(ISO) → KST 날. 시간대가 없으면 UTC 로 읽는다(게이트웨이는 UTC 로 적는다)."""
    try:
        t = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(KST).date().isoformat()


def _kst_iso(ts) -> str | None:
    try:
        t = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(KST).isoformat(timespec="seconds")


def is_status(tool: str) -> bool:
    return tool in STATUS_TOOLS or tool.endswith(STATUS_SUFFIX)


def fold_tool(tool, backend, resolve=None) -> str:
    """감사 줄의 도구 이름 → 통계에 쓰는 이름. 주소를 떼고, 접두 · 별칭을 원래 이름으로 접고, 꼴이 다른 글자는 '(other)' 다."""
    name = str(tool or "")
    if " " in name:
        head, _, rest = name.partition(" ")
        if head == "rest_call":                                 # rest_call GET /api/… → rest_call GET
            method = rest.split(" ", 1)[0].upper()
            return f"rest_call {method}" if method in _HTTP_HEADS else "(other)"
        if head == "resources/read":                            # resources/read ui://… → resources/read
            return head
        return name if head in _HTTP_HEADS and _HTTP_NAME.fullmatch(name) else "(other)"      # GET /fig · GET /kit — 정해진 창구 이름
    if not _NAME_OK.fullmatch(name):
        return "(other)"
    hit = resolve(name) if resolve is not None else None
    if hit:
        orig = str(hit[1] or "")
        return orig if _NAME_OK.fullmatch(orig) and " " not in orig else "(other)"
    p = str(backend or "").replace("-", "") + "_"
    return name[len(p):] if len(p) > 1 and name.startswith(p) and len(name) > len(p) else name


def _outcome(rec: dict) -> str:
    if rec.get("ok") is True:
        return "ok"
    err = str(rec.get("error") or "")
    return "gate" if rec.get("mode") == "refused" or err.startswith(GATE_ERRORS) else "app"


def _le(ms) -> int:
    for i, top in enumerate(LAT_LE_MS):
        if ms <= top:
            return i
    return len(LAT_LE_MS)


def quantile(counts: list, q: float):
    """칸마다의 수 → 분위수(ms) 어림 — 칸 안 선형 보간. 표본이 없으면 None, 마지막 칸(상한 없음)은 그 칸의 아래 끝이다."""
    total = sum(counts)
    if total <= 0:
        return None
    target, seen = q * total, 0
    for i, n in enumerate(counts):
        if n <= 0:
            continue
        if seen + n >= target:
            if i >= len(LAT_LE_MS):
                return LAT_LE_MS[-1]
            lo = LAT_LE_MS[i - 1] if i else 0
            return round(lo + (LAT_LE_MS[i] - lo) * max(0.0, target - seen) / n, 1)
        seen += n
    return LAT_LE_MS[-1]


class _Fold:
    """접는 동안의 셈(한 묶음) — 끝에 한 트랜잭션으로 표에 더한다."""

    def __init__(self) -> None:
        self.calls: dict[tuple, list] = {}
        self.lat: dict[tuple, int] = {}
        self.auth: dict[tuple, int] = {}
        self.fields: dict[str, str] = {}
        self.lines = self.bad = 0
        self.first = self.last = self.tail_ts = None

    def add(self, raw: bytes, resolve) -> None:
        if not raw.strip():
            return
        self.lines += 1
        try:
            rec = json.loads(raw)
        except ValueError:
            rec = None
        day = kst_day(rec.get("ts")) if isinstance(rec, dict) else None
        if day is None:
            self.bad += 1
            return
        self.first = day if self.first is None or day < self.first else self.first
        self.last = day if self.last is None or day > self.last else self.last
        self.tail_ts = rec.get("ts")                # 파일 차례로 마지막에 접은 줄의 시각(가장 늦은 날의 줄이 아니다 — 시각이 뒤섞인 줄이 있어도 읽은 자리를 말한다)
        for k in FIELDS:
            if rec.get(k) not in (None, "") and (k not in self.fields or day < self.fields[k]):
                self.fields[k] = day
        backend, err = rec.get("backend"), str(rec.get("error") or "")
        if backend is None and err.startswith("unauthorized: ") and _AUTH_TOOL.fullmatch(str(rec.get("tool") or "")):
            reason = err[len("unauthorized: "):]
            key = (day, reason if _REASON_OK.fullmatch(reason) else "other")
            self.auth[key] = self.auth.get(key, 0) + 1
            return
        if backend is None and err == "unknown tool":
            bk, tool = "", "(unknown)"
        else:
            bk = str(backend or "")
            bk = bk if _NAME_OK.fullmatch(bk) or not bk else "(other)"
            tool = fold_tool(rec.get("tool"), backend, resolve)
        via = str(rec.get("via") or "")
        via = via if _VIA_OK.fullmatch(via) else ""
        caller = str(rec.get("caller") or "").strip().lower()[:200]
        for_user = "" if caller else str(rec.get("audit_for") or "").strip().lower()[:200]
        for_user = for_user if _FOR_OK.fullmatch(for_user) else ""
        outcome = _outcome(rec)
        chars = rec.get("chars")
        chars = chars if isinstance(chars, int) and not isinstance(chars, bool) and chars >= 0 else 0
        cached = "cache-hit" in str(rec.get("note") or "").split("+")
        row = self.calls.setdefault((day, bk, tool, via, outcome, caller, for_user), [0, 0, 0, 0, 0])
        row[0] += 1
        row[1] += chars
        row[2] = max(row[2], chars)
        row[3] += int(cached)
        row[4] += int(chars >= BIG_CHARS)
        ms = rec.get("ms")
        if outcome == "ok" and not cached and isinstance(ms, (int, float)) and not isinstance(ms, bool) and ms >= 0:
            key = (day, bk, tool, via, caller, for_user, _le(ms))
            self.lat[key] = self.lat.get(key, 0) + 1


def _open(path) -> sqlite3.Connection:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        os.close(os.open(p, os.O_WRONLY | os.O_CREAT, 0o600))       # 사람별 줄이 든다 — 처음부터 주인만
    conn = sqlite3.connect(str(p), timeout=30.0, isolation_level=None)
    conn.execute(_SCHEMA[-1])                          # meta 먼저 — 꼴 판을 본다
    got = conn.execute("SELECT v FROM meta WHERE k = 'schema'").fetchone()
    if (got[0] if got else None) != SCHEMA_VERSION:
        # 옛 꼴(또는 판 표지가 없는 첫 판)이면 표를 버리고 처음부터 다시 접는다 — 감사 원장은 그대로라 잃는 것이 없다.
        conn.execute("BEGIN IMMEDIATE")
        try:
            for t in ("calls", "lat", "auth", "meta"):
                conn.execute(f"DROP TABLE IF EXISTS {t}")  # noqa: S608 — 표 이름은 이 파일의 고정 글자
            for ddl in _SCHEMA:
                conn.execute(ddl)
            conn.execute("INSERT INTO meta VALUES ('schema', ?)", (SCHEMA_VERSION,))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    for ddl in _SCHEMA:
        conn.execute(ddl)
    return conn


def _meta(conn: sqlite3.Connection) -> dict:
    return dict(conn.execute("SELECT k, v FROM meta").fetchall())


def _head_of(f, n: int) -> str:
    f.seek(0)
    return hashlib.sha1(f.read(n)).hexdigest()


def _commit(conn: sqlite3.Connection, fold: _Fold, meta: dict, *, wipe: bool, offset: int, head_n: int, head: str) -> dict:
    """한 묶음의 셈과 읽은 자리를 한 트랜잭션으로 — 도중에 죽으면 둘 다 없던 일이 된다."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        if wipe:
            for t in ("calls", "lat", "auth"):
                conn.execute(f"DELETE FROM {t}")  # noqa: S608 — 표 이름은 이 파일의 고정 글자
            conn.execute("DELETE FROM meta WHERE k != 'schema'")
            meta = {"schema": SCHEMA_VERSION}
        conn.executemany(
            "INSERT INTO calls VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (day, backend, tool, via, outcome, caller, for_user) DO UPDATE SET"
            " n = n + excluded.n, chars = chars + excluded.chars, chars_max = MAX(chars_max, excluded.chars_max),"
            " cache = cache + excluded.cache, big = big + excluded.big", [(*k, *v) for k, v in fold.calls.items()])
        conn.executemany("INSERT INTO lat VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (day, backend, tool, via, caller, for_user, le) DO UPDATE SET"
                         " n = n + excluded.n", [(*k, v) for k, v in fold.lat.items()])
        conn.executemany("INSERT INTO auth VALUES (?, ?, ?) ON CONFLICT (day, reason) DO UPDATE SET n = n + excluded.n",
                         [(*k, v) for k, v in fold.auth.items()])
        new = dict(meta)
        new.update(offset=str(offset), head_n=str(head_n), head=head,
                   lines=str(int(meta.get("lines") or 0) + fold.lines), bad=str(int(meta.get("bad") or 0) + fold.bad))
        if fold.first and (not meta.get("first_day") or fold.first < meta["first_day"]):
            new["first_day"] = fold.first
        if fold.last and (not meta.get("last_day") or fold.last > meta["last_day"]):
            new["last_day"] = fold.last
        if fold.tail_ts:
            new["tail_ts"] = str(fold.tail_ts)
        for k, d in fold.fields.items():
            if not meta.get(f"field:{k}") or d < meta[f"field:{k}"]:
                new[f"field:{k}"] = d
        conn.executemany("INSERT OR REPLACE INTO meta VALUES (?, ?)", list(new.items()))
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return new


def catch_up(db_path, audit_path, *, resolve=None, budget_s: float = BUDGET_S) -> bool:
    """읽은 자리 뒤의 감사 줄을 접는다 → 원장 끝까지 접었나. 원장이 없으면 접을 것이 없다(참 — 만들지 않는다)."""
    with _LOCK, closing(_open(db_path)) as conn:
        try:
            f = open(audit_path, "rb")
        except FileNotFoundError:
            return True
        with f:
            meta = _meta(conn)
            size = os.fstat(f.fileno()).st_size
            offset, head_n = int(meta.get("offset") or 0), int(meta.get("head_n") or 0)
            wipe = bool(meta) and (size < offset or _head_of(f, head_n) != meta.get("head"))
            if wipe:
                offset = 0
            deadline = time.monotonic() + budget_s
            f.seek(offset)
            while True:
                fold, n = _Fold(), 0
                for raw in f:
                    if not raw.endswith(b"\n"):
                        break                       # 덜 쓰인 끝 줄 — 줄바꿈이 온 뒤에 읽는다
                    offset += len(raw)
                    fold.add(raw, resolve)
                    n += 1
                    if n >= CHUNK_LINES:
                        break
                if n or wipe or not meta:
                    hn = min(_HEAD_BYTES, offset)
                    head = _head_of(f, hn)
                    f.seek(offset)
                    meta = _commit(conn, fold, meta, wipe=wipe, offset=offset, head_n=hn, head=head)
                    wipe = False
                if n < CHUNK_LINES:
                    return True
                if time.monotonic() >= deadline:
                    return False


def _day_of(v, what: str) -> date:
    if not isinstance(v, str) or not _DAY.fullmatch(v):
        raise ValueError(f"{what} 는 YYYY-MM-DD(KST 날)다")
    try:
        return date.fromisoformat(v)
    except ValueError as exc:
        raise ValueError(f"{what} 는 YYYY-MM-DD(KST 날)다") from exc


def _names(v, what: str, limit: int) -> list[str]:
    if v is None:
        return []
    if not isinstance(v, list) or len(v) > limit or not all(isinstance(x, str) for x in v):
        raise ValueError(f"{what} 는 글자 목록이다({limit}개까지)")
    return sorted({x.strip() for x in v if x.strip()})


def params(raw: dict, today: str | None = None) -> dict:
    """물음의 칸을 읽는다 — 틀린 꼴은 ValueError(창구가 400 으로 답한다). 기간은 조용히 줄이지 않는다."""
    end = _day_of(raw["until"], "until") if raw.get("until") is not None else (
        date.fromisoformat(today) if today else datetime.now(KST).date())
    start = _day_of(raw["since"], "since") if raw.get("since") is not None else end - timedelta(days=DEFAULT_RANGE_DAYS - 1)
    if start > end:
        raise ValueError("since 가 until 보다 뒤다")
    if (end - start).days + 1 > MAX_RANGE_DAYS:
        raise ValueError(f"기간은 {MAX_RANGE_DAYS}일까지다")
    return {"since": start.isoformat(), "until": end.isoformat(),
            "exclude": [x.lower() for x in _names(raw.get("exclude"), "exclude", EXCLUDE_MAX)],
            "actor_tools": _names(raw.get("actor_tools"), "actor_tools", ACTOR_TOOLS_MAX)}


def query(db_path, p: dict) -> dict:
    """접은 표에서 기간의 답을 짓는다(params 가 읽은 칸으로)."""
    span = (p["since"], p["until"])
    excluded = len(p["exclude"])
    marks = ",".join("?" * excluded)
    not_ex = f" AND caller NOT IN ({marks}) AND for_user NOT IN ({marks})" if excluded else ""
    ex = [*p["exclude"], *p["exclude"]]                # 두 칸 모두에 건다 — 뺄 계정의 일에서 나온 엔진 호출도 뺀다
    with closing(_open(db_path)) as conn:
        meta = _meta(conn)
        rows: dict[tuple, dict] = {}
        for day, bk, tool, via, outcome, n, chars, cmax, cache, big in conn.execute(
                "SELECT day, backend, tool, via, outcome, SUM(n), SUM(chars), MAX(chars_max), SUM(cache), SUM(big) FROM calls"
                f" WHERE day BETWEEN ? AND ?{not_ex} GROUP BY day, backend, tool, via, outcome", (*span, *ex)):
            r = rows.setdefault((day, bk, tool, via), {
                "day": day, "backend": bk, "tool": tool, "via": via, "status": is_status(tool), "calls": 0, "errors_app": 0,
                "errors_gate": 0, "cache": 0, "big": 0, "chars": 0, "chars_max": 0, "lat": [0] * (len(LAT_LE_MS) + 1)})
            r["calls"] += n
            r["chars"] += chars
            r["chars_max"] = max(r["chars_max"], cmax)
            r["cache"] += cache
            r["big"] += big
            if outcome != "ok":
                r["errors_app" if outcome == "app" else "errors_gate"] += n
        for day, bk, tool, via, le, n in conn.execute(
                f"SELECT day, backend, tool, via, le, SUM(n) FROM lat WHERE day BETWEEN ? AND ?{not_ex}"
                " GROUP BY day, backend, tool, via, le", (*span, *ex)):
            if (day, bk, tool, via) in rows and 0 <= le <= len(LAT_LE_MS):
                rows[(day, bk, tool, via)]["lat"][le] += n
        calls = []
        for key in sorted(rows):
            r = rows[key]
            calls.append({**r, "ms_p50": quantile(r["lat"], 0.5), "ms_p95": quantile(r["lat"], 0.95)})
        actors = [{"day": d, "caller": c, "via": v, "n": n} for d, c, v, n in conn.execute(
            f"SELECT day, caller, via, SUM(n) FROM calls WHERE day BETWEEN ? AND ? AND caller != ''{not_ex}"
            " GROUP BY day, caller, via ORDER BY day, caller, via", (*span, *ex))]
        # 호출자가 비었지만 누구의 일에서 나왔는지 적힌 줄(audit_for — 검증하지 않은 주장)은 따로 낸다 — 이름 없는 줄(anon)에 들지 않는다.
        actors_for = [{"day": d, "user": u, "via": v, "n": n} for d, u, v, n in conn.execute(
            f"SELECT day, for_user, via, SUM(n) FROM calls WHERE day BETWEEN ? AND ? AND caller = '' AND for_user != ''{not_ex}"
            " GROUP BY day, for_user, via ORDER BY day, for_user, via", (*span, *ex))]
        anon = [{"day": d, "via": v, "n": n} for d, v, n in conn.execute(
            "SELECT day, via, SUM(n) FROM calls WHERE day BETWEEN ? AND ? AND caller = '' AND for_user = ''"
            " GROUP BY day, via ORDER BY day, via", span)]
        tools = p["actor_tools"]
        tmarks = ",".join("?" * len(tools))
        actor_tools = [] if not tools else [{"day": d, "caller": c, "tool": t, "n": n} for d, c, t, n in conn.execute(
            "SELECT day, caller, tool, SUM(n) FROM calls WHERE day BETWEEN ? AND ? AND caller != '' AND outcome = 'ok'"
            f" AND tool IN ({tmarks}){not_ex} GROUP BY day, caller, tool ORDER BY day, caller, tool",
            (*span, *tools, *ex))]
        actor_tools_for = [] if not tools else [{"day": d, "user": u, "tool": t, "n": n} for d, u, t, n in conn.execute(
            "SELECT day, for_user, tool, SUM(n) FROM calls WHERE day BETWEEN ? AND ? AND caller = '' AND for_user != ''"
            f" AND outcome = 'ok' AND tool IN ({tmarks}){not_ex} GROUP BY day, for_user, tool ORDER BY day, for_user, tool",
            (*span, *tools, *ex))]
        auth = [{"day": d, "reason": r, "n": n} for d, r, n in conn.execute(
            "SELECT day, reason, n FROM auth WHERE day BETWEEN ? AND ? ORDER BY day, reason", span)]
    return {
        "contract": CONTRACT, "tz": "Asia/Seoul", "since": p["since"], "until": p["until"],
        "scanned_through": _kst_iso(meta.get("tail_ts")),
        "audit": {"lines": int(meta.get("lines") or 0), "bad": int(meta.get("bad") or 0),
                  "first_day": meta.get("first_day"), "last_day": meta.get("last_day")},
        "fields": {k: meta[f"field:{k}"] for k in FIELDS if meta.get(f"field:{k}")},
        "rules": {"status_tools": sorted(STATUS_TOOLS), "status_suffix": STATUS_SUFFIX, "big_chars": BIG_CHARS,
                  "lat_le_ms": list(LAT_LE_MS), "gate_errors": list(GATE_ERRORS)},
        "excluded": excluded, "calls": calls, "auth": auth, "actors": actors, "anon": anon, "actor_tools": actor_tools,
        "actors_for": actors_for, "actor_tools_for": actor_tools_for,
    }


def view(db_path, audit_path, raw: dict, *, resolve=None, budget_s: float = BUDGET_S, today: str | None = None,
         adoption_path=None) -> dict:
    """창구 한 번 — 물음을 읽고(틀리면 ValueError), 밀린 줄을 접고, 기간의 답을 낸다. adoption_path 를 주면 같은 기간의 채택 셈(adoption)을 덧붙인다."""
    p = params(raw, today)
    complete = catch_up(db_path, audit_path, resolve=resolve, budget_s=budget_s)
    out = {**query(db_path, p), "complete": complete}
    if adoption_path is not None:
        out["adoption"] = adopt_query(adoption_path, p["since"], p["until"])
    return out


# ── 채택 셈(HWAXPortal docs/mcp-modernize M0 · M3) ───────────────────────────────────────────────────────────────────────────────────────
# 보기(tools/list 의 full · bundle · light · purpose) · prompts/get · 자원 읽기(skill · ui) · 목적 목록 · 검색 목적 층이 얼마나 쓰이나를 KST 날마다 센다.
# 종전 셈(게이트웨이 /health 의 tools_list_by_view)은 프로세스 메모리라 재기동마다 0 이었다 — 그래서 '보기를 아무도 안 쓴다' 를 운영에서 잴 수 없었다.
# 감사 원장에서 다시 지을 수 없는 셈이라 위 접은 표(usage-rollup.sqlite — 꼴이 바뀌면 버리고 다시 접는다)와 따로 둔다. 사람 · 질의 글은 싣지 않는다 —
# 무엇(kind)과 어느 것(key — 보기 이름 · 목적 키 · 'routine' · 'ui')의 날마다의 수뿐이다. 파일은 0600 이다.
ADOPT_KINDS = frozenset(("tools_list", "view_purpose", "prompt", "resource", "list_purpose", "search_purpose"))
_ADOPT_KEY = re.compile(r"[A-Za-z0-9_.:*-]{1,80}")
_ADOPT_SCHEMA = ("CREATE TABLE IF NOT EXISTS adopt (day TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL, n INTEGER NOT NULL,"
                 " PRIMARY KEY (day, kind, key)) WITHOUT ROWID")
_ADOPT_LOCK = threading.Lock()


def _adopt_open(path) -> sqlite3.Connection:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        os.close(os.open(p, os.O_WRONLY | os.O_CREAT, 0o600))
    conn = sqlite3.connect(str(p), timeout=2.0, isolation_level=None)
    conn.execute(_ADOPT_SCHEMA)
    return conn


def adopt_note(path, kind: str, key: str, *, day: str | None = None) -> None:
    """한 번 셈 — (오늘 KST, kind, key) 의 수를 1 올린다. 모르는 kind 는 ValueError, 꼴이 다른 key 는 '(other)' 다(요청이 정한 글자를 싣지 않는다)."""
    if kind not in ADOPT_KINDS:
        raise ValueError(f"모르는 채택 갈래: {kind}")
    key = key if isinstance(key, str) and _ADOPT_KEY.fullmatch(key) else "(other)"
    day = day or datetime.now(KST).date().isoformat()
    with _ADOPT_LOCK, closing(_adopt_open(path)) as conn:
        conn.execute("INSERT INTO adopt VALUES (?, ?, ?, 1) ON CONFLICT (day, kind, key) DO UPDATE SET n = n + 1", (day, kind, key))


def adopt_query(path, since: str, until: str) -> list[dict]:
    """기간(KST 날, 끝 포함)의 채택 셈 — [{day, kind, key, n}] 날 · 갈래 · 열쇠 차례. 원장이 없으면 빈 목록(만들지 않는다)."""
    if not Path(path).exists():
        return []
    with closing(_adopt_open(path)) as conn:
        return [{"day": d, "kind": k, "key": key, "n": n} for d, k, key, n in conn.execute(
            "SELECT day, kind, key, n FROM adopt WHERE day BETWEEN ? AND ? ORDER BY day, kind, key", (since, until))]


def adopt_summary(path, days: int = 7, today: str | None = None) -> dict:
    """최근 days 일(오늘 포함)의 갈래별 합 — {since, until, by_kind: {kind: {key: n}}}. /health 가 싣는다."""
    end = date.fromisoformat(today) if today else datetime.now(KST).date()
    start = end - timedelta(days=max(1, days) - 1)
    by: dict[str, dict[str, int]] = {}
    for r in adopt_query(path, start.isoformat(), end.isoformat()):
        by.setdefault(r["kind"], {})[r["key"]] = by.get(r["kind"], {}).get(r["key"], 0) + r["n"]
    return {"since": start.isoformat(), "until": end.isoformat(), "by_kind": {k: dict(sorted(v.items())) for k, v in sorted(by.items())}}
