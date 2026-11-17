"""Pure log filtering and session summaries."""
import re
import codecs
from .config import DTO_RE, NET_RE


class LogLineBuffer:
    """Preserve UTF-8 characters and log lines split between process reads."""

    def __init__(self):
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._pending = ""

    def feed(self, data: bytes, *, final: bool = False) -> list[str]:
        self._pending += self._decoder.decode(data, final=final)
        complete = self._pending.split("\n")
        self._pending = complete.pop()
        if final and self._pending:
            complete.append(self._pending)
            self._pending = ""
        return [line.rstrip("\r") for line in complete]

def is_interesting(line: str, mode: int) -> bool:
    if mode == 1:
        return True
    if "----- CAPTURE" in line:
        return True
    upper = line.upper()
    if "EUNORA" in upper:
        return True
    if "LSPOSEDCONTEXT" in upper and "WHEELPROBE" in upper:
        return True
    if "COM.EXAMPLE.WHEELPROBE" in upper:
        return True
    if "DTO MATCH" in upper:
        return True
    if "STOPDETECTING" in upper or "DETECTING_CHANGED" in upper:
        return True
    return False

def summarize_lines(lines: list[str]) -> str:
    nets = []
    dtos = []
    for ln in lines:
        m = NET_RE.search(ln)
        if m:
            nets.append(f"NETWORK class={m.group(1)} source={m.group(2)}")
        m = DTO_RE.search(ln)
        if m:
            dtos.append(
                {
                    "group": m.group(1),
                    "index": m.group(2),
                    "callId": m.group(3),
                    "fare": m.group(4),
                    "km": m.group(5),
                    "dest": m.group(6).strip(),
                    "matched": m.group(7).rstrip(",.").lower(),
                }
            )
    out = []
    if nets:
        seen = set()
        out.append("[NETWORK]")
        for n in nets:
            if n not in seen:
                seen.add(n)
                out.append("  " + n)
    if dtos:
        latest = {}
        for d in dtos:
            latest[d["callId"]] = d
        matched = [d for d in latest.values() if d["matched"] in ("true", "1", "yes")]
        others = [d for d in latest.values() if d not in matched]
        out.append(f"[DTO] unique {len(latest)}  matched={len(matched)}  raw={len(dtos)}")
        if matched:
            out.append("★ MATCHED")
            for d in matched:
                out.append(
                    f"  ★ {d['callId']}  ₩{d['fare']}  {d['km']}km  "
                    f"matched=true  {d['dest']}"
                )
        if others:
            out.append("· not matched")
            for d in others:
                out.append(
                    f"  {d['callId']}  ₩{d['fare']}  {d['km']}km  "
                    f"matched={d['matched']}  {d['dest']}"
                )
    if not out:
        eunora_n = sum(1 for x in lines if "EUNORA" in x.upper())
        return f"요약 없음 (전체 {len(lines)}줄, EUNORA {eunora_n}줄)"
    return "\n".join(out)

