#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cyber-radar 数据采集器
======================
只做一件事：抓取公开威胁情报源，聚合成本项目的每日快照。

法律与安全边界（务必保持）：
  * 本脚本只"读"公开数据源，不向任何第三方主机发包探测；
  * 不做端口扫描、不做指纹识别、不做任何形式的主动探测；
  * 数据仅供学习与研究。

输出：
  data/latest.json       当日快照（index.html 读取）
  data/history.json      每日一个聚合点的历史序列（最多 365 天）
  reports/YYYY-MM-DD.md  当日中文日报

仅用 Python 标准库，无需安装任何包。
"""

import json
import ssl
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
REPORT_DIR = ROOT / "reports"

HEADERS = {"User-Agent": "cyber-radar/0.1 (public-feed aggregator; study project)"}
CTX = ssl.create_default_context()
UTC = timezone.utc

INFOCON_ZH = {
    "green": "绿色（当前无显著威胁活动）",
    "yellow": "黄色（出现值得警惕的活动）",
    "orange": "橙色（威胁活动明显升高）",
    "red": "红色（严重威胁事件）",
    "blue": "蓝色（信息性通告）",
}


def fetch_json(url, timeout=20):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


# ---------------------------------------------------------------- 数据源 ----

def src_infocon():
    """SANS ISC 全球威胁等级（green ~ red）。兼容包裹层与裸根两种返回形状。"""
    d = fetch_json("https://isc.sans.edu/api/infocon?json")
    node = d.get("infocon") if isinstance(d, dict) else None
    if not isinstance(node, dict):
        node = d  # 实测返回根就是 {"status": "green"}
    return {"level": str(node.get("status", "unknown")).lower()}


def src_scan_pressure():
    """全球扫描压力：被攻击最多的端口。ISC 失败时退回 DShield 官方 feed。"""
    try:
        d = fetch_json("https://isc.sans.edu/api/topports/records/10?json")
        if isinstance(d, dict) and isinstance(d.get("topports"), (list, dict)):
            raw = d["topports"]
            items = raw if isinstance(raw, list) else list(raw.values())
        elif isinstance(d, dict):
            # ISC 实际形状：{"0": {"rank":1,"targetport":22,...}, "1": {...}}
            items = list(d.values())
        else:
            items = []
        top = []
        for it in items:
            p = it.get("properties", it) if isinstance(it, dict) else {}
            port = p.get("targetport") or p.get("port")
            if port:
                top.append({
                    "rank": p.get("rank"),
                    "port": str(port),
                    "records": p.get("records"),
                    "targets": p.get("targets"),
                    "sources": p.get("sources"),
                })
        if top:
            top.sort(key=lambda x: x["rank"] if isinstance(x.get("rank"), int) else 99)
            return {"source": "SANS ISC", "top": top[:10]}
    except Exception:
        pass
    d = fetch_json("https://feeds.dshield.org/top10-attacked.json")
    items = d.get("data") or []
    top = [{"port": str(e.get("port")), "records": e.get("records"), "targets": e.get("targets")}
           for e in items if e.get("port")]
    return {"source": "DShield", "top": top[:10]}


def src_kev():
    """CISA KEV：已被在野利用的漏洞目录。"""
    d = fetch_json(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        timeout=30,
    )
    vulns = d.get("vulnerabilities") or []
    cutoff = datetime.now(UTC) - timedelta(days=7)

    def added(v):
        try:
            return datetime.strptime(v.get("dateAdded", ""), "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            return None

    recent = [v for v in vulns if (added(v) or datetime.min.replace(tzinfo=UTC)) >= cutoff]
    recent.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    return {
        "total": int(d.get("count") or len(vulns)),
        "new_7d": len(recent),
        "released": d.get("dateReleased", ""),
        "recent": [
            {
                "cve": v.get("cveID", "?"),
                "vendor": v.get("vendorProject", "?"),
                "product": v.get("product", "?"),
                "added": v.get("dateAdded", ""),
                "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                "desc": (v.get("shortDescription") or "").strip()[:100],
            }
            for v in recent[:10]
        ],
    }


def src_feodo():
    """Feodo Tracker：当前活跃的银行木马 C2 地址。"""
    d = fetch_json("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    items = d if isinstance(d, list) else (d.get("Data") or [])
    fams, ips = {}, set()
    for e in items:
        ip = e.get("ip_address")
        if ip:
            ips.add(ip)
        f = (e.get("malware") or "unknown").strip() or "unknown"
        fams[f] = fams.get(f, 0) + 1
    top = sorted(fams.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
    return {
        "c2_ips": len(ips),
        "entries": len(items),
        "families": [{"family": k, "count": v} for k, v in top],
    }


def src_openphish():
    """OpenPhish 社区源：当前活跃钓鱼 URL 列表（纯文本，每行一条）。
    注：原 URLhaus 公开下载端点已下线（HTTP 410，abuse.ch 2025 年起强制 API 鉴权），
    故改用 OpenPhish 免费社区源。"""
    req = urllib.request.Request("https://openphish.com/feed.txt", headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30, context=CTX) as resp:
        text = resp.read().decode("utf-8", "replace")
    urls = [ln.strip() for ln in text.splitlines() if ln.strip()]
    doms = {}
    for u in urls:
        try:
            h = urlparse(u).netloc.lower()
        except Exception:
            continue
        if h:
            doms[h] = doms.get(h, 0) + 1
    top = sorted(doms.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
    return {"recent": len(urls), "top_domains": [{"domain": k, "count": v} for k, v in top]}


def src_nvd():
    """NVD：最近 7 天新披露的 CVE，统计高危/严重。"""
    end = datetime.now(UTC)
    start = end - timedelta(days=7)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start.strftime(fmt)}&pubEndDate={end.strftime(fmt)}"
        "&resultsPerPage=2000"
    )
    d = fetch_json(url, timeout=45)
    rows = d.get("vulnerabilities") or []
    critical, high = [], 0
    for row in rows:
        cve = row.get("cve") or {}
        cid = cve.get("id", "?")
        score, severity = None, ""
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if arr:
                data = arr[0].get("cvssData") or {}
                try:
                    score = float(data.get("baseScore"))
                except (TypeError, ValueError):
                    score = None
                severity = data.get("baseSeverity", "")
                break
        if score is None:
            continue
        item = {"cve": cid, "score": score, "severity": severity}
        if score >= 9.0:
            critical.append(item)
        elif score >= 7.0:
            high += 1
    critical.sort(key=lambda x: -x["score"])
    return {
        "published_7d": int(d.get("totalResults") or len(rows)),
        "critical_7d": len(critical),
        "high_7d": high,
        "critical_list": critical[:10],
    }


# ---------------------------------------------------------------- 主流程 ----

SOURCES = {
    "infocon": ("SANS ISC 威胁等级", src_infocon),
    "scan_pressure": ("全球端口扫描压力", src_scan_pressure),
    "kev": ("CISA KEV 在野利用漏洞", src_kev),
    "feodo": ("Feodo Tracker C2", src_feodo),
    "openphish": ("OpenPhish 钓鱼URL", src_openphish),
    "nvd": ("NVD 新披露 CVE", src_nvd),
}


def build_snapshot():
    now = datetime.now(UTC)
    snap = {
        "generatedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "date": now.strftime("%Y-%m-%d"),
        "ok_sources": 0,
        "sources": {},
    }
    for key, (label, fn) in SOURCES.items():
        try:
            snap["sources"][key] = {"label": label, "status": "ok", "data": fn()}
            snap["ok_sources"] += 1
        except Exception as exc:  # 单源失败不影响整体
            snap["sources"][key] = {
                "label": label, "status": "error", "error": f"{type(exc).__name__}: {exc}",
            }
    return snap


def history_point(snap):
    s = snap["sources"]

    def num(key, *path):
        node = s.get(key, {}).get("data") or {}
        for p in path:
            node = node.get(p) if isinstance(node, dict) else None
        return node if isinstance(node, (int, float)) else 0

    infocon = (s.get("infocon", {}).get("data") or {}).get("level", "unknown")
    return {
        "date": snap["date"],
        "infocon": infocon,
        "kev_total": num("kev", "total"),
        "kev_new_7d": num("kev", "new_7d"),
        "c2_ips": num("feodo", "c2_ips"),
        "phish_recent": num("openphish", "recent"),
        "published_7d": num("nvd", "published_7d"),
        "critical_7d": num("nvd", "critical_7d"),
        "ok_sources": snap["ok_sources"],
    }


def update_history(point):
    DATA_DIR.mkdir(exist_ok=True)
    path = DATA_DIR / "history.json"
    try:
        hist = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        hist = []
    hist = [h for h in hist if h.get("date") != point["date"]]
    hist.append(point)
    hist = hist[-365:]
    path.write_text(json.dumps(hist, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def write_report(snap, point):
    s = snap["sources"]
    day = snap["date"]
    total = len(SOURCES)
    lines = [
        "# 全球网络安全态势日报",
        "",
        f"> 采集时间：{snap['generatedAt']}（UTC）· 成功数据源 {snap['ok_sources']}/{total}",
        "",
        "## 总体态势",
        "",
        f"- SANS ISC 全球威胁等级：**{INFOCON_ZH.get(point.get('infocon', ''), point.get('infocon', 'unknown'))}**",
        "",
    ]

    kev = (s.get("kev") or {}).get("data") or {}
    if kev:
        lines += [
            "## 在野利用漏洞（CISA KEV）",
            "",
            f"- 目录总量：{kev.get('total')}，最近 7 天新增：**{kev.get('new_7d')}**",
            "",
        ]
        rec = kev.get("recent") or []
        if rec:
            lines += ["| 添加日期 | CVE | 厂商/产品 | 勒索软件关联 |", "|---|---|---|---|"]
            for v in rec:
                rw = "是" if v.get("ransomware") else ""
                lines.append(
                    f"| {v.get('added', '')} | {v.get('cve', '')} "
                    f"| {v.get('vendor', '')} / {v.get('product', '')} | {rw} |"
                )
            lines.append("")

    feodo = (s.get("feodo") or {}).get("data") or {}
    if feodo:
        lines += ["## 僵尸网络 C2（Feodo Tracker）", "",
                  f"- 当前活跃 C2 IP：**{feodo.get('c2_ips')}**", ""]
        fams = feodo.get("families") or []
        if fams:
            lines += ["| 家族 | 条目数 |", "|---|---|"]
            lines += [f"| {f['family']} | {f['count']} |" for f in fams]
            lines.append("")

    phish = (s.get("openphish") or {}).get("data") or {}
    if phish:
        doms = phish.get("top_domains") or []
        dom_str = "、".join(f"{t['domain']}({t['count']})" for t in doms) or "无"
        lines += ["## 钓鱼 URL（OpenPhish 当前活跃）", "",
                  f"- 活跃钓鱼 URL：**{phish.get('recent')}** 条；高频域名：{dom_str}", ""]

    nvd = (s.get("nvd") or {}).get("data") or {}
    if nvd:
        lines += [
            "## 新披露 CVE（NVD，最近 7 天）",
            "",
            (f"- 新披露：{nvd.get('published_7d')} 条，其中严重（CVSS≥9.0）"
             f"**{nvd.get('critical_7d')}** 条、高危（7.0–8.9）{nvd.get('high_7d')} 条"),
            "",
        ]
        cl = nvd.get("critical_list") or []
        if cl:
            lines += ["| CVE | 评分 | 等级 |", "|---|---|---|"]
            lines += [f"| {c['cve']} | {c['score']} | {c.get('severity', '')} |" for c in cl]
            lines.append("")

    scan = (s.get("scan_pressure") or {}).get("data") or {}
    if scan:
        top = scan.get("top") or []
        if top:
            lines += [f"## 扫描压力（{scan.get('source', '')}：被攻击最多的端口）", "",
                      "| 端口 | 记录数 | 目标数 | 来源IP数 |", "|---|---|---|---|"]
            lines += [f"| {p.get('port', '')} | {p.get('records') or '-'} | {p.get('targets') or '-'} | {p.get('sources') or '-'} |"
                      for p in top]
            lines.append("")

    bad = [(k, v.get("error")) for k, v in s.items() if v.get("status") != "ok"]
    if bad:
        lines += ["## 数据源状态", ""]
        lines += [f"- ❌ {k}: {err}" for k, err in bad]
        lines += ["- ✅ 其余数据源正常", ""]

    lines += [
        "---",
        "",
        "*本项目仅聚合公开威胁情报，不进行任何主动扫描。数据仅供学习研究。*",
        "",
    ]
    REPORT_DIR.mkdir(exist_ok=True)
    (REPORT_DIR / f"{day}.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    snap = build_snapshot()
    point = history_point(snap)
    update_history(point)
    write_report(snap, point)
    DATA_DIR.mkdir(exist_ok=True)
    (DATA_DIR / "latest.json").write_text(
        json.dumps(snap, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    print(f"[done] {snap['date']}  ok {snap['ok_sources']}/{len(SOURCES)}")
    for k, v in snap["sources"].items():
        line = f"  {k:14s} {v['status']}"
        if v["status"] != "ok":
            line += f"  {v.get('error', '')}"
        print(line)


if __name__ == "__main__":
    main()
