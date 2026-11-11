#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webui.py —— 反射型 XSS 检测工具的图形化 Web 界面（火影忍者像素风）

只使用 Python 标准库，无需安装任何依赖。

启动:
    python webui.py                 # 默认 http://127.0.0.1:8848
    python webui.py --port 9000
    python webui.py --no-open       # 不自动打开浏览器
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import traceback
import urllib.parse
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List

import xss_scanner as xs

ROOT = os.path.dirname(os.path.abspath(__file__))
UI_FILE = os.path.join(ROOT, "ui", "index.html")

TOTAL_STEPS = 9          # 扫描流程的大阶段数, 用于进度条
JOBS: Dict[str, Dict[str, Any]] = {}
_LAST_JOB = {"id": None}


# ---------------------------------------------------------------------------
# 任务执行
# ---------------------------------------------------------------------------
def _build_namespace(cfg: Dict[str, Any]) -> argparse.Namespace:
    def g(k, d=None):
        v = cfg.get(k, d)
        return v if v not in ("", None) else d

    return argparse.Namespace(
        url=g("url", xs.DEFAULT_URL),
        cookie=g("cookie", xs.DEFAULT_COOKIE),
        param=g("param", None),
        method=g("method", None),
        payload=g("payload", None),
        verify_only=bool(cfg.get("verify_only")),
        no_browser=bool(cfg.get("no_browser")),
        max_payloads=int(g("max_payloads", 0) or 0),
        timeout=float(g("timeout", 15) or 15),
        delay=float(g("delay", 0.05) or 0.05),
        proxy=g("proxy", ""),
        json="",          # Web 模式下不落盘
        poc_out="",
        verbose=False,
    )


def _worker(job: Dict[str, Any], cfg: Dict[str, Any]) -> None:
    def sink(level: str, msg: str) -> None:
        with job["lock"]:
            job["logs"].append({"level": level, "msg": msg})
            if level == "head":
                job["step"] += 1

    xs.Log.add_sink(sink)
    try:
        ns = _build_namespace(cfg)
        if ns.verify_only:
            rep = xs.verify_only(ns)
        else:
            rep = xs.run(ns)
        with job["lock"]:
            job["report"] = rep
    except Exception as e:                       # noqa: BLE001
        with job["lock"]:
            job["error"] = "%s: %s" % (type(e).__name__, e)
        traceback.print_exc()
    finally:
        xs.Log.remove_sink(sink)
        with job["lock"]:
            job["done"] = True


def run_diag(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """环境自检：目标连通性 + 浏览器引擎状态。"""
    url = (cfg.get("url") or "").strip() or xs.DEFAULT_URL
    cookie = (cfg.get("cookie") or "").strip() or xs.DEFAULT_COOKIE
    checks: List[Dict[str, Any]] = []

    checks.append({"name": "Python", "ok": True,
                   "detail": sys.version.split()[0]})

    # 1) 目标连通性
    try:
        s = xs.Session(cookie=cookie, timeout=8, delay=0)
        r = s.request(url)
        if r.ok:
            t = re.search(r"<title>(.*?)</title>", r.text, re.I | re.S)
            title = t.group(1).strip()[:60] if t else ""
            detail = "HTTP %s · %d 字节" % (r.status, r.length)
            if title:
                detail += " · " + title
            ok = r.status == 200
            checks.append({"name": "目标连通", "ok": ok, "detail": detail})
            if "login.php" in r.url.lower():
                checks.append({"name": "登录态", "ok": False,
                               "detail": "被重定向到登录页，Cookie 可能已失效"})
        else:
            checks.append({"name": "目标连通", "ok": False,
                           "detail": r.error or ("HTTP %s" % r.status)})
    except Exception as e:                       # noqa: BLE001
        checks.append({"name": "目标连通", "ok": False,
                       "detail": "%s: %s" % (type(e).__name__, e)})

    # 2) 浏览器引擎
    engine = xs.browser_available()
    if not engine:
        checks.append({"name": "弹窗验证", "ok": False,
                       "detail": "未安装 playwright / selenium（可勾选「跳过浏览器验证」）"})
    else:
        checks.append({"name": "浏览器引擎", "ok": True, "detail": engine})
        if engine == "playwright":
            try:
                from playwright.sync_api import sync_playwright
                with sync_playwright() as p:
                    path = p.chromium.executable_path
                exists = bool(path) and os.path.exists(path)
                checks.append({
                    "name": "Chromium 内核", "ok": exists,
                    "detail": path if exists else
                    "缺失，请执行: python -m playwright install chromium"})
            except Exception as e:               # noqa: BLE001
                checks.append({"name": "Chromium 内核", "ok": False,
                               "detail": "%s: %s" % (type(e).__name__, e)})
    return {"checks": checks}


def start_job(cfg: Dict[str, Any]) -> str:
    jid = uuid.uuid4().hex[:10]
    job = {"id": jid, "logs": [], "done": False, "report": None,
           "error": None, "step": 0, "lock": threading.Lock()}
    JOBS[jid] = job
    _LAST_JOB["id"] = jid
    # 清理历史任务, 避免长跑内存增长
    if len(JOBS) > 12:
        for k in list(JOBS)[:-12]:
            JOBS.pop(k, None)
    threading.Thread(target=_worker, args=(job, cfg), daemon=True).start()
    return jid


# ---------------------------------------------------------------------------
# HTTP 服务
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "NinjaXSS/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):      # 静音访问日志
        pass

    # -- helpers ------------------------------------------------------------
    def _send(self, code: int, body, ctype: str = "application/json; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code: int = 200):
        try:
            payload = json.dumps(obj, ensure_ascii=False, default=str)
        except Exception as e:                   # noqa: BLE001
            code = 500
            payload = json.dumps({"error": "响应序列化失败: %s" % e},
                                 ensure_ascii=False)
        self._send(code, payload)

    # -- GET ----------------------------------------------------------------
    def do_GET(self):
        path = urllib.parse.urlsplit(self.path)
        if path.path in ("/", "/index.html"):
            return self._serve_ui()
        if path.path == "/api/poll":
            return self._poll(path.query)
        if path.path == "/api/health":
            return self._json({"ok": True})
        self._json({"error": "not found"}, 404)

    def _serve_ui(self):
        try:
            with open(UI_FILE, "r", encoding="utf-8") as f:
                html = f.read()
        except OSError as e:
            return self._send(500, "UI 文件缺失: %s" % e, "text/plain; charset=utf-8")
        self._send(200, html, "text/html; charset=utf-8")

    def _poll(self, query: str):
        q = urllib.parse.parse_qs(query)
        jid = (q.get("job") or [""])[0]
        try:
            cursor = int((q.get("cursor") or ["0"])[0])
        except ValueError:
            cursor = 0
        job = JOBS.get(jid)
        if job is None:
            return self._json({"logs": [], "cursor": cursor, "done": True,
                               "error": "任务不存在", "report": None,
                               "progress": 0})
        with job["lock"]:
            logs = job["logs"][cursor:]
            total = len(job["logs"])
            done = job["done"]
            report = job["report"]
            err = job["error"]
            step = job["step"]
        progress = 100 if done else min(97, int(step / TOTAL_STEPS * 100))
        self._json({"logs": logs, "cursor": total, "done": done,
                    "error": err, "report": report, "progress": progress})

    # -- POST ---------------------------------------------------------------
    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path not in ("/api/scan", "/api/diag"):
            return self._json({"error": "not found"}, 404)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b"{}"
            cfg = json.loads(raw.decode("utf-8") or "{}")
        except Exception as e:                   # noqa: BLE001
            return self._json({"error": "参数解析失败: %s" % e}, 400)
        if path == "/api/diag":
            try:
                return self._json(run_diag(cfg))
            except Exception as e:               # noqa: BLE001
                return self._json({"error": "%s: %s" % (type(e).__name__, e)}, 500)
        self._json({"job": start_job(cfg)})


def main():
    ap = argparse.ArgumentParser(description="忍界 XSS 探针 · Web 图形界面")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8848)
    ap.add_argument("--no-open", action="store_true", help="不自动打开浏览器")
    a = ap.parse_args()

    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    url = "http://%s:%d/" % (a.host, a.port)
    print("=" * 58)
    print("  忍界 XSS 探针  ·  NINJA REFLEX XSS SCANNER")
    print("  " + url)
    print("  Ctrl+C 停止")
    print("=" * 58)
    if not a.no_open:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
