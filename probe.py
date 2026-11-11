import sys, urllib.request
url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1/vulnerabilities/xss_r/"
req = urllib.request.Request(url, headers={
    "Cookie": "PHPSESSID=pio9vir55opk5pi13vvr61m6k0; security=low",
    "User-Agent": "Mozilla/5.0",
})
try:
    r = urllib.request.urlopen(req, timeout=10)
    b = r.read().decode("utf-8", "replace")
    print("STATUS", r.status, "LEN", len(b))
    print(b[:1200])
except Exception as e:
    print("ERR", type(e).__name__, e)
