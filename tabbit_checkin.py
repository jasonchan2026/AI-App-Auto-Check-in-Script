#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tabbit 浏览器每日自动签到脚本（单文件版）
==========================================

背景
----
Tabbit（美团「光年之外」出品的 AI 浏览器）个人中心有「每日签到」活动：
连续签到可领取 usage 额度与「桌面宠物」权益，权益区分国内版与国际版两套账号体系：

    - 国内版：https://web.tabbit.com
    - 国际版：https://web.tabbit-ai.com

原理
----
签到接口逆向自浏览器扩展的 popup JS：

    1) 鉴权仅用 Cookie（Cookie 中的 token 字段即 JWT）
    2) 查状态：GET  {base}/api/commerce/activity/v1/sign-in/status?scene_codes=...
    3) 签到：  POST {base}/api/commerce/activity/v1/sign-in
       body: { request_no: <32位hex>, scene_codes: ["daily_sign_in","desktop_pet"] }
    4) request_no 为 32 位 hex：时间戳位 [2,7,11,14,18,21,25,28] 填 Unix 秒的 hex，
       第 5 位是「默认浏览器」标记 "1"，其余位从 '023456789abcdef' 随机。

Cookie 从哪来（关键差异点）
---------------------------
macOS 下 Tabbit 的 Cookies 库**无法离线解密**（实测：格式为标准 v10 信封
"AES-128-CBC + 前置 SHA256(host)"，32+1235=1267 -> 补齐到 1280 字节完全吻合，
但 Keychain 中 "Tabbit Browser Safe Storage" 的密钥无法解出明文，说明 Tabbit 使用了
非标准密钥来源）。因此本脚本改用 **Tabbit 自带的 Playwright 桥**读取登录态：

    tabbit-cli nodejs --task <name> --request-id <id> --read-only   # 代码走 stdin

浏览器内 context.cookies() 返回的是已解密明文，零逆向、零依赖。读取结果会缓存到
本地（带 JWT 过期时间），缓存有效期内不重复调用浏览器。

特点
----
- 仅用 Python 标准库，无第三方依赖
- 幂等安全：先查状态，已签到直接跳过，绝不重复领
- Cookie 缓存：读取一次可复用至 JWT 过期（约 7 天），日常签到无需浏览器在线
- 不操控 UI、不新建标签页，纯读取登录态 + 纯 HTTP 调用
- 支持 --dry-run 预览、--json 机器可读输出，适合 cron / launchd 定时运行

用法示例
--------
    python3 tabbit_checkin.py                     # 国内版+国际版都签（已签则跳过）
    python3 tabbit_checkin.py --site cn           # 只签国内版
    python3 tabbit_checkin.py --dry-run           # 只看今日状态，不签到
    python3 tabbit_checkin.py --refresh-cookie    # 强制重新从浏览器读取 Cookie
    python3 tabbit_checkin.py --json              # 仅输出机器可读 JSON

退出码
------
    0  成功（含「今日已签到」）
    1  配置错误（找不到 tabbit-cli / 未登录 / Cookie 失效）
    2  网络 / 接口错误
    3  未知异常

前置条件
--------
    Tabbit 浏览器需处于运行状态（首次读取 Cookie 时）；之后依赖缓存即可。
"""

import argparse
import base64
import json
import os
import random
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# ----------------------------- 配置 -----------------------------
SITES = {
    "cn": "https://web.tabbit.com",
    "intl": "https://web.tabbit-ai.com",
}
SITE_ALIASES = {
    "cn": "cn", "domestic": "cn", "国内": "cn", "国内版": "cn",
    "intl": "intl", "international": "intl", "国际": "intl", "国际版": "intl",
}

STATUS_PATH = "/api/commerce/activity/v1/sign-in/status"
SIGNIN_PATH = "/api/commerce/activity/v1/sign-in"
SCENES = ["daily_sign_in", "desktop_pet"]

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)

# tabbit-cli 稳定启动器候选路径（跨平台）
TABBIT_CLI_CANDIDATES = [
    "~/.local/bin/tabbit-cli",                                   # macOS / POSIX
    r"%LOCALAPPDATA%\Tabbit\LocalAgent\bin\tabbit-cli.exe",      # Windows
]

# Cookie 缓存（含 JWT 过期时间）
CACHE_PATH = "~/.tabbit_checkin/cookies.json"

# request_no 生成参数（还原扩展 en() 逻辑）
REQUEST_NO_CFG = {
    "marker_pos": 5,
    "default_marker": "1",
    "ts_positions": [2, 7, 11, 14, 18, 21, 25, 28],
}


# ----------------------------- 日志 -----------------------------
class Log:
    def __init__(self, quiet=False):
        self.quiet = quiet

    def info(self, msg):
        if not self.quiet:
            print(f"[INFO] {msg}")

    def warn(self, msg):
        if not self.quiet:
            print(f"[WARN] {msg}", file=sys.stderr)

    def err(self, msg):
        print(f"[ERROR] {msg}", file=sys.stderr)


# ----------------------------- request_no -----------------------------
def gen_request_no(is_default_browser=True):
    """生成 32 位 hex 的 request_no（完全复刻 Tabbit 扩展的实现）。

    规则：hex 池去掉 "1"；第 5 位固定为默认浏览器标记 "1"；时间戳 8 位 hex 依次
    填入位置 [2,7,11,14,18,21,25,28]；其余位随机。
    """
    cfg = REQUEST_NO_CFG
    hexchars = "0123456789abcdef"
    pool = hexchars.replace(cfg["default_marker"], "", 1)  # '023456789abcdef'
    ts = format(int(time.time()), "x").rjust(8, "0")[-8:]
    slots = {p: ts[i] for i, p in enumerate(cfg["ts_positions"])}

    out = []
    for i in range(32):
        if i == cfg["marker_pos"]:
            out.append(cfg["default_marker"] if is_default_browser
                       else random.choice(pool))
        elif i in slots:
            out.append(slots[i])
        else:
            out.append(random.choice(pool))
    return "".join(out)


# ----------------------------- Cookie 获取 -----------------------------
def find_tabbit_cli(log: Log):
    for cand in TABBIT_CLI_CANDIDATES:
        path = os.path.expandvars(os.path.expanduser(cand))
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


# 在浏览器内执行的取 Cookie 代码（返回 {站点URL: "cookie串"}）
CLI_JS = """
const urls = %s;
const out = {};
for (const u of urls) {
  try {
    const cs = await context.cookies([u]);
    const t = cs.find(c => c.name === 'token');
    const id = cs.find(c => c.name === 'user_id');
    if (t && t.value) out[u] = 'token=' + t.value + (id ? '; user_id=' + id.value : '');
  } catch (e) { /* 该站点未登录，跳过 */ }
}
return out;
"""


def read_cookies_via_cli(cli, log: Log, timeout_ms=60000):
    """通过 Tabbit 的 Playwright 桥读取各站点解密后的 Cookie。

    使用兼容模式命令：code 从 stdin 送入，stdout 回一行 JSON receipt。
    只做读取，不新建标签页、不操控 UI。
    """
    task = "tabbit-checkin"
    rid = f"ck-{int(time.time())}"
    js = CLI_JS % json.dumps(sorted(set(SITES.values())))

    def _call(extra):
        argv = [cli, "nodejs", "--task", task, "--request-id", rid,
                "--read-only", "--timeout-ms", str(timeout_ms)] + extra
        log.info("调用 Tabbit Playwright 桥读取登录态……")
        try:
            return subprocess.run(argv, input=js.encode("utf-8"),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=timeout_ms / 1000.0 + 30)
        except subprocess.TimeoutExpired:
            raise RuntimeError("tabbit-cli 调用超时（浏览器无响应？）")

    proc = _call([])
    receipts = [ln for ln in proc.stdout.decode("utf-8", "replace").splitlines()
                if ln.strip().startswith("{")]
    if not receipts:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(
            f"tabbit-cli 未返回结果（exit={proc.returncode}）"
            + (f"：{err.splitlines()[-1]}" if err else "")
            + "。请确认 Tabbit 浏览器正在运行。")

    data = json.loads(receipts[-1])

    # 任务可能排队（queued），需用 receipt 命令等待结果
    status = data.get("status")
    if status == "queued":
        log.info("任务排队中，等待结果……")
        argv = [cli, "receipt", "--task", task, "--request-id", rid,
                "--wait-ms", str(timeout_ms)]
        try:
            p2 = subprocess.run(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout_ms / 1000.0 + 30)
            r2 = [ln for ln in p2.stdout.decode("utf-8", "replace").splitlines()
                  if ln.strip().startswith("{")]
            if r2:
                data = json.loads(r2[-1])
        except subprocess.TimeoutExpired:
            raise RuntimeError("等待签到读取结果超时")

    if data.get("status") != "succeeded":
        raise RuntimeError(f"Playwright 桥执行失败：{json.dumps(data, ensure_ascii=False)[:300]}")

    value = (data.get("result") or {}).get("value") or {}
    if not isinstance(value, dict):
        raise RuntimeError("Playwright 桥返回结构异常")

    result = {}
    for key, site in SITES.items():
        if value.get(site):
            result[key] = value[site]
    if not result:
        raise RuntimeError("浏览器内未找到 token Cookie，请先在 Tabbit 中登录对应站点")
    return result


def finish_cli(cli):
    """结束该任务并清理会话创建的标签页（读取操作不会创建标签页）。"""
    try:
        subprocess.run([cli, "finish", "--task", "tabbit-checkin", "--discard"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    except Exception:  # noqa: BLE001
        pass


def jwt_exp(token):
    """解析 JWT 的 exp 声明（秒）。失败返回 None。"""
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        payload = json.loads(base64.urlsafe_b64decode(seg))
        exp = payload.get("exp")
        return int(exp) if exp else None
    except Exception:  # noqa: BLE001
        return None


def cookie_expiry(cookie_str):
    """从 cookie 串里取出 token 的过期时间。"""
    for part in cookie_str.split(";"):
        if part.strip().startswith("token="):
            return jwt_exp(part.split("=", 1)[1])
    return None


def load_cache():
    path = os.path.expanduser(CACHE_PATH)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_cache(cache):
    path = os.path.expanduser(CACHE_PATH)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        pass


def refresh_from_browser(args, log: Log, cache):
    """从运行中的 Tabbit 读取各站点 Cookie，并写入缓存。返回 {site: cookie}。"""
    cli = find_tabbit_cli(log)
    if not cli:
        raise RuntimeError(
            "未找到 tabbit-cli（Tabbit 浏览器未安装或未初始化）。"
            "可用 --cookie / 环境变量 TABBIT_COOKIE 直接传入 Cookie")
    log.info(f"使用启动器：{cli}")
    fresh = read_cookies_via_cli(cli, log, timeout_ms=args.cli_timeout_ms)
    finish_cli(cli)

    now = int(time.time())
    for k, ck in fresh.items():
        cache[k] = {"cookie": ck, "exp": cookie_expiry(ck), "saved_at": now}
    save_cache(cache)
    return fresh


def resolve_cookies(args, log: Log):
    """按优先级取得各站点 Cookie：命令行/环境变量 > 有效缓存 > 浏览器桥。"""
    wanted = list(args.site_keys)

    # 1) 显式传入（--cookie 或环境变量）——仅对单站点有意义
    if args.cookie:
        log.info("使用显式传入的 Cookie（--cookie）")
        return {wanted[0]: args.cookie.strip()}
    if os.environ.get("TABBIT_COOKIE"):
        log.info("使用显式传入的 Cookie（环境变量 TABBIT_COOKIE）")
        return {wanted[0]: os.environ["TABBIT_COOKIE"].strip()}

    # 2) 本地缓存（token 未过期才用）
    cache = {} if args.refresh_cookie else load_cache()
    now = int(time.time())
    usable = {}
    for k in wanted:
        entry = cache.get(k)
        if not entry:
            continue
        exp = entry.get("exp")
        if exp and exp - 600 > now:      # 留 10 分钟余量
            usable[k] = entry["cookie"]
    if len(usable) == len(wanted):
        remain = min((cache[k]["exp"] - now) / 86400.0 for k in wanted)
        log.info(f"使用本地缓存 Cookie（最早 {remain:.1f} 天后过期）")
        return usable

    # 3) 从浏览器读取
    fresh = refresh_from_browser(args, log, cache)
    missing = [k for k in wanted if k not in fresh]
    if missing:
        log.warn("以下站点在浏览器中无登录态，将跳过："
                 + "、".join(SITES[k] for k in missing))
    if not fresh:
        raise RuntimeError("所有目标站点均无有效登录态，请先在 Tabbit 中登录")
    return fresh


# ----------------------------- HTTP -----------------------------
def http_request(url, cookie, timeout, method="GET", body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={
            "Cookie": cookie,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            raw = e.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            raw = ""
        return e.code, raw
    except urllib.error.URLError as e:
        raise RuntimeError(f"网络请求失败: {e.reason}") from e
    return 200, raw


def parse_body(raw):
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"_raw": raw}


def fetch_status(base, cookie, timeout):
    qs = "&".join(f"scene_codes={urllib.parse.quote(s)}" for s in SCENES)
    url = f"{base}{STATUS_PATH}?{qs}"
    code, raw = http_request(url, cookie, timeout, "GET")
    body = parse_body(raw)
    if code != 200:
        if code in (401, 403):
            raise RuntimeError("Cookie 已失效或未登录（HTTP %d）" % code)
        raise RuntimeError(f"状态查询失败: HTTP {code} {(raw or '')[:150]}")
    if body.get("code") not in (None, 0):
        raise RuntimeError(f"状态查询失败: {json.dumps(body, ensure_ascii=False)[:200]}")
    return body


def submit_signin(base, cookie, timeout):
    url = f"{base}{SIGNIN_PATH}"
    body = {"request_no": gen_request_no(True), "scene_codes": SCENES}
    code, raw = http_request(url, cookie, timeout, "POST", body)
    parsed = parse_body(raw)
    if code != 200:
        raise RuntimeError(f"签到失败: HTTP {code} {(raw or '')[:150]}")
    if parsed.get("code") not in (None, 0):
        raise RuntimeError(f"签到失败: {json.dumps(parsed, ensure_ascii=False)[:200]}")
    return parsed


def fetch_status_with_refresh(key, base, cookie, args, log: Log, cache):
    """查状态；若缓存 Cookie 失效则自动从浏览器刷新一次再重试。

    返回 (status_body, 实际生效的 cookie)。
    """
    try:
        return fetch_status(base, cookie, args.timeout), cookie
    except RuntimeError as e:
        msg = str(e)
        if "失效" not in msg and "401" not in msg and "403" not in msg:
            raise
        # 显式传入的 Cookie 不自动覆盖
        if args.cookie or os.environ.get("TABBIT_COOKIE"):
            raise
        log.warn(f"[{key}] 本地缓存 Cookie 已失效，尝试从浏览器重新读取……")
        cache.pop(key, None)
        fresh = refresh_from_browser(args, log, cache)
        if key not in fresh:
            raise RuntimeError("浏览器中该站点也已过期或未登录，请重新登录后再试")
        log.info(f"[{key}] 已获取新 Cookie，重试……")
        return fetch_status(base, fresh[key], args.timeout), fresh[key]


def pick_scene(body, scene="daily_sign_in"):
    for item in (body or {}).get("results") or []:
        if item.get("scene_code") == scene:
            return item
    return {}


# ----------------------------- 主流程 -----------------------------
def parse_sites(value):
    if value in (None, "both", "all"):
        return ["cn", "intl"]
    keys = []
    for part in str(value).replace(",", " ").split():
        key = SITE_ALIASES.get(part.lower()) or SITE_ALIASES.get(part)
        if not key:
            raise argparse.ArgumentTypeError(
                f"未知站点：{part}（可选 cn / intl / both）")
        if key not in keys:
            keys.append(key)
    return keys or ["cn", "intl"]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Tabbit 浏览器每日自动签到脚本（单文件版）")
    parser.add_argument("--site", default="both",
                        help="目标站点：cn（国内版）/ intl（国际版）/ both（默认）")
    parser.add_argument("--cookie", help="直接传入 Cookie 串（仅单站点有效）")
    parser.add_argument("--refresh-cookie", action="store_true",
                        help="忽略本地缓存，强制从浏览器重新读取 Cookie")
    parser.add_argument("--dry-run", action="store_true",
                        help="只查询今日状态，不执行签到")
    parser.add_argument("--json", action="store_true", help="仅输出机器可读 JSON")
    parser.add_argument("--quiet", "-q", action="store_true", help="静默模式")
    parser.add_argument("--timeout", type=int, default=20, help="HTTP 超时（秒）")
    parser.add_argument("--cli-timeout-ms", type=int, default=60000,
                        help="Playwright 桥调用超时（毫秒，默认 60000）")
    args = parser.parse_args(argv)

    # --json 时 stdout 必须只输出 JSON：INFO 一律静音，WARN/ERROR 仍走 stderr
    log = Log(quiet=args.quiet or args.json)
    try:
        args.site_keys = parse_sites(args.site)
    except argparse.ArgumentTypeError as e:
        log.err(str(e))
        return 1

    def emit(payload):
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))

    try:
        cookies = resolve_cookies(args, log)
        cache = load_cache()
        results = []
        errors = []

        for key in args.site_keys:
            cookie = cookies.get(key)
            base = SITES[key]
            if not cookie:
                continue
            entry = {"site": key, "base": base}
            try:
                status, cookie = fetch_status_with_refresh(
                    key, base, cookie, args, log, cache)
                daily = pick_scene(status, "daily_sign_in")
                pet = pick_scene(status, "desktop_pet")
                entry.update({
                    "sign_in_date": status.get("sign_in_date"),
                    "signed_today": bool(daily.get("signed_today")),
                    "signed_days": daily.get("signed_days"),
                    "total_signed_days": daily.get("total_signed_days"),
                    "activity_open": daily.get("activity_open"),
                    "usage_reward": daily.get("usage_reward_result"),
                    "pet_eligible": pet.get("pet_entitlement_result"),
                })
                if not args.json:
                    log.info(
                        f"[{key}] {base}　今日已签到={entry['signed_today']}　"
                        f"连签={entry['signed_days']} 天　累计={entry['total_signed_days']} 天　"
                        f"额度奖励={entry['usage_reward']}")

                if args.dry_run:
                    entry["action"] = "dry_run"
                    results.append(entry)
                    continue

                if entry["signed_today"]:
                    entry["action"] = "skip_already_signed"
                    results.append(entry)
                    if not args.json:
                        log.info(f"[{key}] 今日已签到，跳过。✅")
                    continue

                if not args.json:
                    log.info(f"[{key}] 执行签到……")
                signed = submit_signin(base, cookie, args.timeout)
                sd = pick_scene(signed, "daily_sign_in")
                entry.update({
                    "action": "checked_in",
                    "result": sd.get("sign_in_result"),
                    "signed_days": sd.get("signed_days") or entry.get("signed_days"),
                    "total_signed_days": (sd.get("total_signed_days")
                                          or entry.get("total_signed_days")),
                })
                results.append(entry)
                if not args.json:
                    log.info(
                        f"[{key}] 签到完成：{entry['result']}（连续 "
                        f"{entry['signed_days']} 天，累计 {entry['total_signed_days']} 天）✅")
            except RuntimeError as e:
                entry["action"] = "error"
                entry["msg"] = str(e)
                results.append(entry)
                errors.append({"site": key, "msg": str(e)})
                if not args.json:
                    log.err(f"[{key}] {e}")

        if args.json:
            emit({"status": "error" if errors and len(errors) == len(results) else "ok",
                  "dry_run": args.dry_run, "results": results})
        else:
            ok = [r for r in results if r.get("action") != "error"]
            log.info(f"完成：{len(ok)}/{len(results)} 个站点成功。")

        if errors and len(errors) == len(results):
            return 2
        if not results:
            log.err("没有可执行的目标站点。")
            return 1
        return 0

    except RuntimeError as e:
        if args.json:
            emit({"status": "error", "msg": str(e)})
        else:
            log.err(str(e))
        return 1 if _is_config_error(str(e)) else 2
    except Exception as e:  # noqa: BLE001
        if args.json:
            emit({"status": "error", "msg": f"未知异常: {e}"})
        else:
            log.err(f"未知异常: {e}")
        return 3


def _is_config_error(msg):
    for kw in ("tabbit-cli", "Cookie", "登录", "未找到"):
        if kw in msg:
            return True
    return False


if __name__ == "__main__":
    sys.exit(main())
