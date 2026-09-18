#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WorkBuddy 每日自动签到脚本（单文件版）
=====================================

通过读取本机 WorkBuddy 登录态中的 accessToken，调用官方接口完成每日签到领积分。
- 仅用 Python 标准库，无任何第三方依赖。
- 单次运行：命令行直接执行即可，适合用 cron / 计划任务 / launchd 定时调用。
- 幂等安全：先查询今日是否已签到，已签则跳过，绝不重复签。
- 失败重试：网络抖动 / 5xx 自动指数退避重试；401/403 登录态失效立即明确报错，不重试。
- 输出干净：--json 时 stdout 只有一行 JSON，所有日志一律走 stderr，可安全 `| jq`。
- 跨平台自动定位登录态文件；也支持环境变量 / 命令行参数传入 token。

用法示例
--------
    python workbuddy_checkin.py                # 执行签到（已签则跳过）
    python workbuddy_checkin.py --dry-run      # 只看今日状态，不签到
    python workbuddy_checkin.py --gift         # （可选）领取「今日礼包」，已签也照领
    python workbuddy_checkin.py --json         # 仅输出机器可读 JSON（stdout）
    python workbuddy_checkin.py --retries 0    # 关闭重试（排障用）
    WORKBUDDY_ACCESS_TOKEN=xxx python workbuddy_checkin.py

退出码
------
    0  成功（含「今日已签到」跳过）
    1  参数 / 环境 / 登录态错误（找不到 token、token 已失效等）
    2  网络 / 接口错误
    3  未知异常
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

# ----------------------------- 配置 -----------------------------
DEFAULT_BASE_URL = "https://www.workbuddy.cn"
STATUS_PATH = "/v2/billing/meter/checkin-activity-status"
CHECKIN_PATH = "/v2/billing/meter/daily-checkin"
GIFT_PATH = "/billing/meter/claim-gift"

USER_AGENT = "workbuddy-checkin-script/1.1"

# 失败重试：仅对网络层失败与 5xx 生效（4xx / 登录态错误不重试）
DEFAULT_RETRIES = 3
RETRY_BACKOFF_SECONDS = (1.0, 3.0, 5.0)

# 登录态文件候选路径（跨平台），内含 accessToken
TOKEN_FILE_CANDIDATES = [
    # macOS
    "~/Library/Application Support/CodeBuddyExtension/Data/Public/auth/workbuddy-desktop.info",
    "~/Library/Application Support/WorkBuddyExtension/Data/Public/auth/workbuddy-desktop.info",
    # Windows
    r"%LOCALAPPDATA%\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info",
    r"%LOCALAPPDATA%\WorkBuddyExtension\Data\Public\auth\workbuddy-desktop.info",
    # Linux / 通用
    "~/.workbuddy/auth/workbuddy-desktop.info",
    "~/.config/CodeBuddyExtension/Data/Public/auth/workbuddy-desktop.info",
]


# ----------------------------- 错误类型 -----------------------------
class CheckinError(RuntimeError):
    """脚本内可预期的错误基类，携带退出码与修复建议。"""

    exit_code = 2

    def __init__(self, message, hint=None):
        super().__init__(message)
        self.hint = hint


class AuthError(CheckinError):
    """登录态无效 / 已过期（token 相关），属环境错误。"""

    exit_code = 1


class ApiError(CheckinError):
    """接口返回业务错误 / 非预期响应。"""

    exit_code = 2


class NetworkError(CheckinError):
    """网络层失败（重试耗尽后）。"""

    exit_code = 2


# ----------------------------- 日志 -----------------------------
class Log:
    """日志一律写 stderr；json 模式下更严格，保证 stdout 只承载结果数据。"""

    def __init__(self, quiet=False, json_mode=False):
        self.quiet = quiet
        self.json_mode = json_mode

    def _stream(self):
        # 非 json 模式保持 INFO 走 stdout（便于人工阅读 / 管道分类）
        # json 模式强制走 stderr，避免污染机器可读输出
        return sys.stderr if self.json_mode else sys.stdout

    def info(self, msg):
        if not self.quiet:
            print(f"[INFO] {msg}", file=self._stream())

    def warn(self, msg):
        if not self.quiet:
            print(f"[WARN] {msg}", file=sys.stderr)

    def err(self, msg):
        print(f"[ERROR] {msg}", file=sys.stderr)


# ----------------------------- 工具 -----------------------------
def _pretty(path):
    """把 $HOME 前缀折叠成 ~，日志更短。"""
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path.startswith(home) else path


def find_token(args, log: Log):
    """按优先级获取 accessToken：命令行 > 环境变量 > 指定文件 > 自动定位。

    自动定位会依次尝试候选路径；某个候选文件存在但取不到 token（例如登录态
    结构变更）时会告警并继续尝试下一个，而不是拿垃圾字符串去发请求。
    """
    # 1. 命令行 --token
    if getattr(args, "token", None):
        return args.token.strip()
    # 2. 环境变量
    env_tok = os.environ.get("WORKBUDDY_ACCESS_TOKEN")
    if env_tok:
        return env_tok.strip()
    # 3. 指定文件
    if getattr(args, "token_file", None):
        return read_token_file(args.token_file, log)
    # 4. 自动定位
    for cand in TOKEN_FILE_CANDIDATES:
        path = os.path.expandvars(os.path.expanduser(cand))
        if not os.path.isfile(path):
            continue
        log.info(f"自动定位到登录态文件：{_pretty(path)}")
        tok = read_token_file(path, log)
        if tok:
            return tok
    return None


def read_token_file(path, log: Log):
    """从登录态文件读取 accessToken；兼容 JSON 结构与纯 token 文本。

    注意：JSON 解析成功但没有 accessToken 字段时**不会**退回「把整段 JSON 当
    token」，而是返回 None（该候选路径视为无效），避免把垃圾字符串发到服务端。
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
    except OSError as e:
        log.warn(f"无法读取文件 {path}: {e}")
        return None
    if not content:
        return None

    if content.startswith("{"):
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            log.warn(f"{_pretty(path)} 是 JSON 但解析失败（{e}），已跳过")
            return None
        if not isinstance(data, dict):
            log.warn(f"{_pretty(path)} 顶层不是 JSON 对象，已跳过")
            return None
        tok = None
        auth = data.get("auth")
        if isinstance(auth, dict):
            tok = auth.get("accessToken")
        if not tok:
            tok = data.get("accessToken")
        if isinstance(tok, str) and tok.strip():
            return tok.strip()
        log.warn(f"{_pretty(path)} 中未找到 auth.accessToken（登录态结构可能已变更），已跳过")
        return None

    # 否则当作纯 token（取第一行）
    lines = content.splitlines()
    first = lines[0].strip() if lines else ""
    return first or None


def _sleep_before_retry(attempt, log: Log, reason):
    delay = RETRY_BACKOFF_SECONDS[min(attempt, len(RETRY_BACKOFF_SECONDS) - 1)]
    log.warn(f"{reason}；{delay:g}s 后重试（第 {attempt + 1} 次）")
    time.sleep(delay)


def _parse_body(raw, http_code, url):
    """解析响应体；非 JSON / 结构异常时抛出带原文片段的 ApiError。"""
    if not raw:
        return {}
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        snippet = " ".join(raw.split())[:200]
        raise ApiError(
            f"接口返回非 JSON 响应（HTTP {http_code}，{url}）: {snippet}",
            hint="若为 401/403 或 HTML 页面，通常是登录态失效或域名被网关拦截。",
        ) from None
    if not isinstance(body, dict):
        raise ApiError(f"接口响应结构异常（HTTP {http_code}，顶层 {type(body).__name__}）")
    return body


def http_post(base_url, path, token, timeout, log: Log, retries=DEFAULT_RETRIES):
    """发送 POST 请求，返回 (http_code, body_dict)。

    - 401/403 → 立即抛 AuthError（登录态问题，重试无意义）
    - 网络失败 / 5xx → 指数退避重试，最多 retries 次
    - 其余 4xx → 原样返回响应体，交给业务层判断（例如「已签到」是 HTTP 400）
    """
    url = base_url.rstrip("/") + path
    last_reason = None

    for attempt in range(max(retries, 0) + 1):
        req = urllib.request.Request(
            url,
            data=b"{}",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                http_code = resp.getcode()
                raw = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            http_code = e.code
            try:
                raw = e.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                raw = ""
            if http_code in (401, 403):
                raise AuthError(
                    f"登录态已失效（HTTP {http_code}）",
                    hint="请打开 WorkBuddy 客户端确认已登录，让客户端刷新 token 后重跑本脚本。",
                ) from e
            if http_code >= 500 and attempt < retries:
                last_reason = f"服务端返回 HTTP {http_code}"
                _sleep_before_retry(attempt, log, last_reason)
                continue
        except urllib.error.URLError as e:
            last_reason = f"网络请求失败: {e.reason}"
            if attempt < retries:
                _sleep_before_retry(attempt, log, last_reason)
                continue
            raise NetworkError(last_reason, hint="请检查本机网络 / 代理设置。") from e
        except (TimeoutError, OSError) as e:
            last_reason = f"请求超时或连接异常: {e}"
            if attempt < retries:
                _sleep_before_retry(attempt, log, last_reason)
                continue
            raise NetworkError(last_reason) from e
        except Exception as e:  # noqa: BLE001
            raise NetworkError(f"请求异常: {e}") from e

        return http_code, _parse_body(raw, http_code, url)

    raise NetworkError(last_reason or "网络请求失败", hint="已重试全部次数仍失败。")


def _status_data(token, base_url, timeout, log: Log, retries):
    """查询今日签到状态，返回 data 字典。"""
    http_code, body = http_post(base_url, STATUS_PATH, token, timeout, log, retries)
    if body.get("code") != 0:
        raise ApiError(
            f"状态查询失败: HTTP {http_code} code={body.get('code')} msg={body.get('msg')}"
        )
    data = body.get("data")
    return data if isinstance(data, dict) else {}


def _pick_points(data):
    """签到/礼包响应里积分字段名历史上不稳定，按优先级取值。"""
    if not isinstance(data, dict):
        return None
    for key in ("today_credit", "credit", "points", "add_credit"):
        val = data.get(key)
        if isinstance(val, (int, float)) and val != 0:
            return val
    return None


def do_checkin(token, base_url, timeout, log: Log, retries):
    """执行签到，返回结果字典。"""
    http_code, body = http_post(base_url, CHECKIN_PATH, token, timeout, log, retries)
    code = body.get("code")
    msg = body.get("msg", "") or ""
    if code == 0:
        return {
            "action": "checked_in",
            "ok": True,
            "points": _pick_points(body.get("data")),
            "msg": msg or "OK",
        }
    if code == 10001 or "已签到" in msg:
        return {"action": "already_signed", "ok": True, "points": None,
                "msg": msg or "今天已签到"}
    raise ApiError(f"签到失败: HTTP {http_code} code={code} msg={msg}")


def do_claim_gift(token, base_url, timeout, log: Log, retries):
    """（可选）领取今日礼包。已领取视为成功，不影响主流程退出码。"""
    http_code, body = http_post(base_url, GIFT_PATH, token, timeout, log, retries)
    code = body.get("code")
    msg = body.get("msg", "") or ""
    if code == 0:
        return {"ok": True, "points": _pick_points(body.get("data")),
                "msg": msg or "OK"}
    # 幂等：已领取不算失败。不复用签到接口的 10001，只认语义关键字。
    if "已领" in msg or "领过" in msg:
        return {"ok": True, "points": None, "msg": msg or "今日礼包已领取"}
    return {"ok": False, "points": None,
            "msg": f"HTTP {http_code} code={code} msg={msg}"}


# ----------------------------- 输出 -----------------------------
def _emit(payload, args, log: Log):
    """统一输出：json 模式只往 stdout 写一行 JSON。"""
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    return payload


def _fail(msg, args, log: Log, hint=None, exit_code=2):
    if args.json:
        payload = {"status": "error", "msg": msg}
        if hint:
            payload["hint"] = hint
        print(json.dumps(payload, ensure_ascii=False))
    else:
        log.err(msg)
        if hint:
            log.err(f"      建议：{hint}")
    return exit_code


def _claim_gift(result, args, log: Log, token):
    """把礼包结果并入 result；礼包失败不改变主流程退出码，但一定会被报告出来。"""
    try:
        g = do_claim_gift(token, args.base_url, args.timeout, log, args.retries)
    except CheckinError as e:
        g = {"ok": False, "points": None, "msg": str(e)}
    except Exception as e:  # noqa: BLE001
        g = {"ok": False, "points": None, "msg": f"未知异常: {e}"}
    result["gift"] = g
    if not args.json:
        if g["ok"]:
            pts = f"，+{g['points']} 积分" if g.get("points") else ""
            log.info(f"今日礼包：{g['msg']}{pts}")
        else:
            log.warn(f"今日礼包领取失败（不影响签到）：{g['msg']}")
    return g


# ----------------------------- 主流程 -----------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(
        description="WorkBuddy 每日自动签到脚本（单文件版）"
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL,
                        help=f"API 域名（默认 {DEFAULT_BASE_URL}）")
    parser.add_argument("--token", help="直接传入 accessToken")
    parser.add_argument("--token-file", help="包含 accessToken 的文件路径")
    parser.add_argument("--dry-run", action="store_true",
                        help="只查询今日状态，不执行签到")
    parser.add_argument("--gift", action="store_true",
                        help="顺带领取「今日礼包」（今日已签到也会尝试领取）")
    parser.add_argument("--json", action="store_true",
                        help="仅输出机器可读 JSON 结果（stdout）")
    parser.add_argument("--quiet", "-q", action="store_true", help="静默模式")
    parser.add_argument("--timeout", type=int, default=15, help="请求超时(秒)")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                        help=f"网络失败/5xx 重试次数（默认 {DEFAULT_RETRIES}，0 表示不重试）")
    args = parser.parse_args(argv)

    log = Log(quiet=args.quiet, json_mode=args.json)

    # 获取 token
    token = find_token(args, log)
    if not token:
        return _fail(
            "未找到 accessToken",
            args, log,
            hint="请确认 WorkBuddy 客户端已登录，或用 --token / --token-file / "
                 "环境变量 WORKBUDDY_ACCESS_TOKEN 指定。",
            exit_code=1,
        )

    try:
        # 1) 查询状态
        status = _status_data(token, args.base_url, args.timeout, log, args.retries)
        today_signed = bool(status.get("today_checked_in"))
        summary = {
            "today_checked_in": today_signed,
            "streak_days": status.get("streak_days"),
            "today_credit": status.get("today_credit"),
            "total_credits": status.get("total_credits"),
            "theme_name": status.get("theme_name"),
            "activity_name": status.get("activity_name"),
        }
        if not args.json:
            log.info(f"主题：{summary['theme_name']} / {summary['activity_name']}")
            log.info(f"今日是否已签到：{today_signed}　连续天数：{summary['streak_days']}　"
                     f"今日积分：{summary['today_credit']}　累计：{summary['total_credits']}")

        if args.dry_run:
            if not args.json:
                log.info("仅预览模式，未执行签到。")
            _emit({"status": "ok", "action": "dry_run", **summary}, args, log)
            return 0

        # 2) 今日已签到 → 不重复签，但 --gift 仍照领
        if today_signed:
            result = {"status": "ok", "action": "skip_already_signed",
                      "msg": "今日已签到，无需重复操作", **summary}
            if args.gift:
                _claim_gift(result, args, log, token)
            if not args.json:
                log.info("今日已签到，无需重复操作。✅")
            _emit(result, args, log)
            return 0

        # 3) 执行签到
        log.info("执行每日签到……")
        ck = do_checkin(token, args.base_url, args.timeout, log, args.retries)
        if not ck["ok"]:
            return _fail(ck.get("msg", "签到失败"), args, log, exit_code=2)

        # 签到后重新查询，拿到最新连签/积分（只在字段有效时覆盖，避免抹成 null）
        try:
            latest = _status_data(token, args.base_url, args.timeout, log, args.retries)
            for key in ("streak_days", "today_credit", "total_credits"):
                val = latest.get(key)
                if val is not None:
                    summary[key] = val
            # 只做「升级」不做「降级」：签到接口已返回成功，不因回查延迟把它翻回 false
            if latest.get("today_checked_in"):
                summary["today_checked_in"] = True
            if latest.get("theme_name"):
                summary["theme_name"] = latest["theme_name"]
            if latest.get("activity_name"):
                summary["activity_name"] = latest["activity_name"]
        except CheckinError as e:
            log.warn(f"签到后状态回查失败（不影响本次签到）: {e}")

        result = {"status": "ok", "action": ck["action"],
                  "points": ck.get("points"), "msg": ck.get("msg"), **summary}

        # 4) （可选）领取礼包
        if args.gift:
            _claim_gift(result, args, log, token)

        if args.json:
            _emit(result, args, log)
        else:
            pts = f"（+{ck['points']} 积分）" if ck.get("points") else ""
            log.info(f"签到成功{pts}！连续 {summary['streak_days']} 天，"
                     f"累计 {summary['total_credits']} 积分。✅")
        return 0

    except CheckinError as e:
        return _fail(str(e), args, log, hint=getattr(e, "hint", None),
                     exit_code=e.exit_code)
    except Exception as e:  # noqa: BLE001
        return _fail(f"未知异常: {e}", args, log, exit_code=3)


if __name__ == "__main__":
    sys.exit(main())
