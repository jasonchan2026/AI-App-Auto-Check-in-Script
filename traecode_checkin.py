#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TraeCode（Trae CN 桌面端 IDE）每日自动签到脚本（单文件版）

TraeCode 与 TraeWork（TRAE SOLO CN）共用同一套增长服务与账号积分：
接口路径一致，仅请求体 req_source 不同（1=TraeCode / 2=TraeWork）。
同一账号每日只需签到一次，两端状态共享，接口幂等。

原理
----
1. 从本机 Trae CN 客户端的 storage.json 中读取 iCubeAuthInfo 加密凭证；
2. 按 byteCrypto 信封算法（AES-128-CBC + SHA-512 完整性校验）解密出 token；
   密钥表从本机安装的 Trae CN.app 内 out/main.js 动态提取，随版本自适应；
3. 携带 Cloud-IDE-JWT 调用官方签到接口：先查状态，未签到则领取，幂等安全。

特点
----
- 仅依赖 Python 标准库 + pycryptodome（AES 实现）
- 不重启、不操控客户端 UI，纯 API 调用，签到在客户端关闭时也能完成
- 幂等：claim 接口对已签到账号同样返回 code=0；网络异常 / 5xx 自动重试
- 支持 --dry-run 预览、--json 机器可读输出（日志走 stderr，不污染 JSON），
  适合 cron / launchd 定时运行

用法示例
--------
    python3 traecode_checkin.py                # 执行签到（已签则跳过）
    python3 traecode_checkin.py --dry-run      # 只看今日状态，不签到
    python3 traecode_checkin.py --json         # 仅输出机器可读 JSON

依赖安装
--------
    pip3 install pycryptodome

退出码
------
    0  成功（含「今日已签到」）
    1  配置 / 环境 / 登录态错误（找不到客户端、解密失败、401/403 等）
    2  网络 / 接口错误
    3  未知异常
"""

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import sys
import time
import urllib.error
import urllib.request

try:
    from Crypto.Cipher import AES
except ImportError:
    print("[ERROR] 缺少依赖 pycryptodome，请执行: pip3 install pycryptodome",
          file=sys.stderr)
    sys.exit(1)

# ----------------------------- 配置 -----------------------------
DEFAULT_UG_HOST = "https://api.trae.cn"
CHECKIN_STATUS_PATH = "/trae/api/v2/ug/checkin_credits/status"
CHECKIN_CLAIM_PATH = "/trae/api/v2/ug/checkin_credits/claim"

# req_source: 1=TraeCode（IDE），2=TraeWork（逆向自客户端 main.js）
REQ_SOURCE_CODE = 1
REQ_SOURCE_WORK = 2

# storage.json 候选路径（macOS / Windows）
STORAGE_CANDIDATES = [
    "~/Library/Application Support/Trae CN/User/globalStorage/storage.json",
    r"%APPDATA%\Trae CN\User\globalStorage\storage.json",
]
# 客户端主程序 main.js 候选路径（用于提取密钥表，随版本自适应）
MAINJS_CANDIDATES = [
    "/Applications/Trae CN.app/Contents/Resources/app/out/main.js",
    "~/Applications/Trae CN.app/Contents/Resources/app/out/main.js",
    r"C:\Program Files\Trae CN\resources\app\out\main.js",
    r"C:\Program Files (x86)\Trae CN\resources\app\out\main.js",
]
# 客户端 package.json（读取版本号用于拟真请求头，可选）
PACKAGEJSON_CANDIDATES = [
    "/Applications/Trae CN.app/Contents/Resources/app/package.json",
    "~/Applications/Trae CN.app/Contents/Resources/app/package.json",
    r"C:\Program Files\Trae CN\resources\app\package.json",
    r"C:\Program Files (x86)\Trae CN\resources\app\package.json",
]

BYTECRYPTO_MARKER = "out-build/vs/base/common/byteCrypto.js"
ENVELOPE_HEADER = bytes([116, 99, 5, 16, 0, 0])  # b"tc\x05\x10\x00\x00"

USER_AGENT = "traecode-checkin-script/1.0"


# ----------------------------- 错误类型 -----------------------------
class CheckinError(Exception):
    """带退出码与提示的业务异常"""

    def __init__(self, message, exit_code=2, hint=None):
        super().__init__(message)
        self.exit_code = exit_code
        self.hint = hint


class Log:
    def __init__(self, json_mode=False, quiet=False):
        # --json 时所有日志强制走 stderr，保证 stdout 只有一行 JSON
        self.json_mode = json_mode
        self.quiet = quiet

    def _ts(self):
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def info(self, msg):
        if self.quiet:
            return
        stream = sys.stderr if self.json_mode else sys.stdout
        print(f"[{self._ts()}] [INFO] {msg}", file=stream)

    def warn(self, msg):
        if self.quiet:
            return
        print(f"[{self._ts()}] [WARN] {msg}", file=sys.stderr)

    def err(self, msg):
        print(f"[{self._ts()}] [ERROR] {msg}", file=sys.stderr)


# ----------------------------- 凭证定位与解密 -----------------------------
def expand_path(cand):
    return os.path.expandvars(os.path.expanduser(cand))


def first_existing(candidates):
    for cand in candidates:
        path = expand_path(cand)
        if os.path.isfile(path):
            return path
    return None


def extract_pepper(main_js_path: str, log: Log):
    """从客户端 out/main.js 中提取两张 64 字节硬编码表并异或，得到 pepper。

    表位于 byteCrypto 模块代码内，紧随模块标记之后；逐版本名称可能变化，
    但「模块标记 + 4 张 64 字节数组」的结构稳定，取最后两张（Vie/Qie）。
    """
    try:
        src = open(main_js_path, "r", encoding="utf-8", errors="replace").read()
    except OSError as e:
        raise CheckinError(f"读取 main.js 失败: {e}", exit_code=1,
                           hint="请确认 Trae CN 客户端已正确安装")
    marker = src.find(BYTECRYPTO_MARKER)
    if marker < 0:
        raise CheckinError(
            f"main.js 中未找到 byteCrypto 模块标记: {main_js_path}",
            exit_code=1, hint="客户端版本可能过新或过旧，脚本需适配")
    region = src[marker:marker + 20000]
    tables = []
    for m in re.finditer(
            r"(?:new\s+Uint8Array|Uint8Array\.from)\(\s*\[\s*([0-9\s*,]+?)\s*\]\s*\)",
            region):
        nums = [int(x) for x in m.group(1).split(",") if x.strip()]
        if len(nums) >= 64:
            tables.append(bytes(nums[:64]))
    if len(tables) < 4:
        raise CheckinError(
            f"main.js 中仅找到 {len(tables)} 张 64 字节表（需 4 张），版本可能不兼容",
            exit_code=1, hint="客户端升级改变了 byteCrypto 结构，脚本需适配")
    log.info("已从客户端 main.js 提取密钥表")
    vie, qie = tables[-2], tables[-1]
    return bytes(v ^ q for v, q in zip(vie, qie))


def bytecrypto_decrypt(b64_blob: str, pepper: bytes) -> str:
    """解密 TRAE byteCrypto 信封（AES 模式）。

    格式: 6 字节头 + 32 字节 random + AES-128-CBC(SHA512(plain) || plain)
    密钥派生: key/iv = SHA512(SHA512(random) || pepper) || pepper 的前 32 字节
    """
    try:
        raw = base64.b64decode(b64_blob)
    except Exception as e:
        raise CheckinError(f"凭证 base64 解码失败: {e}", exit_code=1)
    if raw[:6] != ENVELOPE_HEADER:
        raise CheckinError(
            f"未知的凭证信封头: {raw[:6].hex()}（可能不是 Trae CN 的登录态）",
            exit_code=1)
    rnd, ct = raw[6:38], raw[38:]
    digest = hashlib.sha512
    mat = digest(digest(rnd).digest() + pepper).digest() + pepper
    key, iv = mat[:16], mat[16:32]
    padded = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    pad_len = padded[-1]
    if not 1 <= pad_len <= 16:
        raise CheckinError("AES 解密填充非法，密钥表可能不匹配", exit_code=1)
    body = padded[:-pad_len]
    tag, plain = body[:64], body[64:]
    if digest(plain).digest() != tag:
        raise CheckinError("SHA-512 完整性校验失败，凭证已损坏或密钥表不匹配",
                           exit_code=1)
    return plain.decode("utf-8")


def read_app_version(log: Log):
    """尽力读取客户端版本号（用于 x-app-version 请求头），失败返回 None"""
    pkg = first_existing(PACKAGEJSON_CANDIDATES)
    if not pkg:
        return None
    try:
        with open(pkg, "r", encoding="utf-8") as f:
            ver = json.load(f).get("version")
            if isinstance(ver, str) and re.fullmatch(r"[0-9][0-9A-Za-z.\-]*", ver):
                return ver
    except Exception:
        return None
    return None


def _parse_iso_utc(s):
    """解析 ISO 8601 UTC 时间（如 2026-09-23T13:36:19.506Z）为 epoch 秒，失败返回 None"""
    try:
        from datetime import datetime, timezone
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(
            timezone.utc).timestamp()
    except (ValueError, TypeError):
        return None


def load_credentials(log: Log):
    """定位并解密 storage.json，返回凭证字典与设备 ID"""
    storage_path = first_existing(STORAGE_CANDIDATES)
    if not storage_path:
        raise CheckinError(
            "未找到 Trae CN 客户端 storage.json，请确认 TraeCode（Trae CN）已安装并登录过",
            exit_code=1,
            hint="默认路径: ~/Library/Application Support/Trae CN/User/globalStorage/storage.json")
    log.info(f"找到客户端存储: {storage_path}")

    main_js = first_existing(MAINJS_CANDIDATES)
    if not main_js:
        raise CheckinError("未找到客户端 out/main.js，无法提取密钥表", exit_code=1,
                           hint="可用 --mainjs 手动指定路径")
    pepper = extract_pepper(main_js, log)

    try:
        with open(storage_path, "r", encoding="utf-8") as f:
            storage = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise CheckinError(f"storage.json 读取/解析失败: {e}", exit_code=1,
                           hint="客户端可能正在写入或登录态已损坏，请重新登录")

    if not isinstance(storage, dict):
        raise CheckinError("storage.json 顶层结构不是对象，版本可能不兼容",
                           exit_code=1)

    blob = storage.get("iCubeAuthInfo://icube.cloudide")
    if not blob or not isinstance(blob, str):
        raise CheckinError(
            "storage.json 中无 iCubeAuthInfo 凭证，请先在 TraeCode 客户端登录",
            exit_code=1)

    try:
        creds = json.loads(bytecrypto_decrypt(blob, pepper))
    except json.JSONDecodeError as e:
        raise CheckinError(f"凭证解密成功但内容不是合法 JSON: {e}", exit_code=1)

    token = creds.get("token")
    if not token or not isinstance(token, str):
        raise CheckinError("解密结果中缺少 token 字段，请在客户端重新登录后重试",
                           exit_code=1)

    device_id = None
    for k in storage:
        if isinstance(k, str) and k.startswith("iCubeAuthInfo://icube-dc:"):
            device_id = k.split(":")[-1]
            break
    if not device_id:
        raise CheckinError("storage.json 中无设备 ID（icube-dc）", exit_code=1)

    # 客户端前置校验：仅 CN provider + marscode scope 账号可签到
    account = creds.get("account")
    scope = account.get("scope") if isinstance(account, dict) else None
    if scope and scope != "marscode":
        raise CheckinError(
            f"当前账号 scope={scope}，TraeCode 签到仅支持国内 marscode 账号",
            exit_code=1)

    expired_at = creds.get("expiredAt")
    if isinstance(expired_at, str) and expired_at:
        exp = _parse_iso_utc(expired_at)
        if exp is not None and exp <= time.time():
            raise CheckinError(
                f"token 已于 {expired_at} 过期，请在 TraeCode 客户端重新登录后重试",
                exit_code=1)
    log.info(f"凭证解密成功，token 过期时间: {expired_at or '未知'}")
    return creds, token, device_id, storage_path


# ----------------------------- 签到接口 -----------------------------
def parse_body(raw):
    """解析响应体；非 JSON / 顶层非对象时抛出带原文片段的接口错误"""
    if not raw:
        raise CheckinError("服务端返回空响应", exit_code=2)
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        snippet = raw[:200].replace("\n", " ")
        raise CheckinError(
            f"服务端返回了非 JSON 响应（可能是网关错误页）: {snippet!r}",
            exit_code=2)
    if not isinstance(body, dict):
        raise CheckinError(f"服务端响应顶层不是对象: {type(body).__name__}",
                           exit_code=2)
    return body


def post_ug(host, path, token, device_id, req_source, app_version,
            timeout, retries, log: Log):
    """调用增长类接口（Cloud-IDE-JWT 鉴权）。

    - 401/403：登录态失效，不重试（退出码 1）
    - 其他 4xx：业务/参数错误，不重试（退出码 2）
    - 5xx 与网络层异常：指数退避重试
    """
    url = host.rstrip("/") + path
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Cloud-IDE-JWT {token}",
        "x-device-id": device_id,
        "User-Agent": USER_AGENT,
    }
    # 拟真客户端的可选设备头（缺失不影响接口）
    headers["x-device-type"] = platform.system().lower()  # darwin / windows
    if app_version:
        headers["x-app-version"] = app_version

    data = json.dumps({"req_source": req_source}).encode("utf-8")
    last_err = None
    for attempt in range(1, max(1, retries) + 1):
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code = resp.getcode()
                raw = resp.read().decode("utf-8", "replace")
                return code, parse_body(raw)
        except urllib.error.HTTPError as e:
            raw = ""
            try:
                raw = e.read().decode("utf-8", "replace")
            except Exception:
                pass
            if e.code in (401, 403):
                snippet = raw[:200].replace("\n", " ")
                raise CheckinError(
                    f"鉴权失败 HTTP {e.code}，登录态已失效或 token 过期，请在客户端重新登录"
                    + (f"（响应片段: {snippet!r}）" if snippet else ""),
                    exit_code=1)
            if 400 <= e.code < 500:
                # 4xx 一律不重试；尽量解析业务码
                try:
                    return e.code, parse_body(raw)
                except CheckinError:
                    raise CheckinError(f"接口返回 HTTP {e.code}: {raw[:200]!r}",
                                       exit_code=2)
            last_err = f"HTTP {e.code}: {raw[:200]}"
            if attempt < retries:
                wait = min(2 ** attempt, 10)
                log.warn(f"服务端 {e.code}（第 {attempt}/{retries} 次），{wait}s 后重试")
                time.sleep(wait)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_err = str(e)
            if attempt < retries:
                wait = min(2 ** attempt, 10)
                log.warn(f"网络异常（第 {attempt}/{retries} 次）：{e}，{wait}s 后重试")
                time.sleep(wait)
    raise CheckinError(f"网络请求失败（已尝试 {retries} 次）: {last_err}",
                       exit_code=2)


def get_checkin_status(host, token, device_id, req_source, app_version,
                       timeout, retries, log: Log):
    http_code, body = post_ug(host, CHECKIN_STATUS_PATH, token, device_id,
                              req_source, app_version, timeout, retries, log)
    if body.get("code") != 0:
        raise CheckinError(
            f"状态查询失败: HTTP {http_code} code={body.get('code')} "
            f"msg={body.get('message')}", exit_code=2)
    enable = body.get("enable")
    checked_in = body.get("checked_in")
    if not isinstance(enable, bool):
        raise CheckinError(
            f"状态响应字段缺失或类型异常: enable={enable!r}", exit_code=2)
    # 活动未开启时服务端可能不下发 checked_in，此时交给主流程报「未开启」
    if enable and not isinstance(checked_in, bool):
        raise CheckinError(
            f"状态响应字段缺失或类型异常: checked_in={checked_in!r}", exit_code=2)
    return {
        "enable": enable,
        "checked_in": bool(checked_in),
        "did_checked_in": body.get("did_checked_in"),
        "credits": body.get("credits"),
        "extra_credits": body.get("extra_credits"),
    }


def do_claim(host, token, device_id, req_source, app_version,
             timeout, retries, log: Log):
    """领取签到积分。接口幂等：已签到再调同样返回 code=0。"""
    http_code, body = post_ug(host, CHECKIN_CLAIM_PATH, token, device_id,
                              req_source, app_version, timeout, retries, log)
    if body.get("code") == 0:
        return {"ok": True, "msg": body.get("message") or "OK"}
    # 兼容「已签到 / 已领取」语义（当前后端返回 code=0，此处为防御性处理）
    msg = str(body.get("message") or "")
    if body.get("code") in (10001,) or "已签到" in msg or "已领取" in msg:
        return {"ok": True, "already": True, "msg": msg}
    raise CheckinError(
        f"签到失败: HTTP {http_code} code={body.get('code')} msg={msg}",
        exit_code=2)


# ----------------------------- 主流程 -----------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(
        description="TraeCode（Trae CN IDE）每日自动签到脚本（单文件版）")
    parser.add_argument("--host",
                        help=f"API 域名（默认取凭证内 host，回退 {DEFAULT_UG_HOST}）")
    parser.add_argument("--storage", help="指定 storage.json 路径（默认自动定位）")
    parser.add_argument("--mainjs", help="指定客户端 out/main.js 路径（默认自动定位）")
    parser.add_argument("--req-source", type=int, default=REQ_SOURCE_CODE,
                        choices=[REQ_SOURCE_CODE, REQ_SOURCE_WORK],
                        help="请求来源：1=TraeCode（默认），2=TraeWork")
    parser.add_argument("--dry-run", action="store_true",
                        help="只查询今日签到状态，不执行签到")
    parser.add_argument("--retries", type=int, default=3,
                        help="网络异常 / 5xx 自动重试次数（默认 3，0 关闭）")
    parser.add_argument("--timeout", type=int, default=15, help="请求超时（秒）")
    parser.add_argument("--json", action="store_true", help="仅输出机器可读 JSON")
    parser.add_argument("--quiet", "-q", action="store_true", help="静默模式")
    args = parser.parse_args(argv)

    log = Log(json_mode=args.json, quiet=args.quiet)
    retries = max(1, args.retries)

    def emit(payload):
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))

    try:
        if args.storage:
            args.storage = expand_path(args.storage)
            if not os.path.isfile(args.storage):
                raise CheckinError(f"指定的 storage.json 不存在: {args.storage}",
                                   exit_code=1)
            STORAGE_CANDIDATES.insert(0, args.storage)
        if args.mainjs:
            args.mainjs = expand_path(args.mainjs)
            if not os.path.isfile(args.mainjs):
                raise CheckinError(f"指定的 main.js 不存在: {args.mainjs}",
                                   exit_code=1)
            MAINJS_CANDIDATES.insert(0, args.mainjs)

        creds, token, device_id, _ = load_credentials(log)
        host = args.host or creds.get("host") or DEFAULT_UG_HOST
        if not isinstance(host, str) or not host.startswith("http"):
            host = DEFAULT_UG_HOST
        app_version = read_app_version(log)

        status = get_checkin_status(host, token, device_id, args.req_source,
                                    app_version, args.timeout, retries, log)
        if not status["enable"]:
            msg = "签到活动未开启或当前账号不支持签到"
            emit({"status": "error", "exit_code": 1, "msg": msg})
            if not args.json:
                log.err(msg)
            return 1
        if not args.json:
            extra = (f"（含额外 {status['extra_credits']}）"
                     if isinstance(status["extra_credits"], int)
                     and status["extra_credits"] > 0 else "")
            log.info(
                f"今日已签到: {status['checked_in']}　每日积分: "
                f"{status['credits']}{extra}")

        if args.dry_run:
            emit({"status": "ok", "action": "dry_run", **status})
            if not args.json:
                log.info("预览模式，未执行签到。")
            return 0

        if status["checked_in"]:
            emit({"status": "ok", "action": "skip_already_signed",
                  "msg": "今日已签到，无需重复操作", **status})
            if not args.json:
                log.info("今日已签到，无需重复操作。✅")
            return 0

        if not args.json:
            log.info("执行每日签到……")
        result = do_claim(host, token, device_id, args.req_source, app_version,
                          args.timeout, retries, log)

        # 回查确认（只升级不覆盖：回查异常不影响成功结论）
        try:
            after = get_checkin_status(host, token, device_id, args.req_source,
                                       app_version, args.timeout, retries, log)
            result["checked_in_after"] = after["checked_in"]
            if isinstance(after["credits"], int):
                result["credits"] = after["credits"]
        except Exception as e:
            log.warn(f"签到后回查失败（不影响签到结果）: {e}")

        emit({"status": "ok", "action": "checked_in", **result})
        if not args.json:
            pts = f"，每日积分 {result['credits']}" if result.get("credits") else ""
            log.info(f"签到成功{pts}！✅")
        return 0

    except CheckinError as e:
        emit({"status": "error", "exit_code": e.exit_code, "msg": str(e),
              **({"hint": e.hint} if e.hint else {})})
        if not args.json:
            log.err(str(e))
            if e.hint:
                log.err(f"提示: {e.hint}")
        return e.exit_code
    except Exception as e:
        msg = f"未知异常: {e}"
        emit({"status": "error", "exit_code": 3, "msg": msg})
        if not args.json:
            log.err(msg)
        return 3


if __name__ == "__main__":
    sys.exit(main())
