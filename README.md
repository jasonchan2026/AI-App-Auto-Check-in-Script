# AI-App-Auto-Check-in-Script

四个单文件 Python 自动签到脚本，覆盖常用 AI 应用的「每日签到领积分 / 额度」活动。均为幂等设计（已签到自动跳过，绝不重复领），支持 `--dry-run` 预览与 `--json` 机器可读输出，适合 cron / launchd / 计划任务定时运行。

## 包含的脚本

| 脚本 | 目标应用 | 依赖 | 凭证来源 |
|---|---|---|---|
| `tabbit_checkin.py` | Tabbit 浏览器（国内版 / 国际版） | 无（纯标准库） | 通过 Tabbit 自带 Playwright 桥读取浏览器 Cookie，本地缓存复用 |
| `traecode_checkin.py` | TraeCode（Trae CN 桌面端 IDE） | pycryptodome | 解密客户端 `storage.json` 中的登录凭证 |
| `trae_work_checkin.py` | Trae Work（TRAE SOLO CN 桌面端） | pycryptodome | 解密客户端 `storage.json` 中的登录凭证 |
| `workbuddy_checkin.py` | WorkBuddy 桌面端 | 无（纯标准库） | 读取本机登录态文件中的 accessToken |

## 快速开始

```bash
# TraeCode / Trae Work 需要 AES 依赖
pip3 install pycryptodome

# Tabbit（默认国内版 + 国际版都签，已签自动跳过）
python3 tabbit_checkin.py

# TraeCode
python3 traecode_checkin.py

# Trae Work
python3 trae_work_checkin.py

# WorkBuddy（--gift 可选：顺带领取今日礼包）
python3 workbuddy_checkin.py
```

前置条件：

- **Tabbit**：首次运行需 Tabbit 浏览器处于运行状态且已登录对应站点；之后依赖本地 Cookie 缓存（有效期至 JWT 过期，约 7 天），日常签到无需浏览器在线。
- **TraeCode / Trae Work**：本机已安装并登录过对应客户端（客户端关闭时也能签到）。
- **WorkBuddy**：本机已登录 WorkBuddy 客户端。

## 常用参数

| 参数 | 说明 |
|---|---|
| `--dry-run` | 只查询今日签到状态，不执行签到 |
| `--json` | 仅输出一行机器可读 JSON（日志走 stderr，可安全 `| jq`） |
| `--quiet` / `-q` | 静默模式 |
| `--timeout` | HTTP 超时（秒） |
| `--retries` | 网络异常 / 5xx 自动指数退避重试次数 |

各脚本特有参数见 `--help`：

- `tabbit_checkin.py`：`--site cn|intl|both`、`--refresh-cookie`（强制重读 Cookie）、`--cookie`
- `traecode_checkin.py` / `trae_work_checkin.py`：`--storage`、`--mainjs`（手动指定凭证 / 密钥表路径）、`--host`
- `workbuddy_checkin.py`：`--gift`、`--token`、`--token-file`（也支持环境变量 `WORKBUDDY_ACCESS_TOKEN`）

退出码统一约定：`0` 成功（含「今日已签到」）、`1` 配置 / 登录态错误、`2` 网络 / 接口错误、`3` 未知异常。

## 定时运行示例

### cron（每天 09:30）

```cron
30 9 * * * /usr/bin/python3 /path/to/tabbit_checkin.py --quiet >> /tmp/tabbit_checkin.log 2>&1
```

### launchd（macOS）

创建 `~/Library/LaunchAgents/com.checkin.plist`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.checkin</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/path/to/tabbit_checkin.py</string>
        <string>--quiet</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key><integer>9</integer>
        <key>Minute</key><integer>30</integer>
    </dict>
    <key>StandardOutPath</key><string>/tmp/checkin.log</string>
    <key>StandardErrorPath</key><string>/tmp/checkin.log</string>
</dict>
</plist>
```

```bash
launchctl load ~/Library/LaunchAgents/com.checkin.plist
```

## 安全说明

- 脚本代码不含任何硬编码凭证或个人信息；所有登录凭证均在运行时从本机客户端读取，仅用于向对应应用的**官方接口**发起签到请求，不会发送给任何第三方。
- Tabbit 的 Cookie 会缓存到 `~/.tabbit_checkin/cookies.json`（文件权限 `0600`），请勿将该缓存文件或含凭证参数的运行命令分享给他人。

## 免责声明

本项目仅供个人学习与个人账号自动化签到使用，接口路径与加解密逻辑来自对本机客户端的分析，随客户端版本更新可能失效。请自行评估使用风险，请勿用于商业用途。
