import base64
import html
import hashlib
import hmac
import json
import os
import re
import sys
import time
from datetime import datetime, timezone, timedelta

import requests


class BaiduWP:
    def __init__(self, cookie: str):
        self.cookie = cookie.strip()
        self.session = requests.Session()
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Linux; Android 11; Pixel 5) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/90.0.4430.91 Mobile Safari/537.36"
            ),
            "Referer": "https://pan.baidu.com/wap/svip/growth/task",
            "Accept": "application/json, text/plain, */*",
            "X-Requested-With": "XMLHttpRequest",
            "Connection": "keep-alive",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
            "Cookie": self.cookie,
        }

    def signin(self):
        url = "https://pan.baidu.com/rest/2.0/membership/level?app_id=250528&web=5&method=signin"
        resp = self.session.get(url, headers=self.headers, timeout=30)
        sign_point = None
        signin_error_msg = ""
        if resp.status_code == 200:
            match = re.search(r'points":(\d+)', resp.text)
            if match:
                sign_point = match.group(1)
            # 原正则要求 error_msg 后面跟逗号，当 error_msg 在 JSON 末尾时匹配不到，
            # 会把错误响应当成「无错误」——静默失败的主要入口。
            # 改为先走 JSON 解析，失败再回退到宽松正则。
            try:
                data = resp.json()
                signin_error_msg = str(data.get("error_msg", "") or "")
                if not signin_error_msg and data.get("error_code"):
                    signin_error_msg = f"error_code={data['error_code']}"
                if not signin_error_msg and data.get("errno") not in (None, 0):
                    signin_error_msg = f"errno={data['errno']}"
            except Exception:
                error_match = re.search(r'"error_msg"\s*:\s*"(.*?)"', resp.text)
                if error_match:
                    signin_error_msg = error_match.group(1)

            # 响应里既没积分也没错误信息 = 格式不符预期，不能当成成功
            if sign_point is None and not signin_error_msg:
                signin_error_msg = f"响应无积分字段且无错误信息，可能是 Cookie 失效: {resp.text[:120]}"
        else:
            signin_error_msg = f"签到请求失败: HTTP {resp.status_code}"
        return sign_point, signin_error_msg

    def get_question(self):
        url = "https://pan.baidu.com/act/v2/membergrowv2/getdailyquestion?app_id=250528&web=5"
        resp = self.session.get(url, headers=self.headers, timeout=30)
        answer = None
        ask_id = None
        question_msg = "今日暂无答题任务或已完成"
        if resp.status_code == 200:
            answer_match = re.search(r'"answer":(\d+),', resp.text)
            if answer_match:
                answer = answer_match.group(1)
            ask_id_match = re.search(r'"ask_id":(\d+),', resp.text)
            if ask_id_match:
                ask_id = ask_id_match.group(1)
            if ask_id and answer:
                question_msg = f"获取问题成功, answer: {answer}, ask_id: {ask_id}"
        else:
            question_msg = f"获取问题失败: HTTP {resp.status_code}"
        return ask_id, answer, question_msg

    def answer_question(self, ask_id, answer):
        url = (
            "https://pan.baidu.com/act/v2/membergrowv2/answerquestion"
            f"?app_id=250528&web=5&ask_id={ask_id}&answer={answer}"
        )
        resp = self.session.get(url, headers=self.headers, timeout=30)
        answer_score = None
        answer_msg = ""
        if resp.status_code == 200:
            score_match = re.search(r'"score":(\d+)', resp.text)
            if score_match:
                answer_score = score_match.group(1)
            msg_match = re.search(r'"show_msg":"(.*?)"', resp.text)
            if msg_match:
                answer_msg = msg_match.group(1)
        return answer_score, answer_msg

    def get_userinfo(self):
        url = "https://pan.baidu.com/rest/2.0/membership/user?app_id=250528&web=5&method=query"
        resp = self.session.get(url, headers=self.headers, timeout=30)
        current_value = None
        current_level = None
        if resp.status_code == 200:
            value_match = re.search(r'current_value":(\d+),', resp.text)
            if value_match:
                current_value = value_match.group(1)
            level_match = re.search(r'current_level":(\d+),', resp.text)
            if level_match:
                current_level = level_match.group(1)
        return current_level, current_value

    def run(self):
        execution_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        sign_point, signin_error_msg = self.signin()
        time.sleep(3)
        ask_id, answer, question_msg = self.get_question()
        answer_score, answer_msg = (None, "")
        if ask_id and answer:
            answer_score, answer_msg = self.answer_question(ask_id, answer)
        current_level, current_value = self.get_userinfo()
        return {
            "execution_time": execution_time,
            "sign_point": sign_point,
            "signin_error_msg": signin_error_msg,
            "ask_id": ask_id,
            "question_answer": answer,
            "question_msg": question_msg,
            "answer_score": answer_score,
            "answer_msg": answer_msg,
            "current_level": current_level,
            "current_value": current_value,
        }


def is_benign_signin_message(message: str) -> bool:
    normalized = (message or "").strip().lower()
    if not normalized:
        return True
    benign_markers = [
        "已签到",
        "今日已",
        "repeat signin",
        "success",
    ]
    return any(marker in normalized for marker in benign_markers)


def is_already_signed_message(message: str) -> bool:
    """区分「今天已经签过」和「根本没签成」。

    两者积分都是 0，但前者正常、后者是故障。
    """
    normalized = (message or "").strip().lower()
    return any(m in normalized for m in ["已签到", "今日已", "repeat signin"])


def is_benign_answer_message(message: str) -> bool:
    normalized = (message or "").strip().lower()
    if not normalized:
        return True
    benign_markers = [
        "已答",
        "重复答题",
        "repeat",
        "exceeded limit",
        "num exceeded limit",
    ]
    return any(marker in normalized for marker in benign_markers)


def load_accounts():
    raw = os.getenv("BAIDUWP_ACCOUNTS", "").strip()
    if not raw:
        raise ValueError("Missing BAIDUWP_ACCOUNTS secret")

    data = json.loads(raw)
    if not isinstance(data, list) or not data:
        raise ValueError("BAIDUWP_ACCOUNTS must be a non-empty JSON array")

    cookies = []
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Account #{index} must be a JSON object")
        cookie = str(item.get("cookie", "")).strip()
        if not cookie:
            raise ValueError(f"Account #{index} is missing cookie")
        cookies.append(cookie)
    return cookies


def to_beijing_time(utc_iso: str) -> str:
    if not utc_iso:
        return ""
    dt = datetime.fromisoformat(utc_iso.replace("Z", "+00:00"))
    beijing = dt.astimezone(timezone(timedelta(hours=8)))
    return beijing.strftime("%Y-%m-%d %H:%M:%S")


def is_signin_success(result: dict) -> bool:
    return is_benign_signin_message(result.get("signin_error_msg", ""))


def is_answer_skipped(result: dict) -> bool:
    message = (result.get("answer_msg") or "").strip().lower()
    return "exceeded limit" in message or "num exceeded limit" in message


def is_answer_success(result: dict) -> bool:
    score = result.get("answer_score")
    return score not in (None, "", "0", 0)


def total_points_for_result(result: dict) -> int:
    """已到账积分。只算签到分——答题接口的 score 只是「答题成功」回执，
    积分需在 App 内手动领取（2026-09 实测后台无入账），计入会虚报。"""
    return int(result.get("sign_point") or 0)


def build_summary_lines(
    results: list[dict],
    failed: bool,
    error_message: str = "",
    alerts: list[str] | None = None,
    warnings: list[str] | None = None,
) -> list[str]:
    lines = []
    # 标题分级：真正需要处理的问题要从日常日报里跳出来
    if alerts:
        lines.append("🚨 百度网盘签到异常 — 需人工介入")
    elif warnings:
        lines.append("⚠️ 签到 & 答题汇总结果 — 有待确认项")
    else:
        lines.append("📊 签到 & 答题汇总结果")
    lines.append("")

    if alerts:
        for a in alerts:
            lines.append(a)
        lines.append("")
    lines.append("统计")
    lines.append(f"条目数: {len(results)}")
    lines.append(f"总积分增量: {sum(total_points_for_result(result) for result in results)}")
    signin_success_count = sum(1 for result in results if is_signin_success(result))
    signin_fail_count = len(results) - signin_success_count
    answer_success_count = sum(1 for result in results if is_answer_success(result))
    answer_fail_count = sum(
        1
        for result in results
        if not is_answer_success(result) and not is_answer_skipped(result)
    )
    lines.append(f"签到: ✅ {signin_success_count}  / ❌ {signin_fail_count}")
    lines.append(f"答题: ✅ {answer_success_count}  / ❌ {answer_fail_count}")
    earliest = results[0]["execution_time"] if results else ""
    if earliest:
        lines.append(f"最早执行(UTC): {earliest}")
        lines.append(f"最早执行(北京): {to_beijing_time(earliest)}")
    if error_message:
        lines.append(f"错误: {error_message}")

    if warnings:
        lines.append("")
        for w in warnings:
            lines.append(w)

    lines.append("")
    lines.append("🔍 逐条详情")
    return lines


def build_detail_lines(index: int, result: dict) -> list[str]:
    execution_time = result.get("execution_time", "")
    sign_point = int(result.get("sign_point") or 0)
    answer_score = int(result.get("answer_score") or 0)
    signin_message = result.get("signin_error_msg") or ""
    answer_message = result.get("answer_msg") or ""
    ask_id = result.get("ask_id")
    answer = result.get("question_answer")
    question_msg = result.get("question_msg") or "今日暂无答题任务或已完成"

    if sign_point > 0:
        signin_detail = f"签到成功, 获得积分: {sign_point}, 提示: {signin_message}"
    else:
        signin_detail = signin_message

    if answer_score > 0:
        answer_detail = f"答题回执成功, 分值:{answer_score}（积分需在 App 内手动领取，未计入总积分）, 提示: {answer_message}"
        answer_icon = "✅"
    elif is_answer_skipped(result):
        answer_detail = answer_message
        answer_icon = "➖"
    else:
        answer_detail = answer_message or "无答题结果"
        answer_icon = "❌"

    lines = []
    lines.append(f"条目 #{index}")
    lines.append(f"执行时间(UTC): {execution_time}")
    lines.append(f"执行时间(北京): {to_beijing_time(execution_time)}")
    lines.append(f"签到: {'✅' if is_signin_success(result) else '❌'} {signin_detail} (积分+{sign_point})")
    if ask_id and answer:
        lines.append(f"题目: 获取成功 ask_id={ask_id}，拟答: {answer}")
    else:
        lines.append("题目: 无")
    lines.append(f"题目消息: {question_msg}")
    lines.append(f"答题: {answer_icon} {answer_detail} (得分:{answer_score})")
    lines.append(f"会员等级/成长值: {result.get('current_level') or ''} / {result.get('current_value') or ''}")
    lines.append(
        f"用户信息: 当前会员等级: {result.get('current_level') or ''}, 成长值: {result.get('current_value') or ''}"
    )
    lines.append(f"本条到账积分: {total_points_for_result(result)}（仅含签到；答题积分需手动领取未计入）")
    return lines


def render_text_summary(
    results: list[dict],
    failed: bool,
    error_message: str = "",
    alerts: list[str] | None = None,
    warnings: list[str] | None = None,
) -> str:
    lines = build_summary_lines(
        results=results, failed=failed, error_message=error_message,
        alerts=alerts, warnings=warnings,
    )
    for index, result in enumerate(results, start=1):
        lines.extend(build_detail_lines(index=index, result=result))
        lines.append("")
    lines.append(f"生成时间(北京): {to_beijing_time(datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))}")
    return "\n".join(lines).rstrip()


def render_telegram_html(
    results: list[dict],
    failed: bool,
    error_message: str = "",
    alerts: list[str] | None = None,
    warnings: list[str] | None = None,
) -> str:
    lines = []
    text = render_text_summary(
        results=results, failed=failed, error_message=error_message,
        alerts=alerts, warnings=warnings,
    )
    bold_heads = (
        "📊 签到 & 答题汇总结果",
        "🚨 百度网盘签到异常 — 需人工介入",
        "⚠️ 签到 & 答题汇总结果 — 有待确认项",
        "统计",
        "🔍 逐条详情",
    )
    for line in text.splitlines():
        if line in bold_heads or line.startswith("🚨 账号"):
            lines.append(f"<b>{html.escape(line)}</b>")
        elif line.startswith("条目 #"):
            lines.append(f"<b>{html.escape(line)}</b>")
        elif line.startswith("本条累计积分变动:"):
            lines.append(f"<b>{html.escape(line)}</b>")
        else:
            lines.append(html.escape(line))
    return "\n".join(lines)


def send_telegram_message(message_html: str):
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not bot_token or not chat_id:
        return

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    response = requests.post(
        url,
        json={
            "chat_id": chat_id,
            "text": message_html,
            "parse_mode": "HTML",
        },
        timeout=30,
    )
    response.raise_for_status()


def build_feishu_sign(secret: str) -> tuple[str, str]:
    timestamp = str(int(time.time()))
    string_to_sign = f"{timestamp}\n{secret}"
    sign = base64.b64encode(
        hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return timestamp, sign


def send_feishu_message(message_text: str):
    webhook_url = os.getenv("FEISHU_WEBHOOK_URL", "").strip()
    webhook_secret = os.getenv("FEISHU_WEBHOOK_SECRET", "").strip()
    if not webhook_url:
        return

    payload = {
        "msg_type": "text",
        "content": {
            "text": message_text,
        },
    }
    if webhook_secret:
        timestamp, sign = build_feishu_sign(webhook_secret)
        payload["timestamp"] = timestamp
        payload["sign"] = sign

    response = requests.post(webhook_url, json=payload, timeout=30)
    response.raise_for_status()


def send_notifications(
    results: list[dict],
    failed: bool,
    error_message: str = "",
    alerts: list[str] | None = None,
    warnings: list[str] | None = None,
):
    telegram_message = render_telegram_html(
        results=results, failed=failed, error_message=error_message,
        alerts=alerts, warnings=warnings,
    )
    feishu_message = render_text_summary(
        results=results, failed=failed, error_message=error_message,
        alerts=alerts, warnings=warnings,
    )
    errors = []

    try:
        send_telegram_message(telegram_message)
    except Exception as exc:
        errors.append(f"Telegram 通知失败: {exc}")

    try:
        send_feishu_message(feishu_message)
    except Exception as exc:
        errors.append(f"飞书通知失败: {exc}")

    for error in errors:
        print(error)


def main():
    from state import (
        load_state, save_state, record_results,
        build_warnings, check_cookie_age,
    )

    results = []
    failed = False
    error_message = ""
    alerts: list[str] = []
    warnings: list[str] = []

    state = load_state()
    now = datetime.now(timezone(timedelta(hours=8)))

    try:
        cookies = load_accounts()

        # Cookie 年龄检查 —— 在过期前提醒，而不是过期后排查
        for index, cookie in enumerate(cookies, start=1):
            w = check_cookie_age(state, index, cookie, datetime.now(timezone.utc))
            if w:
                print(w)
                if w.startswith("🚨"):
                    alerts.append(w)
                else:
                    warnings.append(w)

        for index, cookie in enumerate(cookies, start=1):
            result = BaiduWP(cookie).run()
            results.append(result)
            print(f"== Account {index} ==")
            print(
                "签到获得"
                f"{result['sign_point'] or ''}"
                f"{result['signin_error_msg'] or ''}"
            )
            print(
                "答题获得"
                f"{result['answer_score'] or ''}"
                f"{result['answer_msg'] or ''}"
            )
            print(
                f"当前会员等级{result['current_level'] or ''}，"
                f"成长值{result['current_value'] or ''}"
            )

            if not is_benign_signin_message(result["signin_error_msg"]):
                failed = True

            if not is_benign_answer_message(result["answer_msg"]):
                failed = True
    except Exception as exc:
        failed = True
        error_message = str(exc)
        print(f"执行失败: {error_message}")
    finally:
        # 跨天追踪：连续失败 / 连续零积分检测
        try:
            streak_alerts = record_results(state, results, now)
            alerts.extend(streak_alerts)
            warnings.extend(build_warnings(state, results))
            for a in streak_alerts:
                print(a)
            save_state(state)
        except Exception as exc:
            print(f"状态追踪异常（不影响签到）: {exc}")

        send_notifications(
            results=results, failed=failed, error_message=error_message,
            alerts=alerts, warnings=warnings,
        )

    # 连续零积分等静默失败也要让 Action 标红，否则依然看不见
    if failed or alerts:
        sys.exit(1)


if __name__ == "__main__":
    main()
