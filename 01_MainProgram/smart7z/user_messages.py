"""Bilingual messages that may appear in the Smart7z run log."""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Optional


@dataclass(frozen=True)
class UserMessageTemplate:
    zh: str
    en: str
    red_terms: tuple[str, ...] = ()
    whole_line_red: bool = False


USER_MESSAGE_TEMPLATES: Mapping[str, UserMessageTemplate] = MappingProxyType({
    "APP_READY": UserMessageTemplate(
        "Smart 7z Ultra 已就绪，任务将逐个处理。",
        "Smart 7z Ultra is ready; jobs will run one at a time.",
    ),
    "RECOVERY_AUTO_RESOLVED": UserMessageTemplate(
        "启动恢复已自动处理 {count} 项。",
        "Startup recovery automatically resolved {count} item(s).",
    ),
    "RECOVERY_REVIEW": UserMessageTemplate(
        "启动恢复有一项需要核对，请保留相关文件。",
        "One startup recovery item needs review; keep the related files.",
        red_terms=("需要核对", "needs review"),
    ),
    "RECOVERY_MORE": UserMessageTemplate(
        "另有 {count} 项恢复结果未在这里展开，请查看恢复日志。",
        "{count} more recovery result(s) are omitted here; see the recovery journal.",
    ),
    "INTAKE_FULL": UserMessageTemplate(
        "待接纳队列已满，未接收这个任务。",
        "Pending intake is full; this job was not accepted.",
        red_terms=("队列已满", "未接收", "is full", "was not accepted"),
    ),
    "JOB_FAILED": UserMessageTemplate(
        "任务失败，请查看任务详情（错误分类：{category}）。",
        "Job failed; see task details (error category: {category}).",
        whole_line_red=True,
    ),
    "ARCHIVE_BLOCKED": UserMessageTemplate(
        "压缩包触发安全或资源限制，已跳过且未解压；具体原因见本行末尾和任务详情。",
        "The archive hit a safety or resource limit and was skipped without extraction; see the end of this line and task details for the reason.",
        whole_line_red=True,
    ),
    "JOB_PARTIAL_RECOVERY": UserMessageTemplate(
        "任务没有完整成功，可恢复输出已保留；请查看任务详情。",
        "The job did not complete; recoverable output was retained. See task details.",
        red_terms=("没有完整成功", "did not complete"),
    ),
    "JOB_INTERRUPTED": UserMessageTemplate(
        "任务已中断，不会清理源文件。",
        "The job was interrupted; its source files will be kept.",
        red_terms=("已中断", "was interrupted"),
    ),
    "JOB_PASSWORD_REQUIRED": UserMessageTemplate(
        "现有密码均未通过，请在提示区输入密码或跳过。",
        "No available password worked; enter a password in the prompt or skip the job.",
        red_terms=("现有密码均未通过", "No available password worked"),
    ),
    "PASSWORD_PROMOTED": UserMessageTemplate(
        "本次成功使用的密码已加入当前会话的优先候选；日志不记录密码。",
        "The successful password is now preferred for this session; its value is not logged.",
    ),
    "SCAN_FAILED": UserMessageTemplate(
        "目录扫描失败，失败前已提交约 {count} 个候选路径。",
        "Folder scan failed after submitting about {count} candidate path(s).",
        red_terms=("目录扫描失败", "Folder scan failed"),
    ),
    "SCAN_COMPLETE": UserMessageTemplate(
        "目录扫描完成，已提交约 {count} 个候选路径。",
        "Folder scan finished; about {count} candidate path(s) were submitted.",
    ),
    "CONFIG_SYNC_FAILED": UserMessageTemplate(
        "设置未能保存或应用，队列没有启动。",
        "Settings could not be saved or applied; the queue was not started.",
        whole_line_red=True,
    ),
    "QUEUE_STARTED": UserMessageTemplate(
        "设置已保存，队列开始或继续处理。",
        "Settings were saved; queue processing started or resumed.",
    ),
    "CANCEL_CURRENT_REQUESTED": UserMessageTemplate(
        "已请求取消当前任务；任务停止后会更新状态。",
        "Cancellation was requested for the current job; its state will update after it stops.",
    ),
    "CANCEL_REMAINING": UserMessageTemplate(
        "已取消当前任务以外的未完成任务和待处理扫描请求。",
        "All unfinished jobs except the current job, plus pending scan requests, were cancelled.",
    ),
    "EXTERNAL_PATHS_RECEIVED": UserMessageTemplate(
        "已接收外部请求：文件 {file_count} 个，目录 {directory_count} 个；{mode_zh}。",
        "External request received: {file_count} file(s), {directory_count} folder(s); {mode_en}.",
    ),
    "USER_NOTICE": UserMessageTemplate(
        "任务产生一条需要查看的通知。",
        "The job produced a notice that needs review.",
        red_terms=("需要查看", "needs review"),
    ),
    "RECYCLE_FALLBACK_UNAVAILABLE": UserMessageTemplate(
        "回收站不可用，已永久删除 {count} 个源文件",
        "Recycle Bin unavailable; permanently deleted {count} source item(s)",
        red_terms=(
            "回收站不可用",
            "已永久删除",
            "Recycle Bin unavailable",
            "permanently deleted",
        ),
    ),
    "RECYCLE_FALLBACK_TOO_LARGE": UserMessageTemplate(
        "{count} 个源文件超过回收站容量限制，已永久删除",
        "{count} source item(s) exceeded the Recycle Bin capacity limit; permanently deleted",
        red_terms=(
            "超过回收站容量限制",
            "已永久删除",
            "exceeded the Recycle Bin capacity limit",
            "permanently deleted",
        ),
    ),
    "RECYCLE_FAILED": UserMessageTemplate(
        "回收站清理失败，已停止",
        "Recycle Bin cleanup failed; stopped",
        whole_line_red=True,
    ),
    "RECYCLE_FALLBACK_DELETE_FAILED": UserMessageTemplate(
        "回收站改用永久删除时失败，已停止",
        "Permanent fallback for Recycle Bin cleanup failed; stopped",
        whole_line_red=True,
    ),
})

CLEANUP_NOTICE_CODES = frozenset({
    "RECYCLE_FALLBACK_UNAVAILABLE",
    "RECYCLE_FALLBACK_TOO_LARGE",
    "RECYCLE_FAILED",
    "RECYCLE_FALLBACK_DELETE_FAILED",
})

_MESSAGE_CODE_RE = re.compile(r"\[([A-Z][A-Z0-9_]*)\](?=\s*(?:\||$))")


def format_user_message(
    code: str,
    *,
    context: str = "",
    detail: str = "",
    **values: object,
) -> str:
    """Render one documented bilingual message with optional shared context."""

    template = USER_MESSAGE_TEMPLATES[code]
    zh = template.zh.format(**values)
    en = template.en.format(**values)
    message = f"{zh} / {en} [{code}]"
    if context:
        message = f"{context}: {message}"
    if detail:
        message = f"{message} | {detail}"
    return message


def user_message_code(message: str) -> Optional[str]:
    """Return the stable code from a fully rendered user message."""

    match = _MESSAGE_CODE_RE.search(str(message).rstrip())
    return match.group(1) if match else None


def user_message_red_spans(
    message: str,
) -> tuple[bool, tuple[tuple[int, int], ...]]:
    """Return whether the full message is red and any red text ranges."""

    text = str(message)
    code = user_message_code(text)
    template = USER_MESSAGE_TEMPLATES.get(code) if code else None
    if template is None:
        return False, ()
    if template.whole_line_red:
        return True, ((0, len(text)),) if text else ()

    spans = []
    for term in template.red_terms:
        start = 0
        while True:
            start = text.find(term, start)
            if start < 0:
                break
            end = start + len(term)
            spans.append((start, end))
            start = end

    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return False, tuple(merged)
