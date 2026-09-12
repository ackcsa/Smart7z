"""PySide6 desktop UI for Smart7z.

The scheduler, extraction pipeline, IPC protocol, configuration format, and
Windows integration stay in their existing modules.  This module replaces
only the presentation layer with a denser, more controllable Qt interface.
"""

from __future__ import annotations

from startup_trace import flush as _flush_startup_trace, mark as _startup_trace

_startup_trace("ui_import:stdlib:start")
import datetime
import logging
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

_startup_trace("ui_import:stdlib:end")
_startup_trace("ui_import:qtcore:start")
from PySide6.QtCore import (
    QAbstractTableModel,
    QEvent,
    QModelIndex,
    QObject,
    QPoint,
    QPointF,
    QRect,
    QRectF,
    QSize,
    Qt,
    QTimer,
    Signal,
    Slot,
)
_startup_trace("ui_import:qtcore:end")
_startup_trace("ui_import:qtgui:start")
from PySide6.QtGui import (
    QAction,
    QActionGroup,
    QColor,
    QCloseEvent,
    QFont,
    QIcon,
    QKeySequence,
    QPainter,
    QPalette,
    QPixmap,
    QPolygonF,
)
_startup_trace("ui_import:qtgui:end")
_startup_trace("ui_import:qtwidgets:start")
from PySide6.QtWidgets import (
    QAbstractItemView,
    QAbstractSpinBox,
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QStyle,
    QStyleFactory,
    QStyleOptionSpinBox,
    QStyledItemDelegate,
    QTabWidget,
    QTableView,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

_startup_trace("ui_import:qtwidgets:end")
_startup_trace("ui_import:application:start")
from config import find_sevenzip, get_app_dir, load_config, save_config
from models import CleanupPolicy, ErrorCategory, Job, JobState, TERMINAL_STATES

# Lazy heavy imports: scheduler pulls executor/recovery/sevenzip and
# discovery pulls the 1200-line archive_classifier.  None of them is needed
# to show the window, so they are resolved on first use instead of at
# module import time.  Tests may still patch these module attributes.
Scheduler = None
classify_automatic_candidate = None
is_multipart_child = None
logical_archive_key = None


def _resolve_scheduler_class():
    global Scheduler
    if Scheduler is None:
        from scheduler import Scheduler as _Scheduler

        Scheduler = _Scheduler
    return Scheduler


def _resolve_scan_helpers():
    global classify_automatic_candidate, is_multipart_child, logical_archive_key
    if logical_archive_key is None:
        from archive_classifier import (
            classify_automatic_candidate as _classify,
        )
        from discovery import (
            is_multipart_child as _is_child,
            logical_archive_key as _logical_key,
        )

        classify_automatic_candidate = _classify
        is_multipart_child = _is_child
        logical_archive_key = _logical_key
    return classify_automatic_candidate, is_multipart_child, logical_archive_key
from runtime_ipc import (
    ARCHIVE_EXTS,
    BoundedIPCServer,
    CONTEXT_AUTO_CLOSE_GRACE_MS,
    EXTERNAL_CLEANUP_POLICIES,
    INSTANCE_STARTUP_POLL_SECONDS,
    INSTANCE_STARTUP_WAIT_SECONDS,
    IPC_MAX_PATHS,
    PROCESSING_STATES,
    SCAN_MODE_DEEP,
    SCAN_MODE_NORMAL,
    SCAN_MODE_STEGANOGRAPHIER,
    STATUS_DISPLAY,
    _forward_launch_request,
    parse_launch_args,
)
from user_messages import (
    CLEANUP_NOTICE_CODES,
    format_user_message,
    user_message_code,
    user_message_red_spans,
)
from windows_adapters import (
    cleanup_stale_sessions,
    close_mutex,
    create_mutex,
    is_reparse_point,
    register_context_menu,
    unregister_context_menu,
)
_startup_trace("ui_import:application:end")

logger = logging.getLogger(__name__)

APP_TITLE = "Smart 7z Ultra"
APP_VERSION = "1.0.4"

_ICON_FONT_FAMILY: Optional[str] = None

MAX_RECOVERY_LOG_DETAILS = 8
ARCHIVE_BLOCK_REASONS = frozenset(
    {
        "manifest_limit",
        "output_file_quota",
        "summary_manifest_blocked",
        "output_byte_quota",
        "nested_output_quota",
        "no_output_capacity",
    }
)
_RECOVERY_ROUTINE_PREFIXES = (
    "Removed stale recovery record for an absent artifact",
    "Deleted owned temporary artifact:",
    "Restored source after interrupted cleanup:",
    "Source cleanup recovery record resolved:",
    "Source cleanup had already completed:",
    "Removed stale recovery record for an absent session",
    "Deleted stale owned session:",
)
_RECOVERY_ALWAYS_SHOW_PREFIXES = ("Source recovery conflict retained at:",)


def find_candidates(*args, **kwargs):
    """Load deep-scan support only when a scan actually needs it."""

    from stego_candidates import find_candidates as implementation

    return implementation(*args, **kwargs)


def find_steganographier_candidates(*args, **kwargs):
    """Load Steganographier compatibility support on first use."""

    from steganographier_compat import (
        find_steganographier_candidates as implementation,
    )

    return implementation(*args, **kwargs)

COLOR_ACCENT = QColor("#00796B")
COLOR_ACCENT_HOVER = QColor("#00695F")
COLOR_ACCENT_SOFT = QColor("#E2F3F0")
COLOR_TEXT = QColor("#1F1F1F")
COLOR_MUTED = QColor("#616161")
COLOR_BORDER = QColor("#D1D1D1")
COLOR_PROCESSING = QColor("#006FC9")
COLOR_SUCCESS = QColor("#107C10")
COLOR_WARNING = QColor("#9D5D00")
COLOR_DANGER = QColor("#C42B1C")
COLOR_NEUTRAL = QColor("#737373")
COLOR_ROW_ALTERNATE = QColor("#F7FAF9")
COLOR_ROW_HOVER = QColor("#EEF4F2")
COLOR_ROW_SELECTED = QColor("#E2F3F0")

TABLE_COLUMNS: Tuple[Tuple[str, str], ...] = (
    ("task", "任务"),
    ("size", "大小"),
    ("state", "任务阶段"),
    ("progress", "进度"),
    ("attempts", "密码尝试"),
    ("policy", "清理策略"),
    ("retention", "源包处置"),
)

PHASE_STATES: Tuple[Tuple[str, frozenset], ...] = (
    ("发现", frozenset({JobState.DISCOVERING, JobState.GROUPED, JobState.STANDALONE})),
    ("列表读取", frozenset({JobState.LISTING, JobState.PASSWORD_ATTEMPT, JobState.PASSWORD_REQUIRED})),
    ("解压", frozenset({JobState.PLANNED, JobState.SPACE_WAIT, JobState.EXTRACTING})),
    ("校验", frozenset({JobState.VERIFYING})),
    ("提交", frozenset({JobState.COMMITTING, JobState.COMPLETE})),
)

_DEFERRED_LINE_EDIT_SIZE_HINT = QSize(226, 40)
_DEFERRED_LINE_EDIT_MINIMUM_SIZE_HINT = QSize(34, 40)


class DeferredLineEdit(QWidget):
    """A lightweight line-edit shell that creates Qt's native editor on demand."""

    textChanged = Signal(str)
    textEdited = Signal(str)
    editingFinished = Signal()
    returnPressed = Signal()
    selectionChanged = Signal()
    cursorPositionChanged = Signal(int, int)

    def __init__(self, text: str = "", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._text = str(text)
        self._placeholder_text = ""
        self._echo_mode = QLineEdit.EchoMode.Normal
        self._read_only = False
        self._max_length = 32767
        self._alignment = Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        self._clear_button_enabled = False
        self._editor: Optional[QLineEdit] = None
        self._tab_previous: Optional[QWidget] = None
        self._tab_next: Optional[QWidget] = None

        self._display = QLabel(self)
        self._display.setProperty("deferredLineEdit", True)
        self._display.setTextFormat(Qt.TextFormat.PlainText)
        self._display.setAlignment(self._alignment)
        self._display.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._display.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._display)

        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._update_display()

    def isMaterialized(self) -> bool:
        return self._editor is not None

    def sizeHint(self) -> QSize:
        return QSize(_DEFERRED_LINE_EDIT_SIZE_HINT)

    def minimumSizeHint(self) -> QSize:
        return QSize(_DEFERRED_LINE_EDIT_MINIMUM_SIZE_HINT)

    def text(self) -> str:
        if self._editor is not None:
            return self._editor.text()
        return self._text

    def setText(self, text: str) -> None:
        value = str(text)
        if self._editor is not None:
            self._editor.setText(value)
            return
        if value == self._text:
            return
        self._text = value
        self._update_display()
        self.textChanged.emit(value)

    def clear(self) -> None:
        self.setText("")

    def placeholderText(self) -> str:
        if self._editor is not None:
            return self._editor.placeholderText()
        return self._placeholder_text

    def setPlaceholderText(self, text: str) -> None:
        self._placeholder_text = str(text)
        if self._editor is not None:
            self._editor.setPlaceholderText(self._placeholder_text)
        else:
            self._update_display()

    def echoMode(self):
        if self._editor is not None:
            return self._editor.echoMode()
        return self._echo_mode

    def setEchoMode(self, mode) -> None:
        self._echo_mode = QLineEdit.EchoMode(mode)
        if self._editor is not None:
            self._editor.setEchoMode(self._echo_mode)
        else:
            self._update_display()

    def isReadOnly(self) -> bool:
        if self._editor is not None:
            return self._editor.isReadOnly()
        return self._read_only

    def setReadOnly(self, value: bool) -> None:
        self._read_only = bool(value)
        if self._editor is not None:
            self._editor.setReadOnly(self._read_only)

    def maxLength(self) -> int:
        if self._editor is not None:
            return self._editor.maxLength()
        return self._max_length

    def setMaxLength(self, value: int) -> None:
        self._max_length = max(0, int(value))
        if len(self._text) > self._max_length:
            self.setText(self._text[: self._max_length])
        if self._editor is not None:
            self._editor.setMaxLength(self._max_length)

    def alignment(self):
        if self._editor is not None:
            return self._editor.alignment()
        return self._alignment

    def setAlignment(self, alignment) -> None:
        self._alignment = Qt.AlignmentFlag(alignment)
        self._display.setAlignment(self._alignment)
        if self._editor is not None:
            self._editor.setAlignment(self._alignment)

    def isClearButtonEnabled(self) -> bool:
        if self._editor is not None:
            return self._editor.isClearButtonEnabled()
        return self._clear_button_enabled

    def setClearButtonEnabled(self, enabled: bool) -> None:
        self._clear_button_enabled = bool(enabled)
        if self._editor is not None:
            self._editor.setClearButtonEnabled(self._clear_button_enabled)

    def setAccessibleName(self, name: str) -> None:
        super().setAccessibleName(name)
        if self._editor is not None:
            self._editor.setAccessibleName(name)

    def setAccessibleDescription(self, description: str) -> None:
        super().setAccessibleDescription(description)
        if self._editor is not None:
            self._editor.setAccessibleDescription(description)

    def selectAll(self) -> None:
        self._materialize().selectAll()

    def deselect(self) -> None:
        if self._editor is not None:
            self._editor.deselect()

    def selectedText(self) -> str:
        if self._editor is None:
            return ""
        return self._editor.selectedText()

    def selectionStart(self) -> int:
        if self._editor is None:
            return -1
        return self._editor.selectionStart()

    def cursorPosition(self) -> int:
        if self._editor is None:
            return len(self._text)
        return self._editor.cursorPosition()

    def setCursorPosition(self, position: int) -> None:
        self._materialize().setCursorPosition(position)

    def copy(self) -> None:
        self._materialize().copy()

    def cut(self) -> None:
        self._materialize().cut()

    def paste(self) -> None:
        self._materialize().paste()

    def undo(self) -> None:
        self._materialize().undo()

    def redo(self) -> None:
        self._materialize().redo()

    def _update_display(self) -> None:
        if self._text:
            if self._echo_mode == QLineEdit.EchoMode.NoEcho:
                display_text = ""
            elif self._echo_mode == QLineEdit.EchoMode.Normal:
                display_text = self._text
            else:
                display_text = "\u25cf" * len(self._text)
            color = COLOR_TEXT
        else:
            display_text = self._placeholder_text
            color = COLOR_MUTED
        palette = self._display.palette()
        palette.setColor(QPalette.ColorRole.WindowText, color)
        self._display.setPalette(palette)
        self._display.setText(display_text)

    def _materialize(self) -> QLineEdit:
        if self._editor is not None:
            return self._editor

        _startup_trace("deferred_line_edit:materialize:start")
        previous_focus = self._tab_focus_neighbor(forward=False)
        next_focus = self._tab_focus_neighbor(forward=True)
        self._tab_previous = previous_focus
        self._tab_next = next_focus
        editor = QLineEdit(self._text, self)
        editor.setPlaceholderText(self._placeholder_text)
        editor.setEchoMode(self._echo_mode)
        editor.setReadOnly(self._read_only)
        editor.setMaxLength(self._max_length)
        editor.setAlignment(self._alignment)
        editor.setClearButtonEnabled(self._clear_button_enabled)
        editor.setAccessibleName(self.accessibleName())
        editor.setAccessibleDescription(self.accessibleDescription())
        editor.setInputMethodHints(self.inputMethodHints())
        editor.setObjectName(self.objectName())
        editor.textChanged.connect(self._editor_text_changed)
        editor.textEdited.connect(self.textEdited)
        editor.editingFinished.connect(self.editingFinished)
        editor.returnPressed.connect(self.returnPressed)
        editor.selectionChanged.connect(self.selectionChanged)
        editor.cursorPositionChanged.connect(self.cursorPositionChanged)
        editor.installEventFilter(self)

        layout = self.layout()
        if layout is not None:
            layout.replaceWidget(self._display, editor)
        self._display.hide()
        self._editor = editor
        self.setFocusProxy(editor)
        if previous_focus is not self:
            QWidget.setTabOrder(previous_focus, self)
        if next_focus is not self:
            QWidget.setTabOrder(self, next_focus)
        editor.show()
        self.updateGeometry()
        _startup_trace("deferred_line_edit:materialize:end")
        return editor

    def _tab_focus_neighbor(self, *, forward: bool) -> Optional[QWidget]:
        candidate = self
        for _index in range(4096):
            candidate = (
                candidate.nextInFocusChain()
                if forward
                else candidate.previousInFocusChain()
            )
            if candidate is self:
                return None
            if (
                candidate.focusPolicy() & Qt.FocusPolicy.TabFocus
                and candidate.isEnabled()
                and not candidate.isHidden()
            ):
                return candidate
        return None

    def eventFilter(self, watched, event) -> bool:
        if watched is self._editor and event.type() == QEvent.Type.KeyPress:
            key = event.key()
            modifiers = event.modifiers()
            if not modifiers & (
                Qt.KeyboardModifier.ControlModifier
                | Qt.KeyboardModifier.AltModifier
                | Qt.KeyboardModifier.MetaModifier
            ):
                if key == Qt.Key.Key_Backtab or (
                    key == Qt.Key.Key_Tab
                    and modifiers & Qt.KeyboardModifier.ShiftModifier
                ):
                    if self._focus_recorded_tab_neighbor(forward=False):
                        return True
                elif key == Qt.Key.Key_Tab:
                    if self._focus_recorded_tab_neighbor(forward=True):
                        return True
        return super().eventFilter(watched, event)

    def _focus_recorded_tab_neighbor(self, *, forward: bool) -> bool:
        target = self._tab_next if forward else self._tab_previous
        if target is None or target.isHidden() or not target.isEnabled():
            return False
        reason = (
            Qt.FocusReason.TabFocusReason
            if forward
            else Qt.FocusReason.BacktabFocusReason
        )
        target.setFocus(reason)
        return target.hasFocus()

    @Slot(str)
    def _editor_text_changed(self, text: str) -> None:
        self._text = text
        self.textChanged.emit(text)

    def focusInEvent(self, event) -> None:
        super().focusInEvent(event)
        self._materialize().setFocus(event.reason())

    def mousePressEvent(self, event) -> None:
        editor = self._materialize()
        editor.setFocus(Qt.FocusReason.MouseFocusReason)
        QApplication.sendEvent(editor, event)
        event.accept()

    def keyPressEvent(self, event) -> None:
        editor = self._materialize()
        editor.setFocus(Qt.FocusReason.OtherFocusReason)
        QApplication.sendEvent(editor, event)

    def inputMethodEvent(self, event) -> None:
        editor = self._materialize()
        editor.setFocus(Qt.FocusReason.OtherFocusReason)
        QApplication.sendEvent(editor, event)


def _icon_font(point_size: int) -> QFont:
    global _ICON_FONT_FAMILY

    if _ICON_FONT_FAMILY is None:
        # The packaged app targets Windows, where this font is part of the
        # supported desktop font set.  QFont.exactMatch() can synchronously
        # initialize the full font database and add hundreds of milliseconds
        # to cold startup, so keep the fallback decision static.
        _ICON_FONT_FAMILY = (
            "Segoe Fluent Icons" if sys.platform == "win32" else "Segoe MDL2 Assets"
        )
    return QFont(_ICON_FONT_FAMILY, point_size)


def fluent_icon(glyph: str, color: QColor = COLOR_TEXT, size: int = 18) -> QIcon:
    """Render a Windows Fluent glyph into a Qt icon without another package."""

    canvas = max(24, size + 8)
    pixmap = QPixmap(canvas, canvas)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
    painter.setPen(color)
    painter.setFont(_icon_font(size))
    painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, glyph)
    painter.end()
    return QIcon(pixmap)


def app_icon() -> QIcon:
    if getattr(sys, "frozen", False):
        candidates = (Path(get_app_dir()) / "smart7z.ico",)
    else:
        candidates = (
            Path(get_app_dir()) / "build_assets" / "smart7z.ico",
            Path(__file__).resolve().parent / "build_assets" / "smart7z.ico",
        )
    for candidate in candidates:
        if candidate.is_file():
            return QIcon(str(candidate))
    return fluent_icon("\ue7b8", QColor("#008675"), 18)


def _log_html_escape(text: str) -> str:
    """Escape text for the limited rich text the log view accepts."""

    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("  ", "&nbsp; ")
    )


def format_size_bytes(size: int) -> str:
    if size >= 1024**3:
        return f"{size / 1024**3:.2f} GB"
    if size >= 1024**2:
        return f"{size / 1024**2:.2f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{max(0, size)} B"


_SIZE_CACHE: Dict[str, Tuple[float, int]] = {}
_SIZE_CACHE_TTL_SECONDS = 5.0


def job_size_bytes(job: Job) -> int:
    source_path = getattr(job, "original_path", None) or job.path
    now = time.monotonic()
    cached = _SIZE_CACHE.get(source_path)
    if cached is not None and now - cached[0] < _SIZE_CACHE_TTL_SECONDS:
        return cached[1]
    try:
        size = os.path.getsize(source_path)
    except OSError:
        size = 0
    if len(_SIZE_CACHE) > 4096:
        _SIZE_CACHE.clear()
    _SIZE_CACHE[source_path] = (now, size)
    return size


def cleanup_policy_text(value: str) -> str:
    return {
        CleanupPolicy.KEEP.value: "保留",
        CleanupPolicy.RECYCLE.value: "回收站",
        CleanupPolicy.PERMANENT.value: "永久删除",
    }.get(value, value or "-")


def retention_text(job: Job) -> str:
    if job.source_retention_reason:
        translations = {
            "cleanup_disabled": "已保留",
            "cleanup_complete": "已处理",
            "password_skipped": "密码已跳过",
            "batch_cancelled": "任务已取消",
            "interrupted": "已中断并保留",
        }
        return translations.get(job.source_retention_reason, job.source_retention_reason)
    if job.cleanup_eligible:
        return "等待任务完成"
    if job.state in TERMINAL_STATES:
        return "已保留"
    return "尚未处理"


def elide_path_middle(text: str, limit: int = 72) -> str:
    """把超长路径压成"开头...结尾"，保留盘符/上级目录与文件名两端。

    与整条省略（ElideRight）相比，中间的"..."能同时保留最关键的定位信息：
    开头告诉用户盘符与顶层目录，结尾告诉用户文件名。仅在超长时才压缩，
    短路径原样返回，避免无谓的视觉抖动。
    """
    value = str(text or "")
    if len(value) <= limit or "\\" not in value:
        return value
    head_len = limit // 2
    tail_len = limit - head_len - 3
    return f"{value[:head_len]}...{value[-tail_len:]}"


def state_color(state: JobState) -> QColor:
    if state == JobState.COMPLETE:
        return COLOR_SUCCESS
    if state in {JobState.PASSWORD_REQUIRED, JobState.STEGO_CANDIDATE_REVIEW, JobState.SPACE_WAIT}:
        return COLOR_WARNING
    if state in {JobState.FAILED, JobState.PARTIAL_RECOVERY, JobState.INTERRUPTED}:
        return COLOR_DANGER
    if state in PROCESSING_STATES:
        return COLOR_PROCESSING
    return COLOR_NEUTRAL


def phase_summary(state: JobState, history: Sequence[JobState] = ()) -> str:
    if state in TERMINAL_STATES and state != JobState.COMPLETE:
        previous = next((item for item in reversed(history) if item not in TERMINAL_STATES), None)
        outcome = STATUS_DISPLAY.get(state, state.value)
        return f"{phase_summary(previous)} · {outcome}" if previous is not None else f"已结束 · {outcome}"
    if state == JobState.QUEUED:
        return "阶段 0/5 · 等待开始"
    for index, (label, states) in enumerate(PHASE_STATES, start=1):
        if state in states:
            return f"阶段 {index}/5 · {label}"
    if state in TERMINAL_STATES:
        return "阶段 5/5 · 已结束"
    return "阶段 · -"


def error_action_text(category: Optional[ErrorCategory]) -> str:
    return {
        ErrorCategory.NOT_ARCHIVE: "确认所选文件是完整压缩包，必要时重新获取源文件。",
        ErrorCategory.UNSUPPORTED_FORMAT: "更新 7-Zip，或使用创建此文件的软件打开。",
        ErrorCategory.BAD_PASSWORD: "核对密码；首尾空格也属于密码内容。",
        ErrorCategory.MISSING_VOLUME: "将全部分卷放在同一目录，补齐缺卷后重新添加任务。",
        ErrorCategory.CORRUPT_HEADER: "核对源文件和分卷是否完整，必要时重新下载。",
        ErrorCategory.TRUNCATED_INPUT: "源文件可能不完整；补齐文件后重新添加任务。",
        ErrorCategory.DISK_FULL: "释放目标盘或暂存盘空间，或在选项中更换目录。",
        ErrorCategory.TIMEOUT: "检查磁盘和文件占用情况，再重新添加任务。",
        ErrorCategory.CANCELLED: "源包已保留；需要继续时重新添加任务。",
        ErrorCategory.UNSAFE_PATH: "检查压缩包中的异常路径或链接，不要绕过安全检查。",
        ErrorCategory.OUTPUT_CONFLICT: "检查输出目录的权限和文件占用，并核对保留的恢复输出。",
        ErrorCategory.VERIFY_FAILED: "核对恢复输出；源包已保留，可重新获取完整文件后再试。",
        ErrorCategory.INTERNAL_ERROR: "查看运行日志并保留源文件；修复问题后重新添加任务。",
    }.get(category, "查看运行日志中的具体原因，再重新添加任务。")


class QtDispatchBridge(QObject):
    scheduler_event = Signal(str, object, tuple, dict)
    invoke = Signal(object, tuple)
    scan_progress = Signal(int, int, str, int, int)
    scan_candidate = Signal(str, object, object, bool, int)
    scan_finished = Signal(int, str, int)


class JobTableModel(QAbstractTableModel):
    JobRole = Qt.ItemDataRole.UserRole + 1

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._jobs: List[Job] = []
        self._rows: Dict[str, int] = {}
        self._sort_column = 1
        self._sort_order = Qt.SortOrder.AscendingOrder

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._jobs)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(TABLE_COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.TextAlignmentRole and orientation == Qt.Orientation.Horizontal:
            if section == 4:
                return int(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.DisplayRole:
            if orientation == Qt.Orientation.Horizontal and 0 <= section < len(TABLE_COLUMNS):
                return TABLE_COLUMNS[section][1]
            return section + 1
        return None

    def flags(self, index: QModelIndex):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self._jobs):
            return None
        job = self._jobs[index.row()]
        column = TABLE_COLUMNS[index.column()][0]
        if role == self.JobRole:
            return job
        if role == Qt.ItemDataRole.ToolTipRole:
            if column == "task":
                return job.display_path
            if column == "retention" and job.error_message:
                return job.error_message
        if role == Qt.ItemDataRole.TextAlignmentRole and column in {"size", "attempts"}:
            return int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight)
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if column == "task":
            return Path(job.display_path).name
        if column == "size":
            return format_size_bytes(job_size_bytes(job))
        if column == "state":
            return STATUS_DISPLAY.get(job.state, job.state.value)
        if column == "progress":
            return max(0, min(100, int(job.progress)))
        if column == "attempts":
            return int(job.attempt_count)
        if column == "policy":
            return cleanup_policy_text(job.cleanup_policy_snapshot)
        if column == "retention":
            return retention_text(job)
        return None

    def upsert(self, job: Job) -> None:
        row = self._rows.get(job.task_id)
        if row is None:
            row = len(self._jobs)
            self.beginInsertRows(QModelIndex(), row, row)
            self._jobs.append(job)
            self._rows[job.task_id] = row
            self.endInsertRows()
            self._resort()
            return
        self._jobs[row] = job
        self._resort()
        row = self._rows[job.task_id]
        self.dataChanged.emit(
            self.index(row, 0),
            self.index(row, len(TABLE_COLUMNS) - 1),
            [Qt.ItemDataRole.DisplayRole, self.JobRole],
        )

    def sort(
        self,
        column: int,
        order: Qt.SortOrder = Qt.SortOrder.AscendingOrder,
    ) -> None:
        if not 0 <= column < len(TABLE_COLUMNS):
            return
        self._sort_column = column
        self._sort_order = order
        self._resort()

    def _sort_key(self, job: Job):
        key = TABLE_COLUMNS[self._sort_column][0]
        path_key = os.path.normcase(job.display_path)
        if key == "task":
            return (Path(job.display_path).name.casefold(), path_key)
        if key == "size":
            return (job_size_bytes(job), path_key)
        if key == "state":
            return (STATUS_DISPLAY.get(job.state, job.state.value), path_key)
        if key == "progress":
            return (max(0, min(100, int(job.progress))), path_key)
        if key == "attempts":
            return (int(job.attempt_count), path_key)
        if key == "policy":
            return (cleanup_policy_text(job.cleanup_policy_snapshot), path_key)
        return (retention_text(job), path_key)

    def _resort(self) -> None:
        if len(self._jobs) < 2:
            self._rows = {job.task_id: row for row, job in enumerate(self._jobs)}
            return
        reverse = self._sort_order == Qt.SortOrder.DescendingOrder
        ordered = sorted(self._jobs, key=self._sort_key, reverse=reverse)
        priority = {JobState.PASSWORD_REQUIRED: 0, JobState.STEGO_CANDIDATE_REVIEW: 1}
        ordered.sort(key=lambda job: priority.get(job.state, 2))
        if ordered == self._jobs:
            return
        self.layoutAboutToBeChanged.emit()
        persistent = self.persistentIndexList()
        identities = [(self._jobs[index.row()].task_id, index.column()) for index in persistent]
        self._jobs[:] = ordered
        self._rows = {job.task_id: row for row, job in enumerate(self._jobs)}
        self.changePersistentIndexList(
            persistent, [self.index(self._rows[task_id], column) for task_id, column in identities]
        )
        self.layoutChanged.emit()

    def remove_ids(self, task_ids: Iterable[str]) -> None:
        rows = sorted(
            (self._rows[task_id] for task_id in set(task_ids) if task_id in self._rows),
            reverse=True,
        )
        for row in rows:
            self.beginRemoveRows(QModelIndex(), row, row)
            self._jobs.pop(row)
            self.endRemoveRows()
        self._rows = {job.task_id: row for row, job in enumerate(self._jobs)}

    def job_at(self, row: int) -> Optional[Job]:
        if 0 <= row < len(self._jobs):
            return self._jobs[row]
        return None

    def row_for_id(self, task_id: str) -> int:
        return self._rows.get(task_id, -1)

    def jobs(self) -> Sequence[Job]:
        return tuple(self._jobs)


class JobTableDelegate(QStyledItemDelegate):
    def paint(self, painter: QPainter, option, index: QModelIndex) -> None:
        job = index.data(JobTableModel.JobRole)
        if not isinstance(job, Job):
            super().paint(painter, option, index)
            return

        opt = option
        rect = QRectF(opt.rect)
        key = TABLE_COLUMNS[index.column()][0]
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        if opt.state & QStyle.StateFlag.State_Selected:
            row_color = COLOR_ROW_SELECTED
        elif opt.state & QStyle.StateFlag.State_MouseOver:
            row_color = COLOR_ROW_HOVER
        else:
            row_color = COLOR_ROW_ALTERNATE if index.row() % 2 else QColor("#FFFFFF")
        painter.fillRect(opt.rect, row_color)
        painter.setPen(QColor("#EEF1F1"))
        painter.drawLine(opt.rect.bottomLeft(), opt.rect.bottomRight())

        if key == "task":
            painter.setPen(QColor("#8B6E2F"))
            painter.setFont(_icon_font(16))
            painter.drawText(
                QRectF(rect.left() + 10, rect.top(), 24, rect.height()),
                Qt.AlignmentFlag.AlignCenter,
                "\ue7c3",
            )
            text_left = rect.left() + 38
            title_font = QFont("Segoe UI", 9)
            title_font.setWeight(QFont.Weight.DemiBold)
            painter.setFont(title_font)
            painter.setPen(COLOR_TEXT)
            title_rect = QRectF(text_left, rect.top() + 5, rect.width() - 46, 18)
            title = painter.fontMetrics().elidedText(
                Path(job.display_path).name,
                Qt.TextElideMode.ElideMiddle,
                max(20, int(title_rect.width())),
            )
            painter.drawText(title_rect, Qt.AlignmentFlag.AlignVCenter, title)
            path_font = QFont("Segoe UI", 8)
            painter.setFont(path_font)
            painter.setPen(COLOR_MUTED)
            path_rect = QRectF(text_left, rect.top() + 23, rect.width() - 46, 15)
            parent = str(Path(job.display_path).parent)
            parent = painter.fontMetrics().elidedText(
                parent,
                Qt.TextElideMode.ElideMiddle,
                max(20, int(path_rect.width())),
            )
            painter.drawText(path_rect, Qt.AlignmentFlag.AlignVCenter, parent)
        elif key == "state":
            color = state_color(job.state)
            dot = QPointF(rect.left() + 13, rect.center().y())
            painter.setBrush(color)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(dot, 3.2, 3.2)
            font = QFont("Segoe UI", 9)
            if job.state in PROCESSING_STATES or job.state in {
                JobState.PASSWORD_REQUIRED,
                JobState.COMPLETE,
            }:
                font.setWeight(QFont.Weight.DemiBold)
            painter.setFont(font)
            painter.setPen(color)
            painter.drawText(
                QRectF(rect.left() + 23, rect.top(), rect.width() - 26, rect.height()),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                STATUS_DISPLAY.get(job.state, job.state.value),
            )
        elif key == "progress":
            progress = max(0, min(100, int(job.progress)))
            track = QRectF(rect.left() + 10, rect.center().y() - 3, max(20, rect.width() - 52), 6)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#E1E5E9"))
            painter.drawRoundedRect(track, 3, 3)
            fill = QRectF(track)
            fill.setWidth(track.width() * progress / 100.0)
            if fill.width() > 0:
                painter.setBrush(state_color(job.state))
                painter.drawRoundedRect(fill, 3, 3)
            painter.setFont(QFont("Consolas", 8))
            painter.setPen(COLOR_TEXT)
            painter.drawText(
                QRectF(rect.right() - 38, rect.top(), 34, rect.height()),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                f"{progress}%",
            )
        else:
            text = str(index.data(Qt.ItemDataRole.DisplayRole) or "")
            font = QFont("Consolas" if key in {"size", "attempts"} else "Segoe UI", 9)
            painter.setFont(font)
            painter.setPen(COLOR_TEXT if key != "retention" else COLOR_MUTED)
            alignment = Qt.AlignmentFlag.AlignVCenter
            if key in {"size", "attempts"}:
                alignment |= Qt.AlignmentFlag.AlignRight
                text_rect = rect.adjusted(6, 0, -10, 0)
            else:
                alignment |= Qt.AlignmentFlag.AlignLeft
                text_rect = rect.adjusted(10, 0, -8, 0)
            text = painter.fontMetrics().elidedText(
                text,
                Qt.TextElideMode.ElideRight,
                max(20, int(text_rect.width())),
            )
            painter.drawText(text_rect, alignment, text)
        painter.restore()

    def sizeHint(self, option, index):
        return QSize(option.rect.width(), 42)


class DropOverlay(QFrame):
    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setObjectName("dropOverlay")
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        label = QLabel("松开以添加到任务队列")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setObjectName("dropOverlayLabel")
        layout.addWidget(label)
        self.hide()


class SoftStepperSpinBox(QSpinBox):
    def paintEvent(self, event) -> None:
        super().paintEvent(event)

        # QSS owns the stepper backgrounds, so draw stable arrows explicitly.
        option = QStyleOptionSpinBox()
        self.initStyleOption(option)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(Qt.PenStyle.NoPen)

        controls = (
            (
                QStyle.SubControl.SC_SpinBoxUp,
                QAbstractSpinBox.StepEnabledFlag.StepUpEnabled,
                True,
            ),
            (
                QStyle.SubControl.SC_SpinBoxDown,
                QAbstractSpinBox.StepEnabledFlag.StepDownEnabled,
                False,
            ),
        )
        for control, enabled_flag, points_up in controls:
            rect = self.style().subControlRect(
                QStyle.ComplexControl.CC_SpinBox,
                option,
                control,
                self,
            )
            painter.setBrush(
                QColor(
                    "#46514f"
                    if self.isEnabled() and option.stepEnabled & enabled_flag
                    else "#9da5a3"
                )
            )
            center = rect.center()
            half_width = 3.0
            half_height = 1.75
            if points_up:
                points = (
                    QPointF(center.x() - half_width, center.y() + half_height),
                    QPointF(center.x(), center.y() - half_height),
                    QPointF(center.x() + half_width, center.y() + half_height),
                )
            else:
                points = (
                    QPointF(center.x() - half_width, center.y() - half_height),
                    QPointF(center.x(), center.y() + half_height),
                    QPointF(center.x() + half_width, center.y() - half_height),
                )
            painter.drawPolygon(QPolygonF(points))


class SettingsDialog(QDialog):
    def __init__(self, config: dict, parent: QWidget):
        super().__init__(parent)
        self.setWindowTitle("选项")
        self.setModal(True)
        self.setMinimumWidth(520)
        self.setWindowIcon(app_icon())

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(14)
        title = QLabel("选项")
        title.setObjectName("dialogTitle")
        root.addWidget(title)

        path_group = QGroupBox("路径")
        path_group.setObjectName("settingsGroup")
        path_form = QFormLayout(path_group)
        path_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        path_form.setHorizontalSpacing(12)
        path_form.setVerticalSpacing(10)
        self.temp_edit = QLineEdit(
            str(config.get("temp_dir") or (Path(tempfile.gettempdir()) / "Smart7z"))
        )
        self.password_file_edit = QLineEdit(str(config.get("password_file", "code.txt")))
        path_form.addRow("暂存目录", self._path_row(self.temp_edit, self._browse_temp))
        path_form.addRow("密码文件", self._path_row(self.password_file_edit, self._browse_password_file))
        root.addWidget(path_group)

        processing_group = QGroupBox("处理")
        processing_group.setObjectName("settingsGroup")
        processing_form = QFormLayout(processing_group)
        processing_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        processing_form.setHorizontalSpacing(12)
        processing_form.setVerticalSpacing(10)
        self.depth_spin = SoftStepperSpinBox()
        self.depth_spin.setObjectName("depthSpin")
        self.depth_spin.setRange(0, 20)
        self.depth_spin.setValue(int(config.get("max_nested_depth", 2)))
        self.wait_space_check = QCheckBox("空间不足时等待")
        self.wait_space_check.setChecked(bool(config.get("wait_disk_space", True)))
        processing_form.addRow("最大嵌套深度", self.depth_spin)
        processing_form.addRow("", self.wait_space_check)
        root.addWidget(processing_group)

        cleanup_group = QGroupBox("清理")
        cleanup_group.setObjectName("settingsGroup")
        cleanup_form = QFormLayout(cleanup_group)
        cleanup_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        cleanup_form.setHorizontalSpacing(12)
        cleanup_form.setVerticalSpacing(10)
        self.permanent_fallback_check = QCheckBox("回收站不可用时允许永久删除源文件")
        self.permanent_fallback_check.setChecked(
            bool(config.get("allow_permanent_fallback", False))
        )
        self.permanent_fallback_check.setToolTip(
            "关闭时（默认）：回收站不可用或容量不足会保留源文件；\n"
            "开启时：回收站不可用或容量不足会直接永久删除源文件，无法恢复。"
        )
        cleanup_form.addRow("", self.permanent_fallback_check)
        root.addWidget(cleanup_group)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("应用")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _path_row(self, edit: QLineEdit, callback) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addWidget(edit, 1)
        button = QPushButton("浏览…")
        button.setObjectName("browseButton")
        button.setAccessibleName("浏览路径")
        button.clicked.connect(callback)
        layout.addWidget(button)
        return row

    def _browse_temp(self) -> None:
        value = QFileDialog.getExistingDirectory(self, "选择暂存目录", self.temp_edit.text())
        if value:
            self.temp_edit.setText(value)

    def _browse_password_file(self) -> None:
        value, _selected = QFileDialog.getOpenFileName(
            self,
            "选择密码本",
            self.password_file_edit.text(),
            "文本文件 (*.txt);;所有文件 (*.*)",
        )
        if value:
            self.password_file_edit.setText(value)

    def values(self) -> dict:
        return {
            "temp_dir": self.temp_edit.text().strip(),
            "password_file": self.password_file_edit.text().strip(),
            "max_nested_depth": self.depth_spin.value(),
            "wait_disk_space": self.wait_space_check.isChecked(),
            "allow_permanent_fallback": self.permanent_fallback_check.isChecked(),
        }


class Smart7zQtWindow(QMainWindow):
    def __init__(
        self,
        startup_args: Optional[Sequence[str]] = None,
        startup_auto_start: bool = True,
        startup_cleanup_policy: str = CleanupPolicy.KEEP.value,
        startup_extract_to_source: bool = False,
        startup_context_menu: bool = False,
        defer_scheduler: bool = False,
    ):
        _startup_trace("window_init:start")
        super().__init__()
        _startup_trace("window_init:qmainwindow")
        self.setWindowTitle(APP_TITLE)
        _startup_trace("window_init:icon:start")
        self.setWindowIcon(app_icon())
        _startup_trace("window_init:icon:end")
        self.resize(1100, 720)
        self.setMinimumSize(920, 640)
        self.setAcceptDrops(True)
        self._place_center()
        QTimer.singleShot(0, self._place_center)

        _startup_trace("window_init:config:start")
        self.config = load_config()
        self.config["_app_dir"] = get_app_dir()
        _startup_trace("window_init:config:end")
        self.scheduler: Optional[Scheduler] = None
        self.ipc_server: Optional[BoundedIPCServer] = None
        self.startup_blocked = False
        self._startup_pending = False
        self._startup_initializer = None
        self._failed_startup_scheduler = None
        self._startup_config_snapshot = {}
        self._pending_startup_jobs: List[Tuple[Job, bool]] = []
        self.jobs: Dict[str, Job] = {}
        self.seen_paths = set()
        self._suppressed_job_ids = set()
        self._main_password = ""
        self._closing = False
        self._close_confirmation_pending = False
        self._shutdown_complete = False
        self._processing_requested = False

        self.startup_args = list(startup_args or ())
        self.startup_auto_start = bool(startup_auto_start)
        self.startup_cleanup_policy = (
            startup_cleanup_policy
            if startup_cleanup_policy in EXTERNAL_CLEANUP_POLICIES
            else CleanupPolicy.KEEP.value
        )
        self.startup_extract_to_source = bool(startup_extract_to_source)
        self.startup_context_menu = bool(startup_context_menu)
        self._context_auto_close_armed = bool(
            self.startup_context_menu and self.startup_args
        )
        self._context_auto_close_abnormal = False
        self._context_auto_close_generation = 0
        self._startup_processing_scheduled = False
        self._startup_args_processed = False

        self._scan_thread: Optional[threading.Thread] = None
        self._retired_scan_threads: List[threading.Thread] = []
        self._scan_generation = 0
        self._scan_cancel = threading.Event()
        self._pending_scan_requests: List[Tuple[List[str], bool, dict]] = []
        self._scan_active = False
        self._scan_found = 0
        self._scan_config_snapshot: Optional[dict] = None
        self._pending_pwd_jobs: List[Job] = []
        self._current_pwd_job: Optional[Job] = None
        self._pending_stego_jobs: List[Job] = []
        self._current_stego_job: Optional[Job] = None
        self._inspector_expanded = True
        self._inspector_sizes = [440, 190]
        self._root_layout: Optional[QVBoxLayout] = None
        self._activity_shelf_ready = False
        self._job_table_model_ready = False
        self._deferred_icons_ready = False
        self._deferred_icon_specs = []

        self.bridge = QtDispatchBridge(self)
        self.bridge.scheduler_event.connect(self._handle_scheduler_event)
        self.bridge.invoke.connect(self._invoke_on_ui)
        self.bridge.scan_progress.connect(self._update_scan_progress)
        self.bridge.scan_candidate.connect(self._accept_scan_candidate)
        self.bridge.scan_finished.connect(self._finish_scan)

        _startup_trace("window_init:build_ui:start")
        self._build_ui()
        _startup_trace("window_init:build_ui:end")
        if defer_scheduler:
            # run_app shows the window first and calls _setup_scheduler()
            # after the first frame, so recovery replay and session setup
            # no longer sit between launch and a visible window.
            _startup_trace("window_init:scheduler_deferred")
        else:
            self._setup_scheduler()
        self._update_summary()
        QTimer.singleShot(0, self._ensure_job_table_model)
        QTimer.singleShot(50, self._apply_deferred_icons)
        _startup_trace("window_init:end")

    def _build_ui(self) -> None:
        _startup_trace("build_ui:menus:start")
        self._build_menus()
        _startup_trace("build_ui:menus:end")
        central = QWidget()
        central.setObjectName("centralSurface")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self._root_layout = root

        _startup_trace("build_ui:command_bar:start")
        root.addWidget(self._build_command_bar())
        _startup_trace("build_ui:command_bar:end")
        _startup_trace("build_ui:option_strip:start")
        root.addWidget(self._build_option_strip())
        _startup_trace("build_ui:option_strip:end")
        # Keep a hidden, cheap slot in the layout. The real activity pages
        # are only needed after a scan or an interactive prompt starts.
        self.activity_shelf = QFrame()
        self.activity_shelf.setObjectName("activityShelf")
        root.addWidget(self.activity_shelf)
        self.activity_shelf.hide()

        self.workspace_splitter = QSplitter(Qt.Orientation.Vertical)
        self.workspace_splitter.setObjectName("workspaceSplitter")
        self.workspace_splitter.setChildrenCollapsible(False)
        self.workspace_splitter.setHandleWidth(4)
        _startup_trace("build_ui:queue:start")
        self.queue_panel = self._build_queue_panel()
        _startup_trace("build_ui:queue:end")
        _startup_trace("build_ui:inspector:start")
        self.inspector_panel = self._build_inspector()
        _startup_trace("build_ui:inspector:end")
        self.workspace_splitter.addWidget(self.queue_panel)
        self.workspace_splitter.addWidget(self.inspector_panel)
        self.workspace_splitter.setStretchFactor(0, 1)
        self.workspace_splitter.setStretchFactor(1, 0)
        self.workspace_splitter.setSizes(self._inspector_sizes)
        root.addWidget(self.workspace_splitter, 1)

        self.drop_overlay = DropOverlay(central)
        self.drop_overlay.raise_()
        _startup_trace("build_ui:status:start")
        self._build_status_bar()
        _startup_trace("build_ui:status:end")

    def _ensure_activity_shelf(self) -> None:
        if self._activity_shelf_ready:
            return
        layout = self._root_layout
        placeholder = self.activity_shelf
        if layout is None or placeholder is None:
            return

        shelf = self._build_activity_shelf()
        layout.replaceWidget(placeholder, shelf)
        shelf.hide()
        placeholder.setParent(None)
        placeholder.deleteLater()
        self.activity_shelf = shelf
        self._activity_shelf_ready = True

    def _build_menus(self) -> None:
        menu_bar = self.menuBar()
        menu_bar.setNativeMenuBar(False)

        context_menu = menu_bar.addMenu("右键菜单")
        add_context = context_menu.addAction("添加右键菜单")
        remove_context = context_menu.addAction("删除右键菜单")
        add_context.triggered.connect(self._register_context_menu)
        remove_context.triggered.connect(self._unregister_context_menu)

        scan_menu = menu_bar.addMenu("文件扫描模式")
        self.scan_action_group = QActionGroup(self)
        self.scan_action_group.setExclusive(True)
        self.scan_actions: Dict[str, QAction] = {}
        scan_items = (
            (SCAN_MODE_DEEP, "深度扫描模式", "全文件读取"),
            (SCAN_MODE_STEGANOGRAPHIER, "仅兼容隐写者模式", "非全读取"),
            (SCAN_MODE_NORMAL, "普通模式", "仅识别常规压缩文件"),
        )
        selected_mode = self._scan_mode_from_config(self.config)
        for mode, title, description in scan_items:
            action = QAction(f"{title}    {description}", self)
            action.setCheckable(True)
            action.setData(mode)
            action.setChecked(mode == selected_mode)
            self.scan_action_group.addAction(action)
            scan_menu.addAction(action)
            self.scan_actions[mode] = action
        self.scan_action_group.triggered.connect(self._scan_mode_changed)

        self.options_action = menu_bar.addAction("选项")
        self.options_action.triggered.connect(self._open_settings)

    def _build_command_bar(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("commandBar")
        frame.setMinimumHeight(52)
        frame.setMaximumHeight(58)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(10, 7, 10, 7)
        layout.setSpacing(6)

        add_button = self._command_button("添加文件", "\ue710", self._add_files)
        add_button.setShortcut(QKeySequence.StandardKey.Open)
        scan_button = self._command_button("扫描文件夹", "\ue838", self._scan_folder)
        self.start_button = self._command_button("开始", "\ue768", self._toggle_processing, primary=True)
        layout.addWidget(add_button)
        layout.addWidget(scan_button)
        layout.addWidget(self.start_button)

        divider = QFrame()
        divider.setObjectName("verticalDivider")
        divider.setFixedSize(1, 28)
        layout.addSpacing(2)
        layout.addWidget(divider)
        layout.addSpacing(2)

        output_label = QLabel("输出到")
        output_label.setObjectName("commandLabel")
        layout.addWidget(output_label)
        self.target_edit = DeferredLineEdit(str(self.config.get("target_dir", "")))
        self.target_edit.setPlaceholderText("未指定时按当前输出策略处理")
        self.target_edit.setAccessibleName("输出目录")
        self.target_edit.setMinimumWidth(240)
        self.target_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.target_edit.editingFinished.connect(lambda: self._sync_config(silent=True))
        layout.addWidget(self.target_edit, 1)
        browse_target = QToolButton()
        browse_target.setObjectName("compactIconButton")
        self._set_deferred_icon(browse_target, "\ue838", COLOR_MUTED, 14)
        browse_target.setIconSize(QSize(15, 15))
        browse_target.setFixedSize(28, 28)
        browse_target.setToolTip("浏览目标目录")
        browse_target.clicked.connect(self._browse_target)
        layout.addWidget(browse_target)

        password_label = QLabel("主密码")
        password_label.setObjectName("commandLabel")
        layout.addWidget(password_label)
        self.main_password_edit = DeferredLineEdit(self._main_password)
        self.main_password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
        self.main_password_edit.setPlaceholderText("会话优先密码")
        self.main_password_edit.setAccessibleName("主密码")
        self.main_password_edit.setToolTip("完整解压成功后会尝试写入明文密码本；不写入配置文件。")
        self.main_password_edit.setMinimumWidth(116)
        self.main_password_edit.setMaximumWidth(170)
        self.main_password_edit.textChanged.connect(self._main_password_changed)
        layout.addWidget(self.main_password_edit)
        return frame

    def _build_option_strip(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("optionStrip")
        frame.setMinimumHeight(36)
        frame.setMaximumHeight(42)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(10, 4, 10, 4)
        layout.setSpacing(10)

        self.extract_source_check = QCheckBox("解压到原目录")
        self.extract_source_check.setChecked(bool(self.config.get("extract_to_source", True)))
        self.staging_check = QCheckBox("暂存模式")
        self.staging_check.setChecked(self.config.get("extract_mode", "staging") == "staging")
        self.nested_check = QCheckBox("嵌套解压")
        self.nested_check.setChecked(bool(self.config.get("nested_extraction", False)))
        for checkbox in (self.extract_source_check, self.staging_check, self.nested_check):
            checkbox.toggled.connect(lambda _checked: self._sync_config(silent=True))
            layout.addWidget(checkbox)

        separator = QFrame()
        separator.setObjectName("verticalDivider")
        separator.setFixedSize(1, 22)
        layout.addWidget(separator)
        complete_label = QLabel("完成后")
        complete_label.setObjectName("secondaryText")
        layout.addWidget(complete_label)

        self.cleanup_group = QButtonGroup(self)
        self.cleanup_group.setExclusive(True)
        self.cleanup_buttons: Dict[str, QPushButton] = {}
        cleanup_values = (
            (CleanupPolicy.KEEP.value, "保留源包"),
            (CleanupPolicy.RECYCLE.value, "移到回收站"),
            (CleanupPolicy.PERMANENT.value, "永久删除"),
        )
        cleanup_segment = QFrame()
        cleanup_segment.setObjectName("cleanupSegment")
        cleanup_layout = QHBoxLayout(cleanup_segment)
        cleanup_layout.setContentsMargins(0, 0, 0, 0)
        cleanup_layout.setSpacing(0)
        selected = str(self.config.get("cleanup_policy", CleanupPolicy.KEEP.value))
        for index, (value, label) in enumerate(cleanup_values):
            button = QPushButton(label)
            button.setCheckable(True)
            button.setProperty("segment", True)
            button.setProperty(
                "segmentPosition",
                "first" if index == 0 else "last" if index == len(cleanup_values) - 1 else "middle",
            )
            button.setChecked(value == selected)
            button.clicked.connect(lambda checked, policy=value: self._select_cleanup_policy(policy, checked))
            self.cleanup_group.addButton(button)
            self.cleanup_buttons[value] = button
            cleanup_layout.addWidget(button)
        layout.addWidget(cleanup_segment)
        layout.addStretch(1)
        return frame

    def _build_activity_shelf(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("activityShelf")
        frame.setMinimumHeight(48)
        frame.setMaximumHeight(56)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(0, 0, 0, 0)
        self.activity_stack = QStackedWidget()
        layout.addWidget(self.activity_stack)

        scan_page = QWidget()
        scan_layout = QHBoxLayout(scan_page)
        scan_layout.setContentsMargins(12, 6, 10, 6)
        scan_layout.setSpacing(10)
        scan_icon = QLabel("\ue721")
        scan_icon.setFont(_icon_font(16))
        scan_icon.setObjectName("activityIcon")
        scan_layout.addWidget(scan_icon)
        scan_copy = QWidget()
        scan_copy_layout = QVBoxLayout(scan_copy)
        scan_copy_layout.setContentsMargins(0, 0, 0, 0)
        scan_copy_layout.setSpacing(0)
        self.scan_title = QLabel("正在扫描")
        self.scan_title.setObjectName("activityTitle")
        self.scan_meta = QLabel("准备中")
        self.scan_meta.setObjectName("secondaryText")
        scan_copy_layout.addWidget(self.scan_title)
        scan_copy_layout.addWidget(self.scan_meta)
        scan_layout.addWidget(scan_copy, 1)
        self.scan_progress = QProgressBar()
        self.scan_progress.setRange(0, 100)
        self.scan_progress.setTextVisible(False)
        self.scan_progress.setFixedWidth(320)
        self.scan_progress.setFixedHeight(6)
        scan_layout.addWidget(self.scan_progress)
        self.scan_percent = QLabel("0%")
        self.scan_percent.setObjectName("monoText")
        self.scan_percent.setFixedWidth(38)
        self.scan_percent.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        scan_layout.addWidget(self.scan_percent)
        cancel_scan = self._icon_button("\ue711", "取消扫描", self._cancel_scan)
        scan_layout.addWidget(cancel_scan)
        self.activity_stack.addWidget(scan_page)
        self.scan_activity_page = scan_page

        password_page = QWidget()
        password_layout = QHBoxLayout(password_page)
        password_layout.setContentsMargins(12, 6, 10, 6)
        password_layout.setSpacing(10)
        pwd_icon = QLabel("\ue72e")
        pwd_icon.setFont(_icon_font(16))
        pwd_icon.setObjectName("warningIcon")
        password_layout.addWidget(pwd_icon)
        self.password_title = QLabel("需要密码")
        self.password_title.setObjectName("activityTitle")
        self.password_title.setFixedWidth(240)
        password_layout.addWidget(self.password_title)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("输入密码")
        self.password_edit.returnPressed.connect(self._submit_password)
        password_layout.addWidget(self.password_edit, 1)
        self.password_reveal_button = QToolButton()
        self.password_reveal_button.setObjectName("compactIconButton")
        self.password_reveal_button.setIcon(fluent_icon("\ue890", COLOR_MUTED, 14))
        self.password_reveal_button.setCheckable(True)
        self.password_reveal_button.setToolTip("显示或隐藏密码")
        self.password_reveal_button.toggled.connect(
            lambda checked: self.password_edit.setEchoMode(
                QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
            )
        )
        password_layout.addWidget(self.password_reveal_button)
        submit_pwd = QPushButton("提交并继续")
        submit_pwd.setObjectName("primaryButton")
        submit_pwd.clicked.connect(self._submit_password)
        password_layout.addWidget(submit_pwd)
        skip_pwd = QPushButton("跳过")
        skip_pwd.clicked.connect(self._skip_password)
        password_layout.addWidget(skip_pwd)
        self.activity_stack.addWidget(password_page)
        self.password_activity_page = password_page

        stego_page = QWidget()
        stego_layout = QHBoxLayout(stego_page)
        stego_layout.setContentsMargins(12, 6, 10, 6)
        stego_layout.setSpacing(10)
        stego_icon = QLabel("\ue8b7")
        stego_icon.setFont(_icon_font(16))
        stego_icon.setObjectName("activityIcon")
        stego_layout.addWidget(stego_icon)
        self.stego_title = QLabel("选择隐写候选")
        self.stego_title.setObjectName("activityTitle")
        self.stego_title.setFixedWidth(240)
        stego_layout.addWidget(self.stego_title)
        self.stego_combo = QComboBox()
        self.stego_combo.setMinimumContentsLength(14)
        self.stego_combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.stego_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        stego_layout.addWidget(self.stego_combo, 1)
        confirm_stego = QPushButton("使用此候选")
        confirm_stego.setObjectName("primaryButton")
        confirm_stego.clicked.connect(self._submit_stego)
        confirm_stego.setEnabled(False)
        self.stego_combo.currentIndexChanged.connect(
            lambda index: confirm_stego.setEnabled(index >= 0)
        )
        stego_layout.addWidget(confirm_stego)
        skip_stego = QPushButton("跳过")
        skip_stego.clicked.connect(self._skip_stego)
        stego_layout.addWidget(skip_stego)
        self.activity_stack.addWidget(stego_page)
        self.stego_activity_page = stego_page
        return frame

    def _build_queue_panel(self) -> QWidget:
        panel = QWidget()
        panel.setObjectName("queuePanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        toolbar = QFrame()
        toolbar.setObjectName("queueToolbar")
        toolbar.setMinimumHeight(40)
        toolbar.setMaximumHeight(44)
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(10, 4, 9, 4)
        toolbar_layout.setSpacing(8)
        heading = QLabel("任务队列")
        heading.setObjectName("sectionTitle")
        toolbar_layout.addWidget(heading)
        self.queue_count_label = QLabel("0 个任务")
        self.queue_count_label.setObjectName("secondaryText")
        toolbar_layout.addWidget(self.queue_count_label)
        self.pending_count_label = QLabel("待接收 0")
        self.pending_count_label.setObjectName("pendingText")
        toolbar_layout.addWidget(self.pending_count_label)
        toolbar_layout.addStretch(1)
        self.cancel_current_button = self._queue_action_button(
            "取消当前", "中断正在运行的任务", self._cancel_current
        )
        self.cancel_selected_button = self._queue_action_button(
            "取消选中", "移除选中的所有未完成任务，正在执行的任务会先安全停止", self._cancel_selected
        )
        self.clear_finished_button = self._queue_action_button(
            "清除已完成", "移除已经完成、失败或中断的任务", self._clear_finished
        )
        self.cancel_pending_button = self._queue_action_button(
            "取消所有待处理", "取消扫描和当前任务之外的待处理任务", self._cancel_remaining
        )
        for button in (
            self.cancel_current_button,
            self.cancel_selected_button,
            self.clear_finished_button,
            self.cancel_pending_button,
        ):
            toolbar_layout.addWidget(button)
        self.inspector_toggle = self._queue_action_button(
            "隐藏详情", "隐藏任务详情和运行日志", self._toggle_inspector
        )
        toolbar_layout.addWidget(self.inspector_toggle)
        layout.addWidget(toolbar)

        self.job_model = JobTableModel(self)
        self.job_model.rowsInserted.connect(
            lambda *_args: self._ensure_job_table_model()
        )
        self.job_table = QTableView()
        self.job_table.setObjectName("jobTable")
        self.job_table.setItemDelegate(JobTableDelegate(self.job_table))
        self.job_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.job_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.job_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.job_table.setAlternatingRowColors(True)
        self.job_table.setMouseTracking(True)
        self.job_table.setShowGrid(False)
        self.job_table.setWordWrap(False)
        self.job_table.setSortingEnabled(True)
        self.job_table.verticalHeader().setVisible(False)
        self.job_table.verticalHeader().setDefaultSectionSize(42)
        header = self.job_table.horizontalHeader()
        header.setMinimumHeight(36)
        header.setStretchLastSection(False)
        layout.addWidget(self.job_table, 1)

        summary = QFrame()
        summary.setObjectName("progressSummary")
        summary.setMinimumHeight(32)
        summary.setMaximumHeight(34)
        summary_layout = QHBoxLayout(summary)
        summary_layout.setContentsMargins(10, 5, 12, 5)
        summary_layout.setSpacing(8)
        summary_layout.addWidget(QLabel("当前任务"))
        self.current_progress = QProgressBar()
        self.current_progress.setRange(0, 100)
        self.current_progress.setTextVisible(False)
        self.current_progress.setFixedHeight(6)
        summary_layout.addWidget(self.current_progress, 1)
        self.current_progress_label = QLabel("0%")
        self.current_progress_label.setObjectName("monoText")
        self.current_progress_label.setFixedWidth(36)
        summary_layout.addWidget(self.current_progress_label)
        summary_layout.addSpacing(10)
        summary_layout.addWidget(QLabel("全部任务"))
        self.total_progress = QProgressBar()
        self.total_progress.setRange(0, 100)
        self.total_progress.setTextVisible(False)
        self.total_progress.setFixedHeight(6)
        summary_layout.addWidget(self.total_progress, 1)
        self.total_progress_label = QLabel("0%")
        self.total_progress_label.setObjectName("monoText")
        self.total_progress_label.setFixedWidth(36)
        summary_layout.addWidget(self.total_progress_label)
        self.progress_summary_text = QLabel("0 完成 · 0 处理中")
        self.progress_summary_text.setObjectName("secondaryText")
        summary_layout.addWidget(self.progress_summary_text)
        layout.addWidget(summary)
        return panel

    def _ensure_job_table_model(self) -> None:
        if self._job_table_model_ready:
            return
        self.job_table.setModel(self.job_model)
        header = self.job_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column, width in ((1, 70), (2, 86), (3, 116), (4, 72), (5, 82), (6, 122)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Fixed)
            self.job_table.setColumnWidth(column, width)
        self.job_table.sortByColumn(1, Qt.SortOrder.AscendingOrder)
        self.job_table.selectionModel().selectionChanged.connect(self._selection_changed)
        self._job_table_model_ready = True

    @staticmethod
    def _empty_icon(size: int) -> QIcon:
        canvas = max(24, size + 8)
        pixmap = QPixmap(canvas, canvas)
        pixmap.fill(Qt.GlobalColor.transparent)
        return QIcon(pixmap)

    def _set_deferred_icon(self, widget, glyph: str, color: QColor, size: int) -> None:
        if self._deferred_icons_ready:
            widget.setIcon(fluent_icon(glyph, color, size))
            return
        widget.setIcon(self._empty_icon(size))
        widget.setIconSize(QSize(size + 2, size + 2))
        for index, (existing, _old_glyph, _old_color, _old_size) in enumerate(
            self._deferred_icon_specs
        ):
            if existing is widget:
                self._deferred_icon_specs[index] = (widget, glyph, color, size)
                return
        self._deferred_icon_specs.append((widget, glyph, color, size))

    def _apply_deferred_icons(self) -> None:
        if self._deferred_icons_ready:
            return
        self._deferred_icons_ready = True
        specs = self._deferred_icon_specs
        self._deferred_icon_specs = []
        for widget, glyph, color, size in specs:
            try:
                widget.setIcon(fluent_icon(glyph, color, size))
            except RuntimeError:
                continue

    def _build_inspector(self) -> QWidget:
        _startup_trace("inspector:details:start")
        panel = QWidget()
        panel.setObjectName("inspectorPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        self.inspector_tabs = QTabWidget()
        self.inspector_tabs.setDocumentMode(True)
        layout.addWidget(self.inspector_tabs)

        details_page = QWidget()
        details_layout = QVBoxLayout(details_page)
        details_layout.setContentsMargins(10, 6, 10, 6)
        details_layout.setSpacing(3)
        detail_header = QHBoxLayout()
        detail_header.setSpacing(8)
        title_box = QVBoxLayout()
        title_box.setSpacing(0)
        self.detail_title = QLabel("未选择任务")
        self.detail_title.setWordWrap(True)
        self.detail_title.setTextFormat(Qt.TextFormat.PlainText)
        self.detail_title.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.detail_title.setObjectName("detailTitle")
        self.detail_path = QLabel("从任务队列中选择一项以查看详情")
        self.detail_path.setTextFormat(Qt.TextFormat.PlainText)
        self.detail_path.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.detail_path.setObjectName("secondaryText")
        title_box.addWidget(self.detail_title)
        title_box.addWidget(self.detail_path)
        detail_header.addLayout(title_box, 1)
        self.detail_state = QLabel("-")
        self.detail_state.setObjectName("detailState")
        self.detail_state.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        self.detail_phase = QLabel("阶段 · -")
        self.detail_phase.setObjectName("secondaryText")
        self.detail_phase.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop)
        state_box = QVBoxLayout()
        state_box.setSpacing(0)
        state_box.addWidget(self.detail_state)
        state_box.addWidget(self.detail_phase)
        detail_header.addLayout(state_box)
        details_layout.addLayout(detail_header)

        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(2)
        self.detail_values: Dict[str, QLabel] = {}
        detail_fields = (
            ("任务 ID", "id"),
            ("识别格式", "format"),
            ("条目数", "entries"),
            ("加密", "encrypted"),
            ("密码尝试", "attempts"),
            ("候选范围", "candidate"),
            ("输出位置", "output"),
            ("清理策略", "policy"),
            ("源包处置", "source"),
        )
        for index, (label_text, key) in enumerate(detail_fields):
            row = index // 3
            pair = index % 3
            label = QLabel(label_text)
            label.setObjectName("detailLabel")
            label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            value = QLabel("-")
            value.setTextFormat(Qt.TextFormat.PlainText)
            value.setObjectName("detailValue")
            value.setMaximumHeight(18)
            value.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.detail_values[key] = value
            grid.addWidget(label, row, pair * 2)
            grid.addWidget(value, row, pair * 2 + 1)
            grid.setColumnStretch(pair * 2 + 1, 1)
        details_layout.addLayout(grid)
        self.detail_error = QLabel()
        self.detail_error.setObjectName("detailError")
        self.detail_action = QLabel()
        self.detail_action.setObjectName("secondaryText")
        for label in (self.detail_error, self.detail_action):
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            label.hide()
            details_layout.addWidget(label)
        details_layout.addStretch(1)
        details_scroll = QScrollArea()
        details_scroll.setObjectName("detailsScroll")
        details_scroll.setFrameShape(QFrame.Shape.NoFrame)
        details_scroll.setWidgetResizable(True)
        details_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        details_scroll.setWidget(details_page)
        self.inspector_tabs.addTab(details_scroll, "任务详情")
        _startup_trace("inspector:details:end")

        _startup_trace("inspector:log:start")
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setObjectName("logOutput")
        self.log_output.document().setMaximumBlockCount(500)
        self.inspector_tabs.addTab(self.log_output, "运行日志")
        _startup_trace("inspector:log:end")
        return panel

    def _build_status_bar(self) -> None:
        status = self.statusBar()
        status.setSizeGripEnabled(False)
        self.status_state = QLabel("●  队列空闲")
        self.status_state.setObjectName("statusReady")
        status.addWidget(self.status_state)
        self.status_context = QLabel("拖入压缩包或使用“添加文件”")
        self.status_context.setObjectName("statusContext")
        self.status_context.setMinimumWidth(0)
        self.status_context.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        status.addWidget(self.status_context, 1)
        self.status_counts = QLabel("")
        self.status_counts.setObjectName("statusCounts")
        self.status_counts.hide()
        status.addPermanentWidget(self.status_counts)

    def _command_button(self, text: str, glyph: str, callback, *, primary=False, subtle=False) -> QPushButton:
        button = QPushButton(text)
        self._set_deferred_icon(
            button,
            glyph,
            QColor("#FFFFFF") if primary else COLOR_TEXT,
            14,
        )
        button.setIconSize(QSize(16, 16))
        if primary:
            button.setObjectName("primaryButton")
        elif subtle:
            button.setObjectName("subtleButton")
        button.clicked.connect(callback)
        return button

    def _queue_action_button(self, text: str, tooltip: str, callback) -> QPushButton:
        button = QPushButton(text)
        button.setObjectName("queueActionButton")
        button.setToolTip(tooltip)
        button.setAccessibleName(text)
        button.clicked.connect(callback)
        return button

    def _icon_button(self, glyph: str, tooltip: str, callback) -> QToolButton:
        button = QToolButton()
        button.setObjectName("compactIconButton")
        button.setIcon(fluent_icon(glyph, COLOR_MUTED, 14))
        button.setIconSize(QSize(15, 15))
        button.setFixedSize(28, 28)
        button.setToolTip(tooltip)
        button.setAccessibleName(tooltip)
        button.clicked.connect(callback)
        return button

    @staticmethod
    def _scan_mode_from_config(config: dict) -> str:
        if bool(config.get("deep_scan", False)):
            return SCAN_MODE_DEEP
        if bool(config.get("steganographier_compat_mode", True)):
            return SCAN_MODE_STEGANOGRAPHIER
        return SCAN_MODE_NORMAL

    def _scan_mode_changed(self, action: QAction) -> None:
        self._sync_config(silent=True)

    def _select_cleanup_policy(self, policy: str, checked: bool) -> None:
        if not checked:
            return
        previous = str(self.config.get("cleanup_policy", CleanupPolicy.KEEP.value))
        if policy == CleanupPolicy.PERMANENT.value:
            result = QMessageBox.warning(
                self,
                "确认永久删除",
                "永久删除源压缩包不可恢复，且只会在校验通过的任务上执行。\n\n确定继续吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if result != QMessageBox.StandardButton.Yes:
                self.cleanup_buttons.get(previous, self.cleanup_buttons[CleanupPolicy.KEEP.value]).setChecked(True)
                return
        self._sync_config(silent=True)

    def _config_candidate(self) -> dict:
        candidate = dict(self.config)
        candidate["target_dir"] = self.target_edit.text().strip()
        candidate["extract_to_source"] = self.extract_source_check.isChecked()
        candidate["extract_mode"] = "staging" if self.staging_check.isChecked() else "direct"
        candidate["nested_extraction"] = self.nested_check.isChecked()
        candidate["cleanup_policy"] = next(
            (policy for policy, button in self.cleanup_buttons.items() if button.isChecked()),
            CleanupPolicy.KEEP.value,
        )
        candidate["del_archive"] = candidate["cleanup_policy"] == CleanupPolicy.PERMANENT.value
        candidate["deep_scan"] = self.scan_actions[SCAN_MODE_DEEP].isChecked()
        candidate["steganographier_compat_mode"] = self.scan_actions[SCAN_MODE_STEGANOGRAPHIER].isChecked()
        candidate["_app_dir"] = get_app_dir()
        candidate["max_nested_depth"] = int(candidate.get("max_nested_depth", 2))
        candidate["wait_disk_space"] = bool(candidate.get("wait_disk_space", True))
        return candidate

    def _sync_config(self, *, silent: bool = False) -> bool:
        return self._apply_config(self._config_candidate(), silent=silent)

    def _apply_config(self, candidate: dict, *, silent: bool = False) -> bool:
        previous = dict(self.config)
        persisted = False
        scheduler_attempted = False
        try:
            save_config(candidate)
            persisted = True
            if self.scheduler is not None:
                scheduler_attempted = True
                self.scheduler.refresh_config(candidate)
        except Exception as exc:
            if scheduler_attempted and self.scheduler is not None:
                try:
                    self.scheduler.refresh_config(previous)
                except Exception:
                    logger.exception("Could not roll back scheduler configuration")
            if persisted:
                try:
                    save_config(previous)
                except Exception:
                    logger.exception("Could not roll back persisted configuration")
            self.config = previous
            self._restore_config_controls()
            self.log_event("CONFIG_APPLY_FAILED", detail=str(exc))
            self.statusBar().showMessage("设置保存或应用失败，已恢复上次设置。详情见运行日志。", 8000)
            if not silent:
                QMessageBox.critical(self, "配置应用失败", str(exc))
            return False
        self.config = candidate
        if self.scheduler is not None:
            self.scheduler.set_session_main_password(self._main_password or None)
        return True

    def _open_settings(self) -> None:
        dialog = SettingsDialog(self.config, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        candidate = self._config_candidate()
        candidate.update(dialog.values())
        self._apply_config(candidate)

    def _main_password_changed(self, value: str) -> None:
        self._main_password = value
        if self.scheduler is not None:
            self.scheduler.set_session_main_password(value or None)

    def _restore_config_controls(self) -> None:
        controls = (
            self.target_edit,
            self.extract_source_check,
            self.staging_check,
            self.nested_check,
            *self.cleanup_buttons.values(),
            *self.scan_actions.values(),
        )
        previous_blocked = [control.blockSignals(True) for control in controls]
        try:
            self.target_edit.setText(str(self.config.get("target_dir", "")))
            self.extract_source_check.setChecked(bool(self.config.get("extract_to_source", True)))
            self.staging_check.setChecked(self.config.get("extract_mode", "staging") == "staging")
            self.nested_check.setChecked(bool(self.config.get("nested_extraction", False)))
            selected_policy = str(self.config.get("cleanup_policy", CleanupPolicy.KEEP.value))
            for policy, button in self.cleanup_buttons.items():
                button.setChecked(policy == selected_policy)
            selected_mode = self._scan_mode_from_config(self.config)
            for mode, action in self.scan_actions.items():
                action.setChecked(mode == selected_mode)
        finally:
            for control, was_blocked in zip(controls, previous_blocked):
                control.blockSignals(was_blocked)

    def _browse_target(self) -> None:
        value = QFileDialog.getExistingDirectory(self, "选择目标目录", self.target_edit.text())
        if value:
            self.target_edit.setText(value)
            self._sync_config(silent=True)

    def _setup_scheduler(self, *, background: bool = False) -> None:
        if self._closing or self._startup_pending or self.scheduler is not None:
            return
        if not self._stop_failed_startup_scheduler():
            self._show_startup_error(RuntimeError("上次启动的任务引擎尚未停止，请稍后重试。"))
            return
        _startup_trace("setup_scheduler:start")
        self._startup_pending = True
        self.startup_blocked = False
        self._startup_config_snapshot = dict(self.config)
        self._update_summary()
        from runtime_startup import SchedulerStartup

        config = dict(self.config)
        if background:
            self._startup_initializer = SchedulerStartup(
                lambda: self._create_startup_scheduler(config),
                lambda: self._post_to_ui(self._finish_scheduler_startup),
            )
            try:
                self._startup_initializer.start()
            except Exception as exc:
                self._show_startup_error(exc)
            return
        try:
            result = self._create_startup_scheduler(config)
        except Exception as exc:
            self._show_startup_error(exc)
            return
        self._install_startup_scheduler(result)

    def _create_startup_scheduler(self, config: dict):
        from runtime_startup import SchedulerStartupResult

        fallback = self._prepare_temp_dir(config)
        sevenzip = find_sevenzip(config)
        if not sevenzip:
            raise FileNotFoundError("找不到 7z.exe。请安装 7-Zip 或将 7z.exe 放在程序目录。")
        config["7z_path"] = sevenzip
        _startup_trace("setup_scheduler:construct")
        scheduler = _resolve_scheduler_class()(sevenzip, config, event_cb=self._scheduler_callback)
        _startup_trace("setup_scheduler:constructed")
        return SchedulerStartupResult(scheduler, config, fallback)

    def _finish_scheduler_startup(self) -> None:
        initializer = self._startup_initializer
        if initializer is None:
            return
        result, error = initializer.take_result()
        if error is not None:
            self._show_startup_error(error)
        elif result is not None:
            if self._install_startup_scheduler(result):
                self._start_startup_processing()

    def _install_startup_scheduler(self, result) -> bool:
        effective = dict(self.config)
        effective["7z_path"] = result.config["7z_path"]
        if result.fallback_temp and effective.get("temp_dir") == self._startup_config_snapshot.get("temp_dir"):
            effective["temp_dir"] = result.fallback_temp
            try:
                save_config(effective)
            except (OSError, TypeError, ValueError):
                self.log_event("CONFIG_APPLY_FAILED", detail="暂存目录回退设置未能保存")
            self._append_log_line(f"暂存目录不可写，已改用用户临时目录：{result.fallback_temp}")
        try:
            if effective != result.config:
                result.scheduler.refresh_config(effective)
            result.scheduler.set_session_main_password(self._main_password or None)
            result.scheduler.start()
        except Exception as exc:
            self._failed_startup_scheduler = result.scheduler
            self._stop_failed_startup_scheduler()
            self._show_startup_error(exc)
            return False
        self.config = effective
        self.scheduler = result.scheduler
        self._startup_pending = False
        self.startup_blocked = False
        self._log_recovery_messages(self.scheduler.recovery_messages)
        self.log_event("APP_READY")
        _startup_trace("run_app:scheduler_ready")
        pending, self._pending_startup_jobs = self._pending_startup_jobs, []
        accepted_keys = set()
        for job, auto_start in pending:
            if job.task_id not in self.jobs:
                continue
            if not self.scheduler.submit(job):
                self._remove_finished_ids({job.task_id})
            else:
                _classify, _child, logical_key = _resolve_scan_helpers()
                accepted_keys.add(logical_key(job.original_path or job.path))
                if auto_start:
                    self.scheduler.enable_processing()
        self.seen_paths.update(accepted_keys)
        if self._pending_scan_requests and not self._scan_active:
            roots, auto_start, snapshot = self._pending_scan_requests.pop(0)
            self._launch_scan(roots, auto_start, snapshot)
        self._update_summary()
        _flush_startup_trace()
        threading.Thread(
            target=cleanup_stale_sessions,
            args=((self.config.get("temp_dir") or tempfile.gettempdir()), []),
            daemon=True,
        ).start()
        return True

    def _stop_failed_startup_scheduler(self) -> bool:
        scheduler = self._failed_startup_scheduler
        if scheduler is None:
            return True
        try:
            if scheduler.stop() is False:
                return False
        except Exception:
            logger.exception("Could not stop a failed startup scheduler")
            return False
        self._failed_startup_scheduler = None
        return True

    def _show_startup_error(self, error: Exception) -> None:
        self._startup_pending = False
        self.startup_blocked = True
        self._append_log_line(f"任务引擎启动失败：{error}")
        self._update_summary()
        QMessageBox.critical(self, "任务引擎启动失败", f"{error}\n\n请在“选项”中修正设置，然后点击“重试启动”。")

    def _prepare_temp_dir(self, config: Optional[dict] = None) -> str:
        from runtime_startup import prepare_temp_directory

        return prepare_temp_directory(self.config if config is None else config)

    def _log_recovery_messages(self, messages) -> None:
        routine_count = 0
        always_show = []
        review_messages = []
        for raw_message in messages or ():
            message = str(raw_message).strip()
            if not message:
                continue
            if message.startswith(_RECOVERY_ROUTINE_PREFIXES):
                routine_count += 1
            elif message.startswith(_RECOVERY_ALWAYS_SHOW_PREFIXES):
                always_show.append(message)
            else:
                review_messages.append(message)

        if always_show or review_messages:
            self._disable_context_auto_close(abnormal=True)
        if routine_count:
            self.log_event("RECOVERY_AUTO_RESOLVED", count=routine_count)
        for message in always_show + review_messages:
            logger.warning("Startup recovery needs review: %s", message)
        for message in always_show + review_messages[:MAX_RECOVERY_LOG_DETAILS]:
            self.log_event("RECOVERY_REVIEW", detail=message)
        omitted = len(review_messages) - MAX_RECOVERY_LOG_DETAILS
        if omitted > 0:
            journal_path = ""
            if self.scheduler is not None:
                journal = getattr(self.scheduler, "recovery_journal", None)
                journal_path = str(getattr(journal, "path", "") or "")
            self.log_event("RECOVERY_MORE", count=omitted, detail=journal_path)

    def _scheduler_callback(self, event_type, job, *args, **kwargs) -> None:
        if self._closing:
            return
        self.bridge.scheduler_event.emit(str(event_type), job, tuple(args), dict(kwargs))

    def _post_to_ui(self, callback, *args) -> bool:
        if self._closing:
            return False
        self.bridge.invoke.emit(callback, tuple(args))
        return True

    @Slot(object, tuple)
    def _invoke_on_ui(self, callback, args) -> None:
        if self._closing:
            return
        try:
            callback(*args)
        except Exception:
            logger.exception("Qt callback failed")
            self._append_log_line("界面回调失败，请查看日志。")

    def _start_startup_processing(self) -> bool:
        if (
            self._closing
            or self._shutdown_complete
            or self._startup_processing_scheduled
            or self._startup_args_processed
        ):
            return False
        self._startup_processing_scheduled = True
        # Defer until the event loop turns once so the already-built window
        # can paint, without adding a fixed right-click latency.
        QTimer.singleShot(0, self._process_startup_args)
        return True

    def _process_startup_args(self) -> None:
        self._startup_processing_scheduled = False
        if (
            self._closing
            or self._shutdown_complete
            or self._startup_args_processed
            or self.scheduler is None
        ):
            return
        self._startup_args_processed = True
        _startup_trace(f"startup_args:{self.startup_args!r}")
        if self.startup_args:
            self._process_external_paths(
                self.startup_args,
                auto_start=self.startup_auto_start,
                source="CLI",
                cleanup_policy=self.startup_cleanup_policy,
                extract_to_source=self.startup_extract_to_source,
                context_menu=self.startup_context_menu,
            )

    def process_ipc_args(
        self,
        args,
        auto_start=True,
        cleanup_policy=CleanupPolicy.KEEP.value,
        extract_to_source=False,
        context_menu=False,
    ) -> bool:
        if not isinstance(context_menu, bool):
            self._disable_context_auto_close(abnormal=True)
            return False
        if not context_menu:
            self._disable_context_auto_close()
        if not isinstance(cleanup_policy, str) or cleanup_policy not in EXTERNAL_CLEANUP_POLICIES:
            if context_menu:
                self._disable_context_auto_close(abnormal=True)
            return False
        if not isinstance(extract_to_source, bool):
            if context_menu:
                self._disable_context_auto_close(abnormal=True)
            return False
        return self._process_external_paths(
            args,
            auto_start=bool(auto_start),
            source="IPC",
            cleanup_policy=cleanup_policy,
            extract_to_source=extract_to_source,
            context_menu=context_menu,
        )

    def activate_window(self, *, disarm_context_auto_close: bool = True) -> bool:
        if disarm_context_auto_close:
            self._disable_context_auto_close()
        if self._closing:
            return False
        screen = QApplication.primaryScreen()
        if screen is not None and not screen.availableGeometry().intersects(self.frameGeometry()):
            self._place_center()
        self.showNormal()
        self.raise_()
        self.activateWindow()
        return True

    def _place_center(self) -> None:
        screen = self.screen() or QApplication.primaryScreen()
        if screen is None:
            return
        available = screen.availableGeometry()
        size = self.size()
        self.move(
            available.center()
            - QPoint(max(1, size.width() // 2), max(1, size.height() // 2))
        )

    def _process_external_paths(
        self,
        paths,
        *,
        auto_start: bool,
        source: str,
        cleanup_policy: str = CleanupPolicy.KEEP.value,
        extract_to_source: bool = False,
        context_menu: bool = False,
    ) -> bool:
        _startup_trace(f"external_paths:{list(paths)!r}:auto={auto_start}:source={source}")
        config_snapshot = dict(self.config)
        config_snapshot["cleanup_policy"] = cleanup_policy
        config_snapshot["del_archive"] = cleanup_policy == CleanupPolicy.PERMANENT.value
        config_snapshot["_extract_to_source_override"] = bool(extract_to_source)
        accepted = False
        for raw_path in paths:
            if not isinstance(raw_path, str):
                continue
            path = os.path.normpath(raw_path)
            if os.path.isdir(path):
                accepted = self._start_scan([path], auto_start=auto_start, config_snapshot=config_snapshot) or accepted
            elif os.path.isfile(path):
                accepted = self._enqueue_path(
                    path,
                    auto_start=auto_start,
                    explicit_input=True,
                    config_snapshot=config_snapshot,
                ) or accepted
        if accepted:
            _startup_trace("external_paths:accepted")
            file_count = sum(
                1 for p in paths if isinstance(p, str) and os.path.isfile(p)
            )
            directory_count = sum(
                1 for p in paths if isinstance(p, str) and os.path.isdir(p)
            )
            self.log_event(
                "EXTERNAL_PATHS_RECEIVED",
                context=source,
                file_count=file_count,
                directory_count=directory_count,
                mode_zh="已自动开始" if auto_start else "等待手动开始",
                mode_en="started automatically" if auto_start else "waiting for manual start",
            )
            if context_menu:
                self._note_context_menu_request()
        elif context_menu:
            _startup_trace("external_paths:rejected_context")
            self._disable_context_auto_close(abnormal=True)
        return accepted

    @Slot(str, object, tuple, dict)
    def _handle_scheduler_event(self, event_type: str, job: Job, args: tuple, kwargs: dict) -> None:
        if self._closing or not isinstance(job, Job) or job.task_id in self._suppressed_job_ids:
            return
        state = args[0] if event_type == "state_change" and args else job.state
        if event_type == "job_submitted":
            self._upsert_job(job)
        elif event_type in {"job_resubmitted", "state_change", "user_notice", "password_promoted"}:
            self._upsert_job(job)
            if event_type == "state_change":
                progress = args[2] if len(args) > 2 else getattr(job, "progress", 0)
                if isinstance(progress, (int, float)) and progress >= 0:
                    job.progress = max(0, min(100, int(progress)))
                if state == JobState.FAILED:
                    context = Path(job.display_path).name
                    if (
                        job.source_retention_reason in ARCHIVE_BLOCK_REASONS
                        or str(job.source_retention_reason or "").startswith("unsafe_")
                    ):
                        self.log_event(
                            "ARCHIVE_BLOCKED",
                            context=context,
                            detail=job.error_message or "",
                        )
                    else:
                        category = getattr(job.error_category, "name", None)
                        self.log_event(
                            "JOB_FAILED",
                            context=context,
                            category=category or "UNCLASSIFIED",
                        )
                elif state == JobState.PARTIAL_RECOVERY:
                    self.log_event("JOB_PARTIAL_RECOVERY", context=Path(job.display_path).name)
                elif state == JobState.INTERRUPTED:
                    self.log_event("JOB_INTERRUPTED", context=Path(job.display_path).name)
                elif state == JobState.PASSWORD_REQUIRED:
                    self.log_event("JOB_PASSWORD_REQUIRED", context=Path(job.display_path).name)
            if event_type == "user_notice" and args:
                message = str(args[0] or "")
                context = Path(job.display_path).name
                if user_message_code(message) in CLEANUP_NOTICE_CODES:
                    self._append_log_line(f"{context}: {message}")
                elif message:
                    self.log_event("USER_NOTICE", context=context, detail=message)
            if event_type == "password_promoted":
                self.log_event("PASSWORD_PROMOTED")
        elif event_type == "password_required":
            self._upsert_job(job)
            self._queue_password_prompt(job)
        elif event_type == "stego_review_required":
            self._upsert_job(job)
            self._queue_stego_prompt(job)
        elif event_type == "job_duplicate":
            self._append_log_line(f"{Path(job.display_path).name}: 已在队列中，跳过重复项")
        elif event_type in {
            "job_complete",
            "job_partial",
            "job_failed",
            "job_interrupted",
            "job_skipped",
        }:
            self._upsert_job(job)
            self._dismiss_prompts_for_job(job)
            if event_type == "job_complete":
                self._append_log_line(f"{Path(job.display_path).name}: 已完成")
            elif event_type == "job_partial":
                self._disable_context_auto_close(abnormal=True)
                self._append_log_line(f"{Path(job.display_path).name}: 部分恢复")
            elif event_type == "job_failed":
                self._disable_context_auto_close(abnormal=True)
                self._append_log_line(f"{Path(job.display_path).name}: 失败 {job.error_message or ''}".strip())
            elif event_type == "job_interrupted":
                self._disable_context_auto_close(abnormal=True)
                self._append_log_line(f"{Path(job.display_path).name}: 已中断")
            elif event_type == "job_skipped":
                self._disable_context_auto_close(abnormal=True)
                self._append_log_line(f"{Path(job.display_path).name}: 已跳过")
        elif event_type == "intake_full":
            self.log_event("INTAKE_FULL", context=Path(job.display_path).name)
        elif event_type == "job_deferred":
            self._append_log_line(f"{Path(job.display_path).name}: 已暂存，等待扫描完成")
        self._update_summary()
        self._schedule_context_auto_close_check()

    def _upsert_job(self, job: Job) -> None:
        if job.task_id in self._suppressed_job_ids:
            return
        self._ensure_job_table_model()
        self.jobs[job.task_id] = job
        self.job_model.upsert(job)
        self._update_summary()
        if self.job_model.row_for_id(job.task_id) >= 0:
            self.job_table.viewport().update()
        selected = self._selected_job()
        if selected is not None and selected.task_id == job.task_id:
            self._update_details(job)

    def _selected_job(self) -> Optional[Job]:
        self._ensure_job_table_model()
        selection = self.job_table.selectionModel().selectedRows()
        if not selection:
            return None
        return self.job_model.job_at(selection[0].row())

    def _selected_jobs(self) -> List[Job]:
        self._ensure_job_table_model()
        return [
            job
            for index in self.job_table.selectionModel().selectedRows()
            if (job := self.job_model.job_at(index.row())) is not None
        ]

    def _selection_changed(self, _selected, _deselected) -> None:
        self._update_details(self._selected_job())
        self._update_queue_action_states()

    def _update_details(self, job: Optional[Job]) -> None:
        self.detail_error.clear()
        self.detail_error.hide()
        self.detail_action.clear()
        self.detail_action.hide()
        if job is None:
            self.detail_title.setText("未选择任务")
            self.detail_title.setToolTip("")
            self.detail_path.setText("从任务队列中选择一项以查看详情")
            self.detail_path.setToolTip("")
            self.detail_state.setText("-")
            self.detail_state.setStyleSheet("")
            self.detail_phase.setText("阶段 · -")
            for value in self.detail_values.values():
                value.setText("-")
                value.setToolTip("")
            return
        self.detail_title.setText(elide_path_middle(Path(job.display_path).name, limit=100))
        self.detail_title.setToolTip(Path(job.display_path).name)
        self.detail_path.setText(elide_path_middle(job.display_path))
        self.detail_path.setToolTip(job.display_path)
        state_label = STATUS_DISPLAY.get(job.state, job.state.value)
        color = state_color(job.state).name()
        self.detail_state.setText(state_label)
        self.detail_state.setStyleSheet(f"color: {color}; font-weight: 600;")
        self.detail_phase.setText(phase_summary(job.state, job.state_history))
        manifest = getattr(job, "manifest", None)
        extraction = getattr(job, "extraction_result", None)
        self.detail_values["id"].setText(job.task_id[:18])
        self.detail_values["format"].setText(getattr(manifest, "format", "-") or "-")
        entry_count = getattr(manifest, "entry_count", 0) if manifest is not None else 0
        if not entry_count and extraction is not None:
            entry_count = getattr(extraction, "output_file_count", 0) or 0
        self.detail_values["entries"].setText(str(entry_count) if entry_count else "-")
        if manifest is None:
            encrypted = "-"
        else:
            encrypted = "是" if bool(getattr(manifest, "is_encrypted", False)) else "否"
        self.detail_values["encrypted"].setText(encrypted)
        attempts = int(getattr(job, "attempt_count", 0) or 0)
        self.detail_values["attempts"].setText(str(attempts))
        self.detail_values["candidate"].setText(
            f"{len(job.stego_candidates)} 个" if job.stego_candidates else "-"
        )
        output_text = job.final_destination or self.config.get("target_dir", "-") or "-"
        output_label = self.detail_values["output"]
        output_label.setText(elide_path_middle(output_text, limit=60))
        output_label.setToolTip(output_text if output_text != "-" else "")
        self.detail_values["policy"].setText(cleanup_policy_text(job.cleanup_policy_snapshot))
        self.detail_values["source"].setText(retention_text(job))
        if job.error_message or job.error_category:
            category = job.error_category.value if job.error_category else "unknown"
            self.detail_error.setText(f"{category}: {job.error_message or STATUS_DISPLAY.get(job.state, job.state.value)}")
            self.detail_error.show()
            self.detail_action.setText(error_action_text(job.error_category))
            self.detail_action.show()

    def _update_summary(self) -> None:
        total = len(self.jobs)
        done = sum(job.state in TERMINAL_STATES for job in self.jobs.values())
        succeeded = sum(job.state == JobState.COMPLETE for job in self.jobs.values())
        active = sum(job.state in PROCESSING_STATES for job in self.jobs.values())
        if total:
            total_value = int(done * 100 / total)
        else:
            total_value = 0
        self.total_progress.setValue(total_value)
        self.total_progress_label.setText(f"{total_value}%")
        current = self.scheduler.current_job if self.scheduler else None
        if current is None:
            current = next(
                (job for job in self.jobs.values() if job.state in PROCESSING_STATES),
                None,
            )
        current_value = int(getattr(current, "progress", 0) or 0)
        self.current_progress.setValue(max(0, min(100, current_value)))
        self.current_progress_label.setText(f"{current_value}%")
        self.queue_count_label.setText(f"{total} 个任务")
        pending = len(self._pending_scan_requests)
        if self.scheduler is not None:
            pending += int(self.scheduler.deferred_intake_size())
        self.pending_count_label.setText(f"待接收 {pending}")
        self.progress_summary_text.setText(f"{succeeded} 成功 · {done} 已结束 · {active} 处理中")

        blocker_states = (
            JobState.PASSWORD_REQUIRED,
            JobState.STEGO_CANDIDATE_REVIEW,
            JobState.SPACE_WAIT,
        )
        blocker = next(
            (
                job
                for state in blocker_states
                for job in self.jobs.values()
                if job.state == state
            ),
            None,
        )
        abnormal_states = {
            JobState.PARTIAL_RECOVERY,
            JobState.FAILED,
            JobState.INTERRUPTED,
            JobState.SKIPPED,
        }
        abnormal = [job for job in self.jobs.values() if job.state in abnormal_states]
        attention_count = sum(job.state in blocker_states for job in self.jobs.values()) + len(abnormal)
        remaining = max(0, total - done)

        def compact_name(job: Optional[Job]) -> str:
            if job is None:
                return ""
            name = Path(job.display_path).name
            if len(name) <= 54:
                return name
            return f"{name[:31]}...{name[-18:]}"

        processing_enabled = self._scheduler_processing_enabled()
        if self._startup_pending:
            self.status_state.setText("●  正在启动")
            self.status_state.setObjectName("statusActive")
            self.status_context.setText("正在检查恢复状态并准备任务引擎")
        elif self.startup_blocked and self.scheduler is None:
            self.status_state.setText("●  启动受阻")
            self.status_state.setObjectName("statusError")
            self.status_context.setText("修正选项后重试启动；已接收的任务仍在队列中")
        elif self._scan_active:
            self.status_state.setText("●  正在扫描")
            self.status_state.setObjectName("statusActive")
            self.status_context.setText(f"{self._scan_mode_label()} · 已发现 {self._scan_found} 项")
        elif blocker is not None:
            blocker_text = {
                JobState.PASSWORD_REQUIRED: "等待输入密码",
                JobState.STEGO_CANDIDATE_REVIEW: "等待选择隐写候选",
                JobState.SPACE_WAIT: "等待释放磁盘空间",
            }.get(blocker.state, STATUS_DISPLAY.get(blocker.state, blocker.state.value))
            self.status_state.setText("●  需要处理")
            self.status_state.setObjectName("statusWarning")
            self.status_context.setText(f"{compact_name(blocker)} · {blocker_text}")
        elif active:
            self.status_state.setText("●  正在处理")
            self.status_state.setObjectName("statusActive")
            phase = STATUS_DISPLAY.get(current.state, current.state.value) if current else "处理中"
            self.status_context.setText(f"{compact_name(current)} · {phase}")
        elif total and done == total:
            if abnormal:
                self.status_state.setText("●  已结束，有未成功项")
                self.status_state.setObjectName(
                    "statusWarning" if all(job.state == JobState.SKIPPED for job in abnormal) else "statusError"
                )
                self.status_context.setText(f"{succeeded} 项成功，{len(abnormal)} 项未成功，请检查任务详情或运行日志")
            else:
                self.status_state.setText("●  全部完成")
                self.status_state.setObjectName("statusDone")
                self.status_context.setText(f"{done} 项任务已完成")
        elif total:
            self.status_state.setText("●  等待调度" if processing_enabled else "●  队列已暂停")
            self.status_state.setObjectName("statusReady")
            self.status_context.setText(f"{remaining} 项尚未完成")
        else:
            self.status_state.setText("●  队列空闲")
            self.status_state.setObjectName("statusReady")
            self.status_context.setText("拖入压缩包或使用“添加文件”")

        if total:
            count_text = f"待完成 {remaining} · 成功 {succeeded} · 已结束 {done}"
            if attention_count:
                count_text += f" · 需处理 {attention_count}"
            self.status_counts.setText(count_text)
            self.status_counts.show()
        else:
            self.status_counts.clear()
            self.status_counts.hide()
        self.status_state.style().unpolish(self.status_state)
        self.status_state.style().polish(self.status_state)
        self._update_queue_action_states()

    def _scheduler_processing_enabled(self) -> bool:
        if self.scheduler is not None:
            latch = getattr(self.scheduler, "processing_enabled", None)
            if latch is not None and hasattr(latch, "is_set"):
                return bool(latch.is_set())
        return bool(self._processing_requested)

    def _update_queue_action_states(self) -> None:
        if not hasattr(self, "cancel_current_button"):
            return
        current = self.scheduler.current_job if self.scheduler is not None else None
        current_active = bool(current is not None and current.state not in TERMINAL_STATES)
        selected = (
            self._selected_jobs()
            if getattr(self, "_job_table_model_ready", False)
            else []
        )
        selected_active = any(job.state not in TERMINAL_STATES for job in selected)
        terminal_exists = any(job.state in TERMINAL_STATES for job in self.jobs.values())
        noncurrent_pending = any(
            job.state not in TERMINAL_STATES
            and (current is None or job.task_id != current.task_id)
            for job in self.jobs.values()
        )
        deferred = 0
        if self.scheduler is not None:
            try:
                deferred = int(self.scheduler.deferred_intake_size())
            except (AttributeError, TypeError, ValueError):
                deferred = 0
        can_cancel_pending = bool(
            self._scan_active or self._pending_scan_requests or noncurrent_pending or deferred
        )
        self.cancel_current_button.setEnabled(current_active)
        self.cancel_selected_button.setEnabled(selected_active)
        self.clear_finished_button.setEnabled(terminal_exists)
        self.cancel_pending_button.setEnabled(can_cancel_pending)

        has_work = bool(
            any(job.state not in TERMINAL_STATES for job in self.jobs.values())
            or self._scan_active
            or self._pending_scan_requests
            or deferred
        )
        self._processing_requested = self._scheduler_processing_enabled()
        if self._startup_pending or (self.startup_blocked and self.scheduler is None):
            self.start_button.setEnabled(not self._startup_pending)
            self.start_button.setText("正在启动" if self._startup_pending else "重试启动")
            return
        self.start_button.setEnabled(self.scheduler is not None and has_work)
        if self._processing_requested and has_work:
            self.start_button.setText("暂停队列")
            self._set_deferred_icon(self.start_button, "\ue769", QColor("#FFFFFF"), 14)
        else:
            self.start_button.setText("开始")
            self._set_deferred_icon(self.start_button, "\ue768", QColor("#FFFFFF"), 14)

    def _append_log_line(self, message: str) -> None:
        text = " ".join(str(message).replace("\x00", "").splitlines()).strip()
        if not text:
            return
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        prefix = f"[{stamp}] "
        whole_line, spans = user_message_red_spans(text)
        if not whole_line and not spans:
            self.log_output.appendPlainText(prefix + text)
            return
        # The manual promises red marking for failed jobs and for notices that
        # need review, so only those lines take the rich-text path.
        color = COLOR_DANGER.name()
        if whole_line:
            self.log_output.appendHtml(
                f'<span style="color:{color};">'
                f"{_log_html_escape(prefix + text)}</span>"
            )
            return
        pieces = []
        cursor = 0
        for start, end in spans:
            pieces.append(_log_html_escape(text[cursor:start]))
            pieces.append(
                f'<span style="color:{color};">{_log_html_escape(text[start:end])}</span>'
            )
            cursor = end
        pieces.append(_log_html_escape(text[cursor:]))
        self.log_output.appendHtml(f"{_log_html_escape(prefix)}{''.join(pieces)}")

    def log_event(self, code: str, **values) -> None:
        self._append_log_line(format_user_message(code, **values))

    def _queue_password_prompt(self, job: Job) -> None:
        if self._current_pwd_job and self._current_pwd_job.task_id == job.task_id:
            return
        if any(item.task_id == job.task_id for item in self._pending_pwd_jobs):
            return
        if self._current_pwd_job is None:
            self._current_pwd_job = job
            self._show_password_prompt()
        else:
            self._pending_pwd_jobs.append(job)

    def _show_password_prompt(self) -> None:
        self._ensure_activity_shelf()
        job = self._current_pwd_job
        if job is None:
            self._reset_password_prompt()
            self._sync_activity_visibility()
            return
        self.password_title.setToolTip(job.display_path)
        self.password_title.setText(self.password_title.fontMetrics().elidedText(
            f"需要密码   {Path(job.display_path).name}", Qt.TextElideMode.ElideMiddle, 240
        ))
        self.password_edit.clear()
        self.password_reveal_button.setChecked(False)
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.activity_stack.setCurrentWidget(self.password_activity_page)
        self._sync_activity_visibility()
        self.password_edit.setFocus()

    def _submit_password(self) -> None:
        job = self._current_pwd_job
        if job is None or self.scheduler is None:
            return
        password = self.password_edit.text()
        self.scheduler.submit_password_response(job, password)
        self._current_pwd_job = None
        self._show_next_password_prompt()

    def _skip_password(self) -> None:
        job = self._current_pwd_job
        if job is None or self.scheduler is None:
            return
        self.scheduler.skip_password_job(job)
        self._current_pwd_job = None
        self._show_next_password_prompt()

    def _show_next_password_prompt(self) -> None:
        if self._pending_pwd_jobs:
            self._current_pwd_job = self._pending_pwd_jobs.pop(0)
            self._show_password_prompt()
        else:
            self._reset_password_prompt()
            self._sync_activity_visibility()

    def _reset_password_prompt(self) -> None:
        self._ensure_activity_shelf()
        self.password_edit.clear()
        self.password_reveal_button.setChecked(False)
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_title.setText("需要密码")

    def _dismiss_prompts_for_job(self, job: Job) -> None:
        self._pending_pwd_jobs = [item for item in self._pending_pwd_jobs if item.task_id != job.task_id]
        self._pending_stego_jobs = [item for item in self._pending_stego_jobs if item.task_id != job.task_id]
        if self._current_pwd_job and self._current_pwd_job.task_id == job.task_id:
            self._current_pwd_job = None
            self._show_next_password_prompt()
        if self._current_stego_job and self._current_stego_job.task_id == job.task_id:
            self._current_stego_job = None
            self._show_next_stego_prompt()

    def _queue_stego_prompt(self, job: Job) -> None:
        if self._current_stego_job and self._current_stego_job.task_id == job.task_id:
            return
        if any(item.task_id == job.task_id for item in self._pending_stego_jobs):
            return
        if self._current_stego_job is None:
            self._current_stego_job = job
            self._show_stego_prompt()
        else:
            self._pending_stego_jobs.append(job)

    def _show_stego_prompt(self) -> None:
        self._ensure_activity_shelf()
        job = self._current_stego_job
        if job is None:
            self._sync_activity_visibility()
            return
        self.stego_title.setToolTip(job.display_path)
        self.stego_title.setText(self.stego_title.fontMetrics().elidedText(
            f"选择隐写候选   {Path(job.display_path).name}", Qt.TextElideMode.ElideMiddle, 240
        ))
        self.stego_combo.clear()
        for index, candidate in enumerate(job.stego_candidates):
            recommended = index == job.stego_recommended_index
            confidence = {"high": "高", "medium": "中", "low": "低"}.get(candidate.confidence.value, "未知")
            prefix = "推荐" if recommended else f"候选 {index + 1}"
            label = f"{prefix} · {candidate.embedded_format or '未知格式'} · {format_size_bytes(candidate.size)} · 置信度{confidence}"
            self.stego_combo.addItem(label, index)
            self.stego_combo.setItemData(
                index,
                f"模式：{candidate.mode}\n范围：{candidate.start_offset:,} - {candidate.end_offset:,}\n"
                f"校验：{', '.join(candidate.validation_flags) or '无'}",
                Qt.ItemDataRole.ToolTipRole,
            )
        self.stego_combo.setCurrentIndex(
            job.stego_recommended_index if job.stego_recommended_index is not None else -1
        )
        self.stego_combo.setPlaceholderText("请选择候选")
        self._sync_activity_visibility()

    def _submit_stego(self) -> None:
        job = self._current_stego_job
        if job is None or self.scheduler is None:
            return
        index = self.stego_combo.currentData()
        if index is None:
            return
        self.scheduler.submit_stego_selection(job, int(index))
        self._current_stego_job = None
        self._show_next_stego_prompt()

    def _skip_stego(self) -> None:
        job = self._current_stego_job
        if job is None or self.scheduler is None:
            return
        self.scheduler.submit_stego_selection(job, None)
        self._current_stego_job = None
        self._show_next_stego_prompt()

    def _show_next_stego_prompt(self) -> None:
        if self._pending_stego_jobs:
            self._current_stego_job = self._pending_stego_jobs.pop(0)
            self._show_stego_prompt()
        else:
            self._sync_activity_visibility()

    def _sync_activity_visibility(self) -> None:
        if self._current_pwd_job is not None:
            self._ensure_activity_shelf()
            self.activity_stack.setCurrentWidget(self.password_activity_page)
            self.activity_shelf.show()
        elif self._current_stego_job is not None:
            self._ensure_activity_shelf()
            self.activity_stack.setCurrentWidget(self.stego_activity_page)
            self.activity_shelf.show()
        elif self._scan_active:
            self._ensure_activity_shelf()
            self.activity_stack.setCurrentWidget(self.scan_activity_page)
            self.activity_shelf.show()
        else:
            self.activity_shelf.hide()

    def _add_files(self) -> None:
        files, _selected = QFileDialog.getOpenFileNames(
            self,
            "添加压缩文件",
            "",
            "所有文件 (*.*);;压缩文件 (*.7z *.rar *.zip *.tar *.gz *.tgz *.bz2 *.xz *.iso *.cab *.001)",
        )
        for path in files:
            self._enqueue_path(path, auto_start=False, explicit_input=True)

    def _scan_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "选择扫描目录")
        if folder:
            self._start_scan([folder], auto_start=False)

    def _enqueue_path(
        self,
        path: str,
        *,
        auto_start: bool = False,
        explicit_input: bool = True,
        config_snapshot: Optional[dict] = None,
        precomputed_candidates=None,
    ) -> bool:
        _startup_trace(f"enqueue:start:{path}")
        if self.scheduler is None and (self._startup_pending or self.startup_blocked):
            normalized = os.path.normpath(path)
            if not os.path.isfile(normalized) or len(self._pending_startup_jobs) >= IPC_MAX_PATHS:
                return False
            key = os.path.normcase(os.path.abspath(normalized))
            if any(os.path.normcase(os.path.abspath(job.path)) == key for job, _auto in self._pending_startup_jobs):
                return False
            snapshot = dict(config_snapshot or self.config)
            job = Job(
                path=normalized,
                original_path=normalized,
                original_basename=Path(normalized).name,
                cleanup_policy_snapshot=str(snapshot.get("cleanup_policy") or CleanupPolicy.KEEP.value),
                extract_to_source_override=bool(snapshot.get("_extract_to_source_override", False)),
                explicit_input=bool(explicit_input),
                stego_candidates=list(precomputed_candidates or ()),
            )
            self._pending_startup_jobs.append((job, bool(auto_start)))
            self._upsert_job(job)
            self._update_summary()
            return True
        _classify, _is_child, _logical_key = _resolve_scan_helpers()
        try:
            normalized = os.path.normpath(path)
            logical_key = _logical_key(normalized)
        except (OSError, ValueError):
            return False
        if not os.path.isfile(normalized) or logical_key in self.seen_paths:
            return False
        job_config = dict(config_snapshot or self.config)
        policy = str(job_config.get("cleanup_policy", CleanupPolicy.KEEP.value) or CleanupPolicy.KEEP.value)
        job = Job(
            path=normalized,
            original_path=normalized,
            original_basename=Path(normalized).name,
            cleanup_policy_snapshot=policy,
            extract_to_source_override=bool(job_config.get("_extract_to_source_override", False)),
            explicit_input=bool(explicit_input),
            stego_candidates=list(precomputed_candidates or ()),
        )
        if self.scheduler is None:
            return False
        accepted = bool(self.scheduler.submit(job))
        if not accepted:
            _startup_trace("enqueue:rejected")
            return False
        _startup_trace(f"enqueue:accepted:{job.task_id}:auto={auto_start}")
        self.seen_paths.add(logical_key)
        if auto_start:
            self.scheduler.enable_processing()
            self._processing_requested = True
        self._update_summary()
        return True

    def _start_scan(self, roots: Sequence[str], *, auto_start: bool = False, config_snapshot: Optional[dict] = None) -> bool:
        normalized = []
        for root in roots:
            if not isinstance(root, str):
                continue
            value = os.path.normcase(os.path.realpath(os.path.abspath(root)))
            if os.path.isdir(value) and value not in normalized:
                normalized.append(value)
        if not normalized:
            return False
        snapshot = dict(config_snapshot or self.config)
        if self._scan_active or (self.scheduler is None and (self._startup_pending or self.startup_blocked)):
            if len(self._pending_scan_requests) >= IPC_MAX_PATHS:
                return False
            self._pending_scan_requests.append((normalized, bool(auto_start), snapshot))
            self._update_summary()
            return True
        self._launch_scan(normalized, bool(auto_start), snapshot)
        return True

    def _launch_scan(self, roots: List[str], auto_start: bool, config_snapshot: dict) -> None:
        if self._closing:
            return
        self._retired_scan_threads = [thread for thread in self._retired_scan_threads if thread.is_alive()]
        self._scan_generation += 1
        generation = self._scan_generation
        self._scan_cancel = cancel_event = threading.Event()
        self._scan_active = True
        self._scan_found = 0
        self._scan_auto_start = bool(auto_start)
        self._scan_config_snapshot = dict(config_snapshot)
        self._show_scan_activity()
        self._append_log_line(f"开始扫描 {len(roots)} 个目录")

        def cancelled() -> bool:
            return cancel_event.is_set() or self._closing

        def worker() -> None:
            scanned = 0
            found = 0
            failure = ""
            last_path = ""
            # Heavy scan helpers are resolved on first scan, not at startup.
            _classify_auto, _is_child, _unused_logical = _resolve_scan_helpers()
            # UI progress is throttled; per-file candidate signals are not.
            last_progress_emit = [0.0]

            def emit_progress(count_scanned: int, count_found: int, path: str, pct: int, *, force: bool = False) -> None:
                now = time.monotonic()
                if force or now - last_progress_emit[0] >= 0.05:
                    last_progress_emit[0] = now
                    self.bridge.scan_progress.emit(count_scanned, count_found, path, pct, generation)

            try:
                archive_exts = set(ARCHIVE_EXTS)
                if self.scheduler is not None:
                    try:
                        archive_exts.update(self.scheduler.runner.supported_formats(timeout=15))
                    except Exception:
                        logger.exception("Could not query 7z supported formats")
                archive_exts = frozenset(
                    extension.casefold()
                    for extension in archive_exts
                    if isinstance(extension, str) and extension.startswith(".")
                )
                deep = bool(config_snapshot.get("deep_scan", False))
                compat = bool(config_snapshot.get("steganographier_compat_mode", True)) and not deep
                for root in roots:
                    for current_root, dirs, files in os.walk(root, followlinks=False):
                        if cancelled():
                            break
                        dirs[:] = [
                            name for name in dirs
                            if not os.path.islink(os.path.join(current_root, name))
                            and not is_reparse_point(os.path.join(current_root, name))
                        ]
                        for filename in files:
                            if cancelled():
                                break
                            full = os.path.join(current_root, filename)
                            if _is_child(full):
                                continue
                            scanned += 1
                            last_path = full
                            emit_progress(scanned, found, full, 0)
                            candidates = []
                            try:
                                if compat or deep:
                                    candidates = list(
                                        find_steganographier_candidates(
                                            full,
                                            cancel_check=cancelled,
                                        )
                                    )
                                if candidates:
                                    should_queue = True
                                else:
                                    decision = _classify_auto(
                                        full,
                                        archive_exts,
                                        cancel_check=cancelled,
                                        allow_full_embedded_scan=deep,
                                    )
                                    candidates = list(decision.candidates)
                                    should_queue = bool(decision.should_queue)
                                    if deep and decision.reason == "no_archive_structure":
                                        candidates = list(
                                            find_candidates(full, cancel_check=cancelled)
                                        )
                                        should_queue = bool(candidates)
                            except Exception:
                                logger.exception("Archive scan failed for %s", full)
                                should_queue = False
                            if should_queue and not cancelled():
                                found += 1
                                self.bridge.scan_candidate.emit(full, config_snapshot, candidates, False, generation)
                            emit_progress(scanned, found, full, 100)
                        if cancelled():
                            break
            except Exception as exc:
                logger.exception("Background scan failed")
                failure = f"{type(exc).__name__}: {exc}"
            finally:
                self.bridge.scan_finished.emit(found, failure, generation)

        self._scan_thread = threading.Thread(target=worker, name="Smart7zQtScan", daemon=True)
        self._scan_thread.start()

    def _show_scan_activity(self) -> None:
        self._ensure_activity_shelf()
        self._scan_active = True
        self.scan_progress.setValue(0)
        self.scan_percent.setText("0%")
        self.scan_title.setText("正在扫描")
        self.scan_meta.setText("准备中")
        self._sync_activity_visibility()

    @Slot(int, int, str, int, int)
    def _update_scan_progress(self, scanned: int, found: int, path: str, progress: int, generation: Optional[int] = None) -> None:
        if not self._accepts_scan_generation(generation):
            return
        self._ensure_activity_shelf()
        name = Path(path).name if path else "准备中"
        self.scan_title.setText(f"正在扫描   {name}")
        self.scan_meta.setText(f"第 {scanned} 个文件   ·   已发现 {found} 个任务   ·   {self._scan_mode_label()}")
        value = max(0, min(100, int(progress)))
        self.scan_progress.setValue(value)
        self.scan_percent.setText(f"{value}%")
        self._update_summary()

    def _accepts_scan_generation(self, generation: Optional[int]) -> bool:
        return (
            self._scan_active
            and not self._closing
            and not self._scan_cancel.is_set()
            and (generation is None or generation == self._scan_generation)
        )

    @Slot(str, object, object, bool, int)
    def _accept_scan_candidate(self, path: str, config_snapshot: dict, candidates, auto_start: bool, generation: Optional[int] = None) -> None:
        if not self._accepts_scan_generation(generation):
            return
        self._enqueue_path(
            path,
            auto_start=bool(auto_start),
            explicit_input=False,
            config_snapshot=dict(config_snapshot),
            precomputed_candidates=candidates,
        )

    @Slot(int, str, int)
    def _finish_scan(self, found: int, failure: str, generation: Optional[int] = None) -> None:
        if not self._accepts_scan_generation(generation):
            return
        self._scan_active = False
        if self._scan_thread is not None and self._scan_thread.is_alive():
            self._retired_scan_threads.append(self._scan_thread)
        self._scan_thread = None
        self._scan_config_snapshot = None
        if failure:
            self._disable_context_auto_close(abnormal=True)
            self.log_event("SCAN_FAILED", count=found, detail=failure)
        else:
            self.log_event("SCAN_COMPLETE", count=found)
        if getattr(self, "_scan_auto_start", False) and self.scheduler is not None:
            self.scheduler.enable_processing()
            self._processing_requested = True
        self._sync_activity_visibility()
        self._update_summary()
        if self._pending_scan_requests and not self._closing:
            roots, auto_start, config_snapshot = self._pending_scan_requests.pop(0)
            self._launch_scan(roots, auto_start, config_snapshot)
        else:
            self._schedule_context_auto_close_check()

    def _scan_mode_label(self) -> str:
        # 扫描进行中必须显示冻结的快照模式：扫描自身按 _launch_scan 收到的
        # config_snapshot 执行，若此处读实时 self.config，用户在扫描期间切换
        # 菜单会让标签与真正在跑的模式不符。
        mode = None
        if self._scan_active:
            snapshot = self._scan_config_snapshot
            if snapshot:
                mode = self._scan_mode_from_config(snapshot)
        if mode is None:
            mode = self._scan_mode_from_config(self.config)
        return {
            SCAN_MODE_DEEP: "深度扫描模式",
            SCAN_MODE_STEGANOGRAPHIER: "仅兼容隐写者模式",
            SCAN_MODE_NORMAL: "普通模式",
        }.get(mode, "普通模式")

    def _cancel_scan(self) -> None:
        self._scan_cancel.set()
        self._scan_generation += 1
        self._scan_active = False
        self._scan_auto_start = False
        self._scan_config_snapshot = None
        if self._scan_thread is not None and self._scan_thread.is_alive():
            self._retired_scan_threads.append(self._scan_thread)
        self._scan_thread = None
        self._pending_scan_requests.clear()
        self._append_log_line("扫描已取消，未接纳的扫描结果已丢弃")
        self._sync_activity_visibility()
        self._update_summary()

    def _toggle_processing(self) -> None:
        if self._processing_requested:
            self._pause_processing()
        else:
            self._start_processing()

    def _start_processing(self) -> None:
        if not self._sync_config():
            self.log_event("CONFIG_SYNC_FAILED")
            return
        if self.scheduler is None:
            if self.startup_blocked:
                self._setup_scheduler(background=True)
            return
        self.scheduler.resume_intake()
        self.scheduler.enable_processing()
        self._processing_requested = True
        self.status_state.setText("●  正在处理")
        self.log_event("QUEUE_STARTED")
        self._update_summary()

    def _pause_processing(self) -> None:
        if self.scheduler is not None:
            self.scheduler.disable_processing()
        self._processing_requested = False
        self._append_log_line("队列已暂停（当前任务会继续到安全阶段）")
        self._update_summary()

    def _cancel_current(self) -> None:
        if self.scheduler is not None and self.scheduler.current_job is not None:
            self.scheduler.cancel_current()
            self.log_event("CANCEL_CURRENT_REQUESTED")
        self._update_summary()

    def _cancel_remaining(self) -> None:
        self._cancel_scan()
        if self.scheduler is not None:
            removed = self.scheduler.discard_remaining()
            self._remove_finished_ids(removed)
            self.log_event("CANCEL_REMAINING")
        else:
            self._remove_finished_ids({job.task_id for job, _auto in self._pending_startup_jobs})
            self._pending_startup_jobs.clear()
        self._update_summary()

    def _clear_finished(self) -> None:
        if self.scheduler is not None:
            removed = set(self.scheduler.clear_finished())
        else:
            removed = {task_id for task_id, job in self.jobs.items() if job.state in TERMINAL_STATES}
        self._remove_finished_ids(removed)

    def _cancel_selected(self) -> None:
        jobs = [job for job in self._selected_jobs() if job.state not in TERMINAL_STATES]
        if not jobs:
            return
        task_ids = {job.task_id for job in jobs}
        if self.scheduler is not None:
            removed = self.scheduler.discard_jobs(task_ids)
            self._remove_finished_ids(removed)
            self.log_event("CANCEL_SELECTED")
        else:
            self._remove_finished_ids(task_ids)
            self.log_event("CANCEL_SELECTED")
        self._update_summary()

    def _remove_finished_ids(self, task_ids: Iterable[str]) -> None:
        self._ensure_job_table_model()
        _classify_unused, _child_unused, _logical_key = _resolve_scan_helpers()
        ids = set(task_ids)
        if not ids:
            return
        self._suppressed_job_ids.update(ids)
        self._pending_startup_jobs = [
            (job, auto_start) for job, auto_start in self._pending_startup_jobs
            if job.task_id not in ids
        ]
        self._pending_pwd_jobs = [job for job in self._pending_pwd_jobs if job.task_id not in ids]
        self._pending_stego_jobs = [job for job in self._pending_stego_jobs if job.task_id not in ids]
        if self._current_pwd_job and self._current_pwd_job.task_id in ids:
            self._current_pwd_job = None
            self._show_next_password_prompt()
        if self._current_stego_job and self._current_stego_job.task_id in ids:
            self._current_stego_job = None
            self._show_next_stego_prompt()
        for task_id in ids:
            job = self.jobs.pop(task_id, None)
            if job:
                for source in (job.path, job.original_path):
                    if source:
                        try:
                            self.seen_paths.discard(_logical_key(source))
                        except (OSError, ValueError):
                            pass
        self.job_model.remove_ids(ids)
        self._update_details(self._selected_job())
        self._update_summary()

    def _toggle_inspector(self) -> None:
        sizes = self.workspace_splitter.sizes()
        if self._inspector_expanded:
            self._inspector_sizes = sizes
            total = max(1, sum(sizes))
            self.workspace_splitter.setSizes([total, 1])
            self.inspector_toggle.setText("显示详情")
            self.inspector_toggle.setToolTip("显示任务详情和运行日志")
            self._inspector_expanded = False
        else:
            total = max(1, sum(sizes))
            expanded = self._inspector_sizes[1] if len(self._inspector_sizes) > 1 else 190
            self.workspace_splitter.setSizes([max(1, total - expanded), expanded])
            self.inspector_toggle.setText("隐藏详情")
            self.inspector_toggle.setToolTip("隐藏任务详情和运行日志")
            self._inspector_expanded = True

    def _register_context_menu(self) -> None:
        if register_context_menu():
            self._append_log_line("已添加资源管理器右键菜单")
            return
        QMessageBox.warning(self, "右键菜单", "添加右键菜单失败，请确认当前用户有注册表写入权限。")

    def _unregister_context_menu(self) -> None:
        if unregister_context_menu():
            self._append_log_line("已删除资源管理器右键菜单")
            return
        QMessageBox.warning(self, "右键菜单", "删除右键菜单失败。")

    def _note_context_menu_request(self) -> None:
        if not self._context_auto_close_armed or self._context_auto_close_abnormal or self._closing:
            return
        self._context_auto_close_generation += 1
        self._schedule_context_auto_close_check()

    def _schedule_context_auto_close_check(self) -> None:
        if not self._context_auto_close_armed or self._context_auto_close_abnormal or self._closing:
            return
        generation = self._context_auto_close_generation
        QTimer.singleShot(
            CONTEXT_AUTO_CLOSE_GRACE_MS,
            lambda generation=generation: self._maybe_auto_close_context(generation),
        )

    def _maybe_auto_close_context(self, generation: int) -> None:
        if (
            generation != self._context_auto_close_generation
            or not self._context_auto_close_armed
            or self._context_auto_close_abnormal
            or self._closing
            or not self.jobs
        ):
            return
        if any(job.state != JobState.COMPLETE for job in self.jobs.values()):
            return
        if self._scan_active or self._scan_thread is not None or self._pending_scan_requests:
            return
        if (
            self._current_pwd_job is not None
            or self._pending_pwd_jobs
            or self._current_stego_job is not None
            or self._pending_stego_jobs
        ):
            return
        if self.scheduler is not None:
            try:
                if self.scheduler.current_job is not None or self.scheduler.is_io_busy():
                    return
                deferred_size = getattr(self.scheduler, "deferred_intake_size", None)
                if callable(deferred_size) and deferred_size() != 0:
                    return
            except Exception:
                self._disable_context_auto_close(abnormal=True)
                logger.exception("Could not verify Qt context-menu completion state")
                return
        self.close()

    def _disable_context_auto_close(self, abnormal: bool = False) -> None:
        if abnormal:
            self._context_auto_close_abnormal = True
        if self._context_auto_close_armed:
            self._context_auto_close_armed = False
            self._context_auto_close_generation += 1

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            self.drop_overlay.setGeometry(self.centralWidget().rect())
            self.drop_overlay.show()
            self.drop_overlay.raise_()
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragLeaveEvent(self, event) -> None:
        self.drop_overlay.hide()
        event.accept()

    def dropEvent(self, event) -> None:
        try:
            paths = [url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()]
            for path in paths:
                if os.path.isdir(path):
                    self._start_scan([path], auto_start=False)
                else:
                    self._enqueue_path(path, auto_start=False, explicit_input=True)
            event.acceptProposedAction()
        finally:
            self.drop_overlay.hide()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if hasattr(self, "drop_overlay"):
            self.drop_overlay.setGeometry(self.centralWidget().rect())

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._shutdown_complete:
            event.accept()
            return
        if self._close_confirmation_pending:
            event.ignore()
            return
        unfinished = bool(
            not self._closing
            and (
                self._scan_active
                or self._pending_scan_requests
                or self._pending_startup_jobs
                or any(job.state not in TERMINAL_STATES for job in self.jobs.values())
                or (self.scheduler is not None and self.scheduler.has_unfinished_jobs())
            )
        )
        if unfinished:
            self._close_confirmation_pending = True
            try:
                answer = QMessageBox.question(
                    self,
                    "退出 Smart 7z Ultra",
                    "仍有未完成任务或扫描（包括排队或等待）。\n"
                    "退出后未完成任务需要重新添加，确定退出吗？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
            finally:
                self._close_confirmation_pending = False
            if answer != QMessageBox.StandardButton.Yes:
                self._disable_context_auto_close()
                event.ignore()
                return
        # 手册承诺：关闭流程开始前自动保存；保存失败则提示并取消本次关闭。
        if not self._flush_pending_config_edits():
            event.ignore()
            return
        if self._shutdown(force=True):
            event.accept()
            return
        QMessageBox.warning(
            self,
            "正在完成关闭",
            "后台组件尚未完全停止，Smart7z 将继续保持单实例锁。\n请稍候片刻后再次关闭。",
        )
        event.ignore()

    def _pending_config_edits(self) -> bool:
        """是否存在未提交的编辑。

        只比目标目录文本框：其余控件都是即时保存（复选框 toggled、清理策略
        clicked、扫描菜单 triggered），不存在悬空编辑。
        """
        pending = self.target_edit.text().strip()
        committed = str(self.config.get("target_dir", "") or "").strip()
        return pending != committed

    def _flush_pending_config_edits(self) -> bool:
        """关闭前保存未提交的编辑；失败时由调用方取消本次关闭。

        手册「正常关闭窗口」一节承诺：关闭流程开始前自动保存当前设置，保存失败
        时显示错误、恢复上一次已提交的配置并取消本次关闭。大部分控件是即时保存
        的（复选框 toggled、清理策略 clicked、扫描菜单 triggered），但目标目录
        文本框只接 editingFinished —— 用户在框内输入后不移动焦点、直接关窗时，
        编辑内容此前会丢失（实测复现）。

        仅在确有悬空编辑时才写盘：无条件 _sync_config 会把当前内存配置整体
        落盘，在配置路径被重定向（测试）或尚未加载完成时反而污染真实配置。

        返回 True 表示可以继续关闭；False 表示保存失败，调用方必须 event.ignore()。
        """
        if self._closing:
            return True
        if not self._pending_config_edits():
            return True
        try:
            if self._sync_config(silent=True):
                return True
        except Exception:
            logger.exception("Could not persist configuration on shutdown")
            return False
        # _sync_config 内部已回滚配置并恢复控件，这里只需提示用户。
        QMessageBox.critical(
            self,
            "配置保存失败",
            "关闭前未能保存当前设置，已恢复为上一次成功保存的配置。\n"
            "本次关闭已取消，请检查目标目录或配置文件是否可写后重试。",
        )
        return False

    def _shutdown(self, force: bool = False) -> bool:
        if self._shutdown_complete:
            return True
        ipc = self.ipc_server
        scheduler = self.scheduler
        if ipc is not None:
            begin_draining = getattr(ipc, "begin_draining", None)
            if callable(begin_draining):
                try:
                    begin_draining()
                except Exception:
                    logger.exception("Could not begin Qt IPC draining")
        self._closing = True
        self._disable_context_auto_close()
        self._scan_cancel.set()
        self._pending_scan_requests.clear()
        startup_stopped = True
        if self._startup_initializer is not None:
            startup_stopped = self._startup_initializer.cancel_and_join(timeout=1.0)
        failed_startup_stopped = self._stop_failed_startup_scheduler()
        startup_stopped = startup_stopped and failed_startup_stopped
        scan_threads = list(self._retired_scan_threads)
        if self._scan_thread is not None:
            scan_threads.append(self._scan_thread)
        scan_deadline = time.monotonic() + 1.0
        for thread in scan_threads:
            thread.join(timeout=max(0.0, scan_deadline - time.monotonic()))
        scans_stopped = all(not thread.is_alive() for thread in scan_threads)
        self._retired_scan_threads = [thread for thread in scan_threads if thread.is_alive()]
        scheduler_stopped = True
        if scheduler is not None:
            try:
                scheduler_stopped = scheduler.stop() is not False
            except Exception:
                scheduler_stopped = False
                logger.exception("Could not stop scheduler")
            if scheduler_stopped:
                self.scheduler = None
        ipc_stopped = True
        if ipc is not None:
            try:
                ipc_stopped = ipc.close() is not False
            except Exception:
                ipc_stopped = False
                logger.exception("Could not close Qt IPC server")
            if ipc_stopped:
                self.ipc_server = None
        self._shutdown_complete = bool(scheduler_stopped and ipc_stopped and scans_stopped and startup_stopped)
        if not self._shutdown_complete:
            logger.error(
                "Qt shutdown incomplete (scheduler=%s, ipc=%s, scans=%s, startup=%s)",
                scheduler_stopped,
                ipc_stopped,
                scans_stopped,
                startup_stopped,
            )
        return self._shutdown_complete


QT_STYLESHEET = r"""
QMainWindow, QWidget#centralSurface { background: #ffffff; }
QMenuBar {
    background: #fbfbfb;
    border-bottom: 1px solid #e4e4e4;
    padding: 0 6px;
}
QMenuBar::item {
    padding: 2px 8px;
    margin: 1px 1px;
    border: 1px solid transparent;
    border-radius: 3px;
}
QMenuBar::item:selected { color: #00695f; background: #e5f3f1; border-color: #badfd9; }
QMenu { background: #fafafa; border: 1px solid #cfcfcf; padding: 4px; }
QMenu::item { min-height: 24px; padding: 3px 20px 3px 9px; border-radius: 3px; }
QMenu::item:selected { color: #00695f; background: #e5f3f1; }
QFrame#commandBar { background: #ffffff; border-bottom: 1px solid #e4e4e4; }
QFrame#optionStrip { background: #f7f7f7; border-bottom: 1px solid #dedede; }
QFrame#activityShelf { background: #eaf7f5; border-bottom: 1px solid #b7ddd7; }
QFrame#queuePanel, QFrame#inspectorPanel { background: #ffffff; }
QFrame#queueToolbar { background: #ffffff; border-bottom: 1px solid #e4e4e4; }
QFrame#progressSummary { background: #fafafa; border-top: 1px solid #e4e4e4; }
QFrame#verticalDivider { background: #dedede; }
QFrame#cleanupSegment { border: 0; background: transparent; }
QLabel#detailError { color: #b3261e; }
QPushButton, QToolButton {
    min-height: 30px;
    padding: 0 10px;
    border: 1px solid #cfcfcf;
    border-radius: 5px;
    background: #fbfbfb;
}
QPushButton:hover, QToolButton:hover { background: #f1f1f1; border-color: #bdbdbd; }
QPushButton:pressed, QToolButton:pressed { background: #e7e7e7; }
QPushButton:disabled, QToolButton:disabled {
    color: #9a9a9a;
    background: #f4f4f4;
    border-color: #e3e3e3;
}
QPushButton#queueActionButton {
    min-height: 28px;
    padding: 0 8px;
    border-color: transparent;
    background: transparent;
    color: #4f4f4f;
}
QPushButton#queueActionButton:hover { background: #eef4f2; border-color: #d7e9e5; color: #00695f; }
QPushButton#queueActionButton:pressed { background: #e2f3f0; }
QPushButton#queueActionButton:disabled { color: #a7aaa9; background: transparent; border-color: transparent; }
QPushButton#browseButton { min-width: 64px; padding: 0 8px; }
QToolButton#compactIconButton {
    min-width: 28px;
    max-width: 28px;
    min-height: 28px;
    max-height: 28px;
    padding: 0;
    border-radius: 4px;
}
QToolButton#compactIconButton:hover { background: #f1f1f1; border-color: #bdbdbd; }
QPushButton#primaryButton {
    color: #ffffff;
    background: #00796b;
    border-color: #00796b;
    font-weight: 600;
}
QPushButton#primaryButton:hover { background: #00695f; border-color: #00695f; }
QPushButton#subtleButton { border-color: transparent; background: transparent; }
QPushButton#subtleButton:hover { background: #f1f1f1; border-color: #e1e1e1; }
QPushButton[segment="true"] {
    min-height: 28px;
    padding: 0 14px;
    border: 1px solid #c7c7c7;
    border-radius: 0;
    margin: 0;
    background: #ffffff;
}
QPushButton[segment="true"]:hover { background: #f1f1f1; border-color: #a9a9a9; }
QPushButton[segmentPosition="first"] { border-top-left-radius: 5px; border-bottom-left-radius: 5px; }
QPushButton[segmentPosition="middle"], QPushButton[segmentPosition="last"] { margin-left: -1px; }
QPushButton[segmentPosition="last"] { border-top-right-radius: 5px; border-bottom-right-radius: 5px; }
QPushButton[segment="true"]:checked {
    color: #ffffff;
    background: #3a3a3a;
    border-color: #3a3a3a;
    font-weight: 600;
}
QPushButton[segment="true"]:focus { border-color: #00796b; }
QCheckBox { spacing: 6px; }
QLineEdit, QLabel[deferredLineEdit="true"], QComboBox, QSpinBox {
    min-height: 30px;
    padding: 4px 8px;
    border: 1px solid #b9b9b9;
    border-radius: 4px;
    background: #ffffff;
    selection-background-color: #d7efeb;
    selection-color: #1f1f1f;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #00796b; }
QSpinBox#depthSpin { padding-right: 21px; }
QSpinBox#depthSpin::up-button, QSpinBox#depthSpin::down-button {
    width: 18px;
    border: 0;
    border-left: 1px solid #cfd8d5;
    background: #f5f7f7;
}
QSpinBox#depthSpin::up-button {
    border-top-right-radius: 3px;
    border-bottom: 1px solid #dfe5e3;
}
QSpinBox#depthSpin::down-button { border-bottom-right-radius: 3px; }
QSpinBox#depthSpin::up-button:hover, QSpinBox#depthSpin::down-button:hover {
    background: #e8f1ef;
}
QSpinBox#depthSpin::up-button:pressed, QSpinBox#depthSpin::down-button:pressed {
    background: #d8e8e5;
}
QGroupBox#settingsGroup {
    margin-top: 8px;
    padding: 12px 10px 10px;
    border: 1px solid #d9e2df;
    border-radius: 5px;
}
QGroupBox#settingsGroup::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: #00695f;
    font-weight: 600;
    background: #ffffff;
}
QComboBox::drop-down { width: 22px; border: 0; }
QProgressBar { border: 0; border-radius: 3px; background: #e1e5e9; }
QProgressBar::chunk { border-radius: 3px; background: #00796b; }
QTableView#jobTable {
    border: 0;
    background: #ffffff;
    alternate-background-color: #f7faf9;
    selection-background-color: #e2f3f0;
    selection-color: #1f1f1f;
    outline: 0;
}
QTableView#jobTable::item:hover { background: #eef4f2; }
QHeaderView { background: #f7f7f7; }
QHeaderView::section {
    min-height: 34px;
    padding: 0 9px;
    color: #4b4b4b;
    background: #f7f7f7;
    border: 0;
    border-bottom: 1px solid #d1d1d1;
    font-weight: 600;
}
QSplitter::handle { background: #d1d1d1; }
QTabWidget::pane { border: 0; border-top: 1px solid #d1d1d1; }
QTabBar::tab {
    min-width: 92px;
    min-height: 34px;
    padding: 0 14px;
    color: #565656;
    background: #ffffff;
    border: 0;
    border-bottom: 2px solid transparent;
}
QTabBar::tab:selected { color: #00796b; border-bottom-color: #00796b; font-weight: 600; }
QStatusBar { min-height: 22px; background: #f7f7f7; border-top: 1px solid #d1d1d1; }
QStatusBar QLabel { padding: 0 7px; color: #5f5f5f; }
QLabel#statusActive { color: #00796b; font-weight: 600; }
QLabel#statusDone { color: #107c10; font-weight: 600; }
QLabel#statusWarning { color: #9d5d00; font-weight: 600; }
QLabel#statusError { color: #c42b1c; font-weight: 600; }
QLabel#statusReady { color: #5f5f5f; font-weight: 600; }
QLabel#statusContext { padding-left: 3px; color: #616161; }
QLabel#statusCounts { border-left: 1px solid #d1d1d1; padding: 0 9px; color: #4f4f4f; }
QLabel#sectionTitle, QLabel#detailTitle { font-weight: 600; }
QLabel#commandLabel, QLabel#activityTitle { font-weight: 600; }
QLabel#activityIcon { color: #00796b; }
QLabel#warningIcon { color: #9d5d00; }
QLabel#secondaryText, QLabel#detailLabel { color: #616161; }
QLabel#detailValue { color: #1f1f1f; }
QLabel#detailState { padding: 0; font-weight: 600; }
QLabel#monoText { font-family: Consolas; }
QPlainTextEdit#logOutput {
    border: 0;
    padding: 10px 12px;
    color: #d4d9e2;
    background: #242932;
    font-size: 11px;
}
QFrame#dropOverlay { background: rgba(0, 121, 107, 28); border: 2px dashed #00796b; }
QLabel#dropOverlayLabel { color: #00796b; font-size: 20px; font-weight: 600; }
QLabel#dialogTitle { font-size: 15px; font-weight: 600; }
"""


def _configure_qt_application(app: QApplication) -> None:
    _startup_trace("configure_qt:start")
    styles = {name.casefold(): name for name in QStyleFactory.keys()}
    if "windowsvista" in styles:
        app.setStyle(QStyleFactory.create(styles["windowsvista"]))
    else:
        app.setStyle(QStyleFactory.create("Fusion"))
    _startup_trace("configure_qt:style")
    # Use a Chinese-capable UI family and a concrete monospace family in QSS
    # to avoid expensive fallback work during the first widget layout.
    app.setFont(QFont("Microsoft YaHei UI" if sys.platform == "win32" else "Segoe UI", 9))

    palette = app.palette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#FFFFFF"))
    palette.setColor(QPalette.ColorRole.WindowText, COLOR_TEXT)
    palette.setColor(QPalette.ColorRole.Base, QColor("#FFFFFF"))
    palette.setColor(QPalette.ColorRole.AlternateBase, COLOR_ROW_ALTERNATE)
    palette.setColor(QPalette.ColorRole.Text, COLOR_TEXT)
    palette.setColor(QPalette.ColorRole.ButtonText, COLOR_TEXT)
    palette.setColor(QPalette.ColorRole.PlaceholderText, COLOR_MUTED)
    palette.setColor(QPalette.ColorRole.Highlight, COLOR_ROW_SELECTED)
    palette.setColor(QPalette.ColorRole.HighlightedText, COLOR_TEXT)
    palette.setColor(QPalette.ColorRole.Link, COLOR_ACCENT)
    app.setPalette(palette)
    _startup_trace("configure_qt:font_palette")
    app.setStyleSheet(QT_STYLESHEET)
    app.setApplicationName(APP_TITLE)
    app.setOrganizationName("Smart7z")
    _startup_trace("configure_qt:end")


def _qt_forward_exit_code(
    result,
    parent: Optional[QWidget],
    *,
    allow_shutdown_handoff: bool = False,
) -> Optional[int]:
    if result.accepted:
        return 0
    if not result.reached_existing:
        return None
    if allow_shutdown_handoff and result.reason == "server_stopping":
        return None
    QMessageBox.critical(
        parent,
        "请求未接纳",
        "已有 Smart7z 实例，但本次请求没有被确认接纳。\n\n"
        f"原因：{result.reason or result.status}",
    )
    return 1


def _wait_for_existing_or_claim_mutex(
    request,
    parent: Optional[QWidget] = None,
):
    """Wait for a starting/closing instance, or claim ownership after it exits."""

    deadline = time.monotonic() + INSTANCE_STARTUP_WAIT_SECONDS
    last_reason = "state_unavailable"
    while True:
        forward_result = _forward_launch_request(request)
        last_reason = forward_result.reason or forward_result.status
        forward_exit_code = _qt_forward_exit_code(
            forward_result,
            parent,
            allow_shutdown_handoff=True,
        )
        if forward_exit_code is not None:
            return None, forward_exit_code

        instance_mutex = create_mutex()
        if instance_mutex is not None:
            return instance_mutex, None

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            QMessageBox.critical(
                parent,
                "启动请求未转交",
                "检测到另一个 Smart7z 正在启动或关闭，但未能在限定时间内完成请求转交。\n"
                "本次请求未进入队列，也没有启动第二个实例。\n"
                f"最后状态：{last_reason}\n请稍后重试。",
            )
            return None, 1
        time.sleep(min(INSTANCE_STARTUP_POLL_SECONDS, remaining))


def run_app(argv=None, *, initial_forward_result=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    request = parse_launch_args(argv)
    _startup_trace(f"run_app:request:{request!r}")

    # Keep direct callers on the same lightweight existing-instance path as
    # the smart7z.py bootstrap.  A second right-click process should not
    # construct QApplication before it has a chance to hand the request off.
    forward_result = (
        initial_forward_result
        if initial_forward_result is not None
        else _forward_launch_request(request)
    )
    _startup_trace(f"run_app:forward:{forward_result!r}")
    if forward_result.accepted:
        return 0

    _startup_trace("run_app:qapplication:start")
    app = QApplication.instance() or QApplication([sys.argv[0], *argv])
    _startup_trace("run_app:qapplication:end")
    _configure_qt_application(app)
    forward_exit_code = _qt_forward_exit_code(
        forward_result,
        None,
        allow_shutdown_handoff=sys.platform == "win32",
    )
    if forward_exit_code is not None:
        return forward_exit_code

    instance_mutex = None
    if sys.platform == "win32":
        instance_mutex = create_mutex()
        _startup_trace(f"run_app:mutex:{instance_mutex is not None}")
        if instance_mutex is None:
            instance_mutex, wait_exit_code = _wait_for_existing_or_claim_mutex(
                request,
                None,
            )
            if wait_exit_code is not None:
                return wait_exit_code

    window: Optional[Smart7zQtWindow] = None
    shutdown_error = None
    try:
        window = Smart7zQtWindow(
            startup_args=request.paths,
            startup_auto_start=request.auto_start,
            startup_cleanup_policy=request.cleanup_policy,
            startup_extract_to_source=request.extract_to_source,
            startup_context_menu=request.context_menu,
            defer_scheduler=True,
        )
        _startup_trace("run_app:window_ready")
        ipc = BoundedIPCServer(window)
        window.ipc_server = ipc
        if not ipc.start():
            retry_result = _forward_launch_request(request)
            window._shutdown(force=True)
            retry_exit_code = _qt_forward_exit_code(retry_result, None)
            if retry_exit_code is not None:
                return retry_exit_code
            QMessageBox.critical(
                None,
                "启动错误",
                "无法绑定 Smart7z IPC 端口，可能已有实例在运行。",
            )
            return 1
        _startup_trace("run_app:show:start")
        window.show()
        _startup_trace("run_app:show:end")
        window.activate_window(disarm_context_auto_close=False)
        window._setup_scheduler(background=True)
        app.processEvents()
        _startup_trace("run_app:initial_events:end")
        _startup_trace("run_app:event_loop")
        _flush_startup_trace()
        return app.exec()
    finally:
        shutdown_complete = True
        try:
            if window is not None:
                shutdown_complete = window._shutdown(force=True) is not False
        except Exception as exc:
            shutdown_complete = False
            shutdown_error = exc
            logger.exception("Unexpected Qt shutdown failure")
        finally:
            if instance_mutex is not None:
                if shutdown_complete:
                    if not close_mutex(instance_mutex):
                        logger.warning("Could not close the Smart7z instance mutex")
                else:
                    logger.error(
                        "Smart7z instance mutex retained until process exit because shutdown is incomplete"
                    )
        if shutdown_error is not None:
            raise shutdown_error
        _flush_startup_trace()


__all__ = ["Smart7zQtWindow", "run_app"]
