"""PySide6 desktop UI for Smart7z.

The scheduler, extraction pipeline, IPC protocol, configuration format, and
Windows integration stay in their existing modules.  This module replaces
only the presentation layer with a denser, more controllable Qt interface.
"""

from __future__ import annotations

import datetime
import logging
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from PySide6.QtCore import (
    QAbstractTableModel,
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

from archive_classifier import classify_automatic_candidate
from config import find_sevenzip, get_app_dir, load_config, save_config
from discovery import is_multipart_child, logical_archive_key
from models import CleanupPolicy, Job, JobState, TERMINAL_STATES
from scheduler import Scheduler
from stego_candidates import find_candidates
from steganographier_compat import find_steganographier_candidates
from runtime_ipc import (
    ARCHIVE_EXTS,
    BoundedIPCServer,
    CONTEXT_AUTO_CLOSE_GRACE_MS,
    EXTERNAL_CLEANUP_POLICIES,
    INSTANCE_STARTUP_POLL_SECONDS,
    INSTANCE_STARTUP_WAIT_SECONDS,
    IPC_FORWARD_REJECTED,
    PROCESSING_STATES,
    SCAN_MODE_DEEP,
    SCAN_MODE_NORMAL,
    SCAN_MODE_STEGANOGRAPHIER,
    STATUS_DISPLAY,
    _forward_launch_request,
    parse_launch_args,
)
from user_messages import CLEANUP_NOTICE_CODES, format_user_message, user_message_code
from windows_adapters import (
    cleanup_stale_sessions,
    close_mutex,
    create_mutex,
    is_reparse_point,
    register_context_menu,
    unregister_context_menu,
)

logger = logging.getLogger(__name__)

APP_TITLE = "Smart 7z Ultra"
APP_VERSION = "1.0.0"

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


def _icon_font(point_size: int) -> QFont:
    font = QFont("Segoe Fluent Icons", point_size)
    if not QFont("Segoe Fluent Icons").exactMatch():
        font = QFont("Segoe MDL2 Assets", point_size)
    return font


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
    candidates = (
        Path(get_app_dir()) / "build_assets" / "smart7z.ico",
        Path(get_app_dir()) / "smart7z.ico",
        Path(__file__).resolve().parent / "build_assets" / "smart7z.ico",
    )
    for candidate in candidates:
        if candidate.is_file():
            return QIcon(str(candidate))
    return fluent_icon("\ue7b8", QColor("#008675"), 18)


def format_size_bytes(size: int) -> str:
    if size >= 1024**3:
        return f"{size / 1024**3:.2f} GB"
    if size >= 1024**2:
        return f"{size / 1024**2:.2f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{max(0, size)} B"


def job_size_bytes(job: Job) -> int:
    source_path = getattr(job, "original_path", None) or job.path
    try:
        return os.path.getsize(source_path)
    except OSError:
        return 0


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


def phase_summary(state: JobState) -> str:
    if state == JobState.QUEUED:
        return "阶段 0/5 · 等待开始"
    for index, (label, states) in enumerate(PHASE_STATES, start=1):
        if state in states:
            return f"阶段 {index}/5 · {label}"
    if state in TERMINAL_STATES:
        return "阶段 5/5 · 已结束"
    return "阶段 · -"


class QtDispatchBridge(QObject):
    scheduler_event = Signal(str, object, tuple, dict)
    invoke = Signal(object, tuple)
    scan_progress = Signal(int, int, str, int)
    scan_candidate = Signal(str, object, object, bool)
    scan_finished = Signal(int, str)


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
        if ordered == self._jobs:
            return
        self.layoutAboutToBeChanged.emit()
        self._jobs[:] = ordered
        self._rows = {job.task_id: row for row, job in enumerate(self._jobs)}
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

        # QSS owns the quiet stepper backgrounds; draw compact arrows explicitly
        # so they remain visible on Windows styles that suppress native arrows.
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
        self.temp_edit = QLineEdit(str(config.get("temp_dir", r"C:\Temp_Smart7z")))
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
        }


class Smart7zQtWindow(QMainWindow):
    def __init__(
        self,
        startup_args: Optional[Sequence[str]] = None,
        startup_auto_start: bool = True,
        startup_cleanup_policy: str = CleanupPolicy.KEEP.value,
        startup_extract_to_source: bool = False,
        startup_context_menu: bool = False,
    ):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.setWindowIcon(app_icon())
        self.resize(1100, 720)
        self.setMinimumSize(920, 640)
        self.setAcceptDrops(True)
        self._place_center()
        QTimer.singleShot(0, self._place_center)

        self.config = load_config()
        self.config["_app_dir"] = get_app_dir()
        self.scheduler: Optional[Scheduler] = None
        self.ipc_server: Optional[BoundedIPCServer] = None
        self.startup_blocked = False
        self.jobs: Dict[str, Job] = {}
        self.seen_paths = set()
        self._suppressed_job_ids = set()
        self._clear_after_terminal = set()
        self._main_password = ""
        self._closing = False
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
        self._scan_cancel = threading.Event()
        self._pending_scan_requests: List[Tuple[List[str], bool, dict]] = []
        self._scan_active = False
        self._scan_found = 0
        self._pending_pwd_jobs: List[Job] = []
        self._current_pwd_job: Optional[Job] = None
        self._pending_stego_jobs: List[Job] = []
        self._current_stego_job: Optional[Job] = None
        self._inspector_expanded = True
        self._inspector_sizes = [500, 118]

        self.bridge = QtDispatchBridge(self)
        self.bridge.scheduler_event.connect(self._handle_scheduler_event)
        self.bridge.invoke.connect(self._invoke_on_ui)
        self.bridge.scan_progress.connect(self._update_scan_progress)
        self.bridge.scan_candidate.connect(self._accept_scan_candidate)
        self.bridge.scan_finished.connect(self._finish_scan)

        self._build_ui()
        self._setup_scheduler()
        self._update_summary()

    def _build_ui(self) -> None:
        self._build_menus()
        central = QWidget()
        central.setObjectName("centralSurface")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_command_bar())
        root.addWidget(self._build_option_strip())
        self.activity_shelf = self._build_activity_shelf()
        root.addWidget(self.activity_shelf)
        self.activity_shelf.hide()

        self.workspace_splitter = QSplitter(Qt.Orientation.Vertical)
        self.workspace_splitter.setObjectName("workspaceSplitter")
        self.workspace_splitter.setChildrenCollapsible(False)
        self.workspace_splitter.setHandleWidth(4)
        self.queue_panel = self._build_queue_panel()
        self.inspector_panel = self._build_inspector()
        self.workspace_splitter.addWidget(self.queue_panel)
        self.workspace_splitter.addWidget(self.inspector_panel)
        self.workspace_splitter.setStretchFactor(0, 1)
        self.workspace_splitter.setStretchFactor(1, 0)
        self.workspace_splitter.setSizes(self._inspector_sizes)
        root.addWidget(self.workspace_splitter, 1)

        self.drop_overlay = DropOverlay(central)
        self.drop_overlay.raise_()
        self._build_status_bar()

    def _build_menus(self) -> None:
        menu_bar = self.menuBar()
        menu_bar.setNativeMenuBar(False)
        menu_bar.setFixedHeight(26)

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
        self.target_edit = QLineEdit(str(self.config.get("target_dir", "")))
        self.target_edit.setPlaceholderText("未指定时按当前输出策略处理")
        self.target_edit.setMinimumWidth(240)
        self.target_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.target_edit.editingFinished.connect(lambda: self._sync_config(silent=True))
        layout.addWidget(self.target_edit, 1)
        browse_target = QToolButton()
        browse_target.setObjectName("compactIconButton")
        browse_target.setIcon(fluent_icon("\ue838", COLOR_MUTED, 14))
        browse_target.setIconSize(QSize(15, 15))
        browse_target.setFixedSize(28, 28)
        browse_target.setToolTip("浏览目标目录")
        browse_target.clicked.connect(self._browse_target)
        layout.addWidget(browse_target)

        password_label = QLabel("主密码")
        password_label.setObjectName("commandLabel")
        layout.addWidget(password_label)
        self.main_password_edit = QLineEdit(self._main_password)
        self.main_password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
        self.main_password_edit.setPlaceholderText("仅本次会话")
        self.main_password_edit.setAccessibleName("主密码，仅本次会话")
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
        self.password_title.setMinimumWidth(220)
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
        self.stego_title.setMinimumWidth(220)
        stego_layout.addWidget(self.stego_title)
        self.stego_combo = QComboBox()
        stego_layout.addWidget(self.stego_combo, 1)
        confirm_stego = QPushButton("使用此候选")
        confirm_stego.setObjectName("primaryButton")
        confirm_stego.clicked.connect(self._submit_stego)
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
            "终止当前任务", "终止当前正在运行的任务", self._cancel_current
        )
        self.cancel_selected_button = self._queue_action_button(
            "取消选中", "中断选中的未完成任务", self._cancel_selected
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
        self.job_table = QTableView()
        self.job_table.setObjectName("jobTable")
        self.job_table.setModel(self.job_model)
        self.job_table.setItemDelegate(JobTableDelegate(self.job_table))
        self.job_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.job_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.job_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.job_table.setAlternatingRowColors(True)
        self.job_table.setMouseTracking(True)
        self.job_table.setShowGrid(False)
        self.job_table.setWordWrap(False)
        self.job_table.setSortingEnabled(True)
        self.job_table.sortByColumn(1, Qt.SortOrder.AscendingOrder)
        self.job_table.verticalHeader().setVisible(False)
        self.job_table.verticalHeader().setDefaultSectionSize(42)
        header = self.job_table.horizontalHeader()
        header.setMinimumHeight(36)
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column, width in ((1, 84), (2, 86), (3, 116), (4, 72), (5, 82), (6, 122)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Fixed)
            self.job_table.setColumnWidth(column, width)
        self.job_table.selectionModel().selectionChanged.connect(self._selection_changed)
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

    def _build_inspector(self) -> QWidget:
        panel = QWidget()
        panel.setObjectName("inspectorPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        self.inspector_tabs = QTabWidget()
        self.inspector_tabs.setDocumentMode(True)
        self.inspector_tabs.tabBar().setObjectName("inspectorTabBar")
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
        self.detail_title.setObjectName("detailTitle")
        self.detail_path = QLabel("从任务队列中选择一项以查看详情")
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
            value.setObjectName("detailValue")
            value.setMaximumHeight(18)
            value.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.detail_values[key] = value
            grid.addWidget(label, row, pair * 2)
            grid.addWidget(value, row, pair * 2 + 1)
            grid.setColumnStretch(pair * 2 + 1, 1)
        details_layout.addLayout(grid)
        self.inspector_tabs.addTab(details_page, "任务详情")

        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setObjectName("logOutput")
        self.log_output.document().setMaximumBlockCount(500)
        self.inspector_tabs.addTab(self.log_output, "运行日志")
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
        button.setIcon(fluent_icon(glyph, QColor("#FFFFFF") if primary else COLOR_TEXT, 14))
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
            if not silent:
                QMessageBox.critical(self, "配置应用失败", str(exc))
            return False
        self.config = candidate
        if self.scheduler is not None:
            self.scheduler.set_session_main_password(self._main_password.strip() or None)
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
            self.scheduler.set_session_main_password(value.strip() or None)

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

    def _setup_scheduler(self) -> None:
        sevenzip = find_sevenzip(self.config)
        if not sevenzip:
            QMessageBox.critical(self, "配置错误", "找不到 7z.exe。请安装 7-Zip 或将 7z.exe 放在程序目录后重启。")
            self.startup_blocked = True
            return
        self.config["7z_path"] = sevenzip
        try:
            self.scheduler = Scheduler(sevenzip, self.config, event_cb=self._scheduler_callback)
            self.scheduler.start()
            self._log_recovery_messages(self.scheduler.recovery_messages)
            self._log_event("APP_READY")
        except OSError as exc:
            self.scheduler = None
            self.startup_blocked = True
            QMessageBox.critical(self, "暂存目录错误", str(exc))
            return
        threading.Thread(
            target=cleanup_stale_sessions,
            args=((self.config.get("temp_dir") or tempfile.gettempdir()), []),
            daemon=True,
        ).start()

    def _log_event(self, code: str, **values) -> None:
        self._append_log_line(format_user_message(code, **values))

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
            self._log_event("RECOVERY_AUTO_RESOLVED", count=routine_count)

        for message in always_show + review_messages:
            logger.warning("Startup recovery needs review: %s", message)
        for message in always_show + review_messages[:MAX_RECOVERY_LOG_DETAILS]:
            self._log_event("RECOVERY_REVIEW", detail=message)

        omitted = len(review_messages) - MAX_RECOVERY_LOG_DETAILS
        if omitted > 0:
            journal = getattr(self.scheduler, "recovery_journal", None)
            journal_path = str(getattr(journal, "path", "") or "")
            self._log_event("RECOVERY_MORE", count=omitted, detail=journal_path)

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
        QTimer.singleShot(100, self._process_startup_args)
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

    def activate_window(self) -> bool:
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
        path_values = tuple(paths or ())
        config_snapshot = dict(self.config)
        config_snapshot["cleanup_policy"] = cleanup_policy
        config_snapshot["del_archive"] = cleanup_policy == CleanupPolicy.PERMANENT.value
        config_snapshot["_extract_to_source_override"] = bool(extract_to_source)
        accepted = False
        file_count = 0
        directory_count = 0
        for raw_path in path_values:
            if not isinstance(raw_path, str):
                continue
            path = os.path.normpath(raw_path)
            if os.path.isdir(path):
                directory_count += 1
                accepted = self._start_scan([path], auto_start=auto_start, config_snapshot=config_snapshot) or accepted
            elif os.path.isfile(path):
                file_count += 1
                accepted = self._enqueue_path(
                    path,
                    auto_start=auto_start,
                    explicit_input=True,
                    config_snapshot=config_snapshot,
                ) or accepted
        if file_count or directory_count:
            self._log_event(
                "EXTERNAL_PATHS_RECEIVED",
                context=source,
                file_count=file_count,
                directory_count=directory_count,
                mode_zh="自动开始" if auto_start else "等待手动开始",
                mode_en="auto-start" if auto_start else "manual start",
            )
        if accepted and context_menu:
            self._note_context_menu_request()
        elif context_menu:
            self._disable_context_auto_close(abnormal=True)
        return accepted

    @Slot(str, object, tuple, dict)
    def _handle_scheduler_event(self, event_type: str, job: Job, args: tuple, kwargs: dict) -> None:
        if self._closing or not isinstance(job, Job):
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
                context = Path(job.display_path).name
                if state == JobState.FAILED:
                    reason = str(getattr(job, "source_retention_reason", "") or "")
                    if reason in ARCHIVE_BLOCK_REASONS or reason.startswith("unsafe_"):
                        self._log_event(
                            "ARCHIVE_BLOCKED",
                            context=context,
                            detail=job.error_message,
                        )
                    else:
                        category = getattr(job.error_category, "name", None)
                        self._log_event(
                            "JOB_FAILED",
                            context=context,
                            category=category or "UNCLASSIFIED",
                        )
                elif state == JobState.PARTIAL_RECOVERY:
                    self._log_event("JOB_PARTIAL_RECOVERY", context=context)
                elif state == JobState.INTERRUPTED:
                    self._log_event("JOB_INTERRUPTED", context=context)
                elif state == JobState.PASSWORD_REQUIRED:
                    self._log_event("JOB_PASSWORD_REQUIRED", context=context)
            if event_type == "user_notice" and args:
                message = str(args[0] or "")
                if message:
                    context = Path(job.display_path).name
                    if user_message_code(message) in CLEANUP_NOTICE_CODES:
                        self._append_log_line(f"{context}: {message}")
                    else:
                        self._log_event(
                            "USER_NOTICE",
                            context=context,
                            detail=message,
                        )
            if event_type == "password_promoted":
                self._log_event("PASSWORD_PROMOTED")
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
            if event_type == "job_partial":
                self._disable_context_auto_close(abnormal=True)
            elif event_type == "job_failed":
                self._disable_context_auto_close(abnormal=True)
            elif event_type == "job_interrupted":
                self._disable_context_auto_close(abnormal=True)
            elif event_type == "job_skipped":
                self._disable_context_auto_close(abnormal=True)
            if job.task_id in self._clear_after_terminal:
                QTimer.singleShot(80, lambda task_id=job.task_id: self._remove_finished_ids({task_id}))
        elif event_type == "intake_full":
            self._log_event("INTAKE_FULL", context=Path(job.display_path).name)
        elif event_type == "job_deferred":
            self._append_log_line(f"{Path(job.display_path).name}: 已暂存，等待扫描完成")
        self._update_summary()
        self._schedule_context_auto_close_check()

    def _upsert_job(self, job: Job) -> None:
        self.jobs[job.task_id] = job
        self.job_model.upsert(job)
        self._update_summary()
        if self.job_model.row_for_id(job.task_id) >= 0:
            self.job_table.viewport().update()
        selected = self._selected_job()
        if selected is not None and selected.task_id == job.task_id:
            self._update_details(job)

    def _selected_job(self) -> Optional[Job]:
        selection = self.job_table.selectionModel().selectedRows()
        if not selection:
            return None
        return self.job_model.job_at(selection[0].row())

    def _selected_jobs(self) -> List[Job]:
        return [
            job
            for index in self.job_table.selectionModel().selectedRows()
            if (job := self.job_model.job_at(index.row())) is not None
        ]

    def _selection_changed(self, _selected, _deselected) -> None:
        self._update_details(self._selected_job())
        self._update_queue_action_states()

    def _update_details(self, job: Optional[Job]) -> None:
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
        display_path = job.display_path
        self.detail_title.setText(Path(display_path).name)
        self.detail_title.setToolTip(display_path)
        self.detail_path.setText(display_path)
        self.detail_path.setToolTip(display_path)
        state_label = STATUS_DISPLAY.get(job.state, job.state.value)
        color = state_color(job.state).name()
        self.detail_state.setText(state_label)
        self.detail_state.setStyleSheet(f"color: {color}; font-weight: 600;")
        self.detail_phase.setText(phase_summary(job.state))
        manifest = getattr(job, "manifest", None)
        extraction = getattr(job, "extraction_result", None)
        detail_text = {}
        detail_text["id"] = job.task_id[:18]
        detail_text["format"] = getattr(manifest, "format", "-") or "-"
        entry_count = getattr(manifest, "entry_count", 0) if manifest is not None else 0
        if not entry_count and extraction is not None:
            entry_count = getattr(extraction, "output_file_count", 0) or 0
        detail_text["entries"] = str(entry_count) if entry_count else "-"
        if manifest is None:
            encrypted = "-"
        else:
            encrypted = "是" if bool(getattr(manifest, "is_encrypted", False)) else "否"
        detail_text["encrypted"] = encrypted
        attempts = int(getattr(job, "attempt_count", 0) or 0)
        detail_text["attempts"] = str(attempts)
        detail_text["candidate"] = f"{len(job.stego_candidates)} 个" if job.stego_candidates else "-"
        detail_text["output"] = job.final_destination or self.config.get("target_dir", "-") or "-"
        detail_text["policy"] = cleanup_policy_text(job.cleanup_policy_snapshot)
        detail_text["source"] = retention_text(job)
        for key, text in detail_text.items():
            self.detail_values[key].setText(text)
            self.detail_values[key].setToolTip(text)

    def _update_summary(self) -> None:
        total = len(self.jobs)
        done = sum(job.state in TERMINAL_STATES for job in self.jobs.values())
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
        self.progress_summary_text.setText(f"{done} 完成 · {active} 处理中")

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
        if self._scan_active:
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
                self.status_state.setText("●  完成但有异常")
                self.status_state.setObjectName("statusError")
                self.status_context.setText(f"{len(abnormal)} 项未正常完成，请检查任务详情或运行日志")
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
            count_text = f"待完成 {remaining} · 完成 {done}"
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
        selected = self._selected_jobs() if hasattr(self, "job_table") else []
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
        self.start_button.setEnabled(self.scheduler is not None and has_work)
        if self._processing_requested and has_work:
            self.start_button.setText("暂停队列")
            self.start_button.setIcon(fluent_icon("\ue769", QColor("#FFFFFF"), 14))
        else:
            self.start_button.setText("开始")
            self.start_button.setIcon(fluent_icon("\ue768", QColor("#FFFFFF"), 14))

    def _append_log_line(self, message: str) -> None:
        text = " ".join(str(message).replace("\x00", "").splitlines()).strip()
        if not text:
            return
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_output.appendPlainText(f"[{stamp}] {text}")

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
        job = self._current_pwd_job
        if job is None:
            self._reset_password_prompt()
            self._sync_activity_visibility()
            return
        self.password_title.setText(f"需要密码   {Path(job.display_path).name}")
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
        job = self._current_stego_job
        if job is None:
            self._sync_activity_visibility()
            return
        self.stego_title.setText(f"选择隐写候选   {Path(job.display_path).name}")
        self.stego_combo.clear()
        for index, candidate in enumerate(job.stego_candidates):
            label = f"候选 {index + 1} · {candidate.embedded_format or '未知格式'} · {candidate.start_offset:,} - {candidate.end_offset:,}"
            self.stego_combo.addItem(label, index)
        self.activity_stack.setCurrentWidget(self.stego_activity_page)
        self._sync_activity_visibility()

    def _submit_stego(self) -> None:
        job = self._current_stego_job
        if job is None or self.scheduler is None:
            return
        index = self.stego_combo.currentData()
        self.scheduler.submit_stego_selection(job, int(index) if index is not None else None)
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
            self.stego_combo.clear()
            self.stego_title.setText("选择隐写候选")
            self._sync_activity_visibility()

    def _sync_activity_visibility(self) -> None:
        if self._current_pwd_job is not None:
            self.activity_stack.setCurrentWidget(self.password_activity_page)
            self.activity_shelf.show()
        elif self._current_stego_job is not None:
            self.activity_stack.setCurrentWidget(self.stego_activity_page)
            self.activity_shelf.show()
        elif self._scan_active:
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
        try:
            normalized = os.path.normpath(path)
            logical_key = logical_archive_key(normalized)
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
            return False
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
        if self._scan_active:
            self._pending_scan_requests.append((normalized, bool(auto_start), snapshot))
            self._update_summary()
            return True
        self._launch_scan(normalized, bool(auto_start), snapshot)
        return True

    def _launch_scan(self, roots: List[str], auto_start: bool, config_snapshot: dict) -> None:
        self._scan_cancel.clear()
        self._scan_active = True
        self._scan_found = 0
        self._scan_auto_start = bool(auto_start)
        self._show_scan_activity()
        self._append_log_line(f"开始扫描 {len(roots)} 个目录")

        def cancelled() -> bool:
            return self._scan_cancel.is_set() or self._closing

        def worker() -> None:
            scanned = 0
            found = 0
            failure = ""
            last_path = ""
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
                            if is_multipart_child(full):
                                continue
                            scanned += 1
                            last_path = full
                            self.bridge.scan_progress.emit(scanned, found, full, 0)
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
                                    decision = classify_automatic_candidate(
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
                                self.bridge.scan_candidate.emit(full, config_snapshot, candidates, False)
                            self.bridge.scan_progress.emit(scanned, found, full, 100)
                        if cancelled():
                            break
            except Exception as exc:
                logger.exception("Background scan failed")
                failure = f"{type(exc).__name__}: {exc}"
            finally:
                self.bridge.scan_finished.emit(found, failure)

        self._scan_thread = threading.Thread(target=worker, name="Smart7zQtScan", daemon=True)
        self._scan_thread.start()

    def _show_scan_activity(self) -> None:
        self._scan_active = True
        self.scan_progress.setValue(0)
        self.scan_percent.setText("0%")
        self.scan_title.setText("正在扫描")
        self.scan_meta.setText("准备中")
        self._sync_activity_visibility()

    @Slot(int, int, str, int)
    def _update_scan_progress(self, scanned: int, found: int, path: str, progress: int) -> None:
        if not self._scan_active:
            return
        name = Path(path).name if path else "准备中"
        self.scan_title.setText(f"正在扫描   {name}")
        self.scan_meta.setText(f"第 {scanned} 个文件   ·   已发现 {found} 个任务   ·   {self._scan_mode_label()}")
        value = max(0, min(100, int(progress)))
        self.scan_progress.setValue(value)
        self.scan_percent.setText(f"{value}%")
        self._update_summary()

    @Slot(str, object, object, bool)
    def _accept_scan_candidate(self, path: str, config_snapshot: dict, candidates, auto_start: bool) -> None:
        self._enqueue_path(
            path,
            auto_start=bool(auto_start),
            explicit_input=False,
            config_snapshot=dict(config_snapshot),
            precomputed_candidates=candidates,
        )

    @Slot(int, str)
    def _finish_scan(self, found: int, failure: str) -> None:
        self._scan_active = False
        self._scan_thread = None
        if failure:
            self._disable_context_auto_close(abnormal=True)
            self._log_event("SCAN_FAILED", count=found, detail=failure)
        else:
            self._log_event("SCAN_COMPLETE", count=found)
        if getattr(self, "_scan_auto_start", False) and self.scheduler is not None:
            self.scheduler.enable_processing()
            self._processing_requested = True
        self._sync_activity_visibility()
        self._update_summary()
        if self._pending_scan_requests and not self._closing:
            roots, auto_start, config_snapshot = self._pending_scan_requests.pop(0)
            QTimer.singleShot(80, lambda: self._launch_scan(roots, auto_start, config_snapshot))
        else:
            self._schedule_context_auto_close_check()

    def _scan_mode_label(self) -> str:
        mode = self._scan_mode_from_config(self.config)
        return {
            SCAN_MODE_DEEP: "深度扫描模式",
            SCAN_MODE_STEGANOGRAPHIER: "仅兼容隐写者模式",
            SCAN_MODE_NORMAL: "普通模式",
        }.get(mode, "普通模式")

    def _cancel_scan(self) -> None:
        self._scan_cancel.set()
        self._pending_scan_requests.clear()
        self._append_log_line("已请求取消扫描")

    def _toggle_processing(self) -> None:
        if self._processing_requested:
            self._pause_processing()
        else:
            self._start_processing()

    def _start_processing(self) -> None:
        if not self._sync_config():
            self._log_event("CONFIG_SYNC_FAILED")
            return
        if self.scheduler is None:
            return
        self.scheduler.resume_intake()
        self.scheduler.enable_processing()
        self._processing_requested = True
        self.status_state.setText("●  正在处理")
        self._log_event("QUEUE_STARTED")
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
            self._log_event("CANCEL_CURRENT_REQUESTED")
        self._update_summary()

    def _cancel_remaining(self) -> None:
        self._cancel_scan()
        if self.scheduler is not None:
            self.scheduler.cancel_remaining()
            self._log_event("CANCEL_REMAINING")
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
            current_id = self.scheduler.current_job.task_id if self.scheduler.current_job else None
            if current_id in task_ids:
                self.scheduler.cancel_current()
            remaining_ids = task_ids - ({current_id} if current_id else set())
            if remaining_ids:
                self.scheduler.cancel_jobs(remaining_ids)
            self._append_log_line(f"已请求取消 {len(task_ids)} 个选中任务")
        self._update_summary()

    def _remove_finished_ids(self, task_ids: Iterable[str]) -> None:
        ids = set(task_ids)
        if not ids:
            return
        self._suppressed_job_ids.update(ids)
        for task_id in ids:
            job = self.jobs.pop(task_id, None)
            if job:
                for source in (job.path, job.original_path):
                    if source:
                        try:
                            self.seen_paths.discard(logical_archive_key(source))
                        except (OSError, ValueError):
                            pass
        self.job_model.remove_ids(ids)
        self._clear_after_terminal.difference_update(ids)
        self._update_details(self._selected_job())
        self._update_summary()

    def _toggle_inspector(self) -> None:
        sizes = self.workspace_splitter.sizes()
        if self._inspector_expanded:
            if len(sizes) > 1 and sizes[1] > 0:
                self._inspector_sizes = sizes
            self.inspector_panel.hide()
            self.inspector_toggle.setText("显示详情")
            self.inspector_toggle.setToolTip("显示任务详情和运行日志")
            self._inspector_expanded = False
        else:
            total = max(1, sum(sizes))
            expanded = self._inspector_sizes[1] if len(self._inspector_sizes) > 1 else 190
            self.inspector_panel.show()
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
        active = bool(
            not self._closing
            and self.scheduler
            and (self.scheduler.current_job or self._scan_active)
        )
        if active:
            answer = QMessageBox.question(
                self,
                "退出 Smart 7z Ultra",
                "仍有任务正在处理，确定退出吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
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
        self._shutdown_complete = bool(scheduler_stopped and ipc_stopped)
        if not self._shutdown_complete:
            logger.error(
                "Qt shutdown incomplete (scheduler=%s, ipc=%s)",
                scheduler_stopped,
                ipc_stopped,
            )
        return self._shutdown_complete


QT_STYLESHEET = r"""
* {
    font-family: "Segoe UI", "Microsoft YaHei UI", sans-serif;
    font-size: 12px;
    color: #1f1f1f;
}
QMainWindow, QWidget#centralSurface { background: #ffffff; }
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
QLineEdit, QComboBox, QSpinBox {
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
QTabWidget::pane { border: 0; border-top: 1px solid #cfd6d3; background: #ffffff; }
QTabBar#inspectorTabBar { background: #f4f7f6; border-top: 1px solid #d8dfdc; }
QTabBar#inspectorTabBar::tab {
    min-width: 92px;
    min-height: 34px;
    padding: 0 14px;
    color: #565656;
    background: #f4f7f6;
    border: 0;
    border-right: 1px solid #e1e6e4;
    border-bottom: 2px solid transparent;
}
QTabBar#inspectorTabBar::tab:selected {
    color: #00796b;
    background: #ffffff;
    border-bottom-color: #00796b;
    font-weight: 600;
}
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
QLabel#monoText { font-family: Consolas, "Cascadia Mono", monospace; }
QPlainTextEdit#logOutput {
    border: 0;
    padding: 10px 12px;
    color: #d4d9e2;
    background: #242932;
    font-family: Consolas, "Cascadia Mono", monospace;
    font-size: 11px;
}
QFrame#dropOverlay { background: rgba(0, 121, 107, 28); border: 2px dashed #00796b; }
QLabel#dropOverlayLabel { color: #00796b; font-size: 20px; font-weight: 600; }
QLabel#dialogTitle { font-size: 15px; font-weight: 600; }
"""


def _configure_qt_application(app: QApplication) -> None:
    styles = {name.casefold(): name for name in QStyleFactory.keys()}
    if "windowsvista" in styles:
        app.setStyle(QStyleFactory.create(styles["windowsvista"]))
    else:
        app.setStyle(QStyleFactory.create("Fusion"))
    app.setFont(QFont("Segoe UI", 9))
    app.setStyleSheet(QT_STYLESHEET)
    app.setApplicationName(APP_TITLE)
    app.setOrganizationName("Smart7z")


def _qt_forward_exit_code(
    result,
    parent: Optional[QWidget],
    *,
    allow_shutdown_handoff: bool = False,
) -> Optional[int]:
    if result.accepted:
        return 0
    if allow_shutdown_handoff and result.reason == "server_stopping":
        return None
    if result.status == IPC_FORWARD_REJECTED:
        QMessageBox.critical(
            parent,
            "启动请求无效" if not result.reached_existing else "请求未接纳",
            (
                "本次启动参数无效，Smart7z 未创建任务。\n\n"
                if not result.reached_existing
                else "已有 Smart7z 实例，但本次请求没有被确认接纳。\n\n"
            )
            + f"原因：{result.reason or result.status}",
        )
        return 1
    if not result.reached_existing:
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


def run_app(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    app = QApplication.instance() or QApplication([sys.argv[0], *argv])
    _configure_qt_application(app)
    request = parse_launch_args(argv)

    forward_result = _forward_launch_request(request)
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
        )
        if window.startup_blocked or window.scheduler is None:
            window._shutdown(force=True)
            return 1
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
        window.show()
        window.activate_window()
        window._start_startup_processing()
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


__all__ = ["Smart7zQtWindow", "run_app"]
