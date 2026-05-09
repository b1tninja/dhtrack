"""Shared metric cards for dashboards (consistent look via QFrame[role=\"card\"] in dark_theme.qss)."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget


class StatCard(QFrame):
    """A card displaying label + monospace value."""

    _value_stylesheet_blue = (
        "color: #89b4fa; font-size: 20px; font-weight: bold; "
        "font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;"
    )

    def __init__(self, label: str, value: str = "-", parent: QWidget | None = None):
        super().__init__(parent)
        self.label_text = label
        self._current_value = value
        self.setProperty("role", "card")
        self.setFrameStyle(QFrame.Shape.NoFrame)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(4)

        self.label = QLabel(label)
        self.label.setStyleSheet("color: #a6adc8; font-size: 11px;")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(self._value_stylesheet_blue)
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        layout.addWidget(self.label)
        layout.addWidget(self.value_label)

    def update_value(self, value: str, color: str | None = None) -> None:
        """Update metric value; optional CSS color overrides accent."""
        self._current_value = value
        self.value_label.setText(value)
        if color:
            self.value_label.setStyleSheet(
                f"color: {color}; font-size: 20px; font-weight: bold; "
                "font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;"
            )
        else:
            self.value_label.setStyleSheet(self._value_stylesheet_blue)
