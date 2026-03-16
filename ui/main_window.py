"""
CyberGuardian Main GUI Module
=============================
PyQt5-based graphical user interface with cyberpunk theme.
Features AI-powered analysis with Deepseek, OpenAI, and Gemini support.
"""

import os
import sys
import logging
import threading
import webbrowser
import ctypes
import subprocess
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTabWidget, QTextEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QProgressBar, QStatusBar,
    QSystemTrayIcon, QMenu, QAction, QMessageBox, QFileDialog,
    QSplitter, QFrame, QGroupBox, QScrollArea, QDialog,
    QDialogButtonBox, QLineEdit, QComboBox, QCheckBox,
    QTreeWidget, QTreeWidgetItem, QToolBar, QStyle, QSpinBox,
    QFormLayout, QTabWidget as QTabWidgetInner, QWidget as QWidgetInner,
    QListWidget, QListWidgetItem, QRadioButton, QButtonGroup,
)
from PyQt5.QtCore import (
    Qt, QTimer, QThread, pyqtSignal, QSize, QSettings,
    QPropertyAnimation, QEasingCurve, QRect
)
from PyQt5.QtGui import (
    QIcon, QFont, QColor, QPalette, QPixmap, QPainter,
    QPen, QBrush, QLinearGradient, QFontDatabase
)

from scanners.base_scanner import ScanResult, Detection, RiskLevel, ScanStatus
from scanners.process_scanner import ProcessScanner
from scanners.file_scanner import FileScanner
from scanners.registry_scanner import RegistryScanner
from scanners.network_scanner import NetworkScanner
from scanners.realtime_monitor import RealTimeMonitor
from scanners.yara_manager import get_yara_manager
from reporting.generator import ReportGenerator
from utils.config import get_config, APP_DIR
from utils.logging_utils import get_logger, setup_logging
from utils.whitelist import get_whitelist
from utils.secure_storage import get_secure_storage, load_all_api_keys

# Import AI analyzer
try:
    from ai_analysis.analyzer import AIAnalyzer, AIProvider, AnalysisResult, Verdict, get_ai_analyzer
    AI_ANALYSIS_AVAILABLE = True
except ImportError:
    AI_ANALYSIS_AVAILABLE = False
    logging.warning("AI analysis module not available")

# Import VirusTotal checker
try:
    from threat_intel.virustotal_checker import (
        get_virustotal_checker, is_virustotal_available,
        VirusTotalChecker, IOCResult
    )
    VIRUSTOTAL_AVAILABLE = True
except ImportError:
    VIRUSTOTAL_AVAILABLE = False
    logging.warning("VirusTotal checker module not available")

logger = get_logger('ui.main_window')


# Cyber Theme Colors
CYBER_COLORS = {
    'background': '#0a0f0f',
    'background_secondary': '#121a1a',
    'background_card': '#1a2424',
    'primary': '#00ff9d',
    'secondary': '#00b8ff',
    'accent': '#ff00ff',
    'critical': '#ff0040',
    'high': '#ff6b35',
    'medium': '#ffd93d',
    'low': '#6bcb77',
    'info': '#4d96ff',
    'text': '#e0e0e0',
    'text_muted': '#8a8a8a',
    'border': '#2a3a3a',
}


def is_admin() -> bool:
    """Check if the application is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    """Re-run the application with administrator privileges."""
    if sys.platform == 'win32':
        try:
            script = os.path.abspath(sys.argv[0])
            params = ' '.join(sys.argv[1:])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script}" {params}', None, 1
            )
            return True
        except Exception as e:
            logger.error(f"Failed to elevate privileges: {e}")
            return False
    return False


class CyberStyle:
    """Cyber-themed stylesheet for the application."""
    
    @staticmethod
    def get_stylesheet() -> str:
        return f'''
        QMainWindow {{
            background-color: {CYBER_COLORS['background']};
        }}
        
        QWidget {{
            background-color: {CYBER_COLORS['background']};
            color: {CYBER_COLORS['text']};
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
        }}
        
        QPushButton {{
            background-color: {CYBER_COLORS['background_card']};
            color: {CYBER_COLORS['primary']};
            border: 2px solid {CYBER_COLORS['primary']};
            border-radius: 8px;
            padding: 12px 24px;
            font-size: 14px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        QPushButton:hover {{
            background-color: {CYBER_COLORS['primary']};
            color: {CYBER_COLORS['background']};
        }}
        
        QPushButton:pressed {{
            background-color: {CYBER_COLORS['secondary']};
            border-color: {CYBER_COLORS['secondary']};
        }}
        
        QPushButton:disabled {{
            background-color: {CYBER_COLORS['background_secondary']};
            color: {CYBER_COLORS['text_muted']};
            border-color: {CYBER_COLORS['text_muted']};
        }}
        
        QPushButton#criticalButton {{
            border-color: {CYBER_COLORS['critical']};
            color: {CYBER_COLORS['critical']};
        }}
        
        QPushButton#criticalButton:hover {{
            background-color: {CYBER_COLORS['critical']};
            color: white;
        }}
        
        QPushButton#dangerButton {{
            background-color: {CYBER_COLORS['critical']};
            color: white;
            border-color: {CYBER_COLORS['critical']};
        }}
        
        QPushButton#dangerButton:hover {{
            background-color: #ff2040;
        }}
        
        QPushButton#warningButton {{
            background-color: {CYBER_COLORS['high']};
            color: white;
            border-color: {CYBER_COLORS['high']};
        }}
        
        QPushButton#warningButton:hover {{
            background-color: #ff8050;
        }}
        
        QPushButton#aiButton {{
            background-color: {CYBER_COLORS['secondary']};
            color: white;
            border-color: {CYBER_COLORS['secondary']};
        }}
        
        QPushButton#aiButton:hover {{
            background-color: #00d0ff;
        }}
        
        QTabWidget::pane {{
            border: 1px solid {CYBER_COLORS['border']};
            border-radius: 8px;
            background-color: {CYBER_COLORS['background_secondary']};
        }}
        
        QTabBar::tab {{
            background-color: {CYBER_COLORS['background_card']};
            color: {CYBER_COLORS['text_muted']};
            border: 1px solid {CYBER_COLORS['border']};
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            padding: 8px 16px;
            margin-right: 2px;
        }}
        
        QTabBar::tab:selected {{
            background-color: {CYBER_COLORS['background_secondary']};
            color: {CYBER_COLORS['primary']};
            border-bottom: 2px solid {CYBER_COLORS['primary']};
        }}
        
        QTableWidget {{
            background-color: {CYBER_COLORS['background_secondary']};
            alternate-background-color: {CYBER_COLORS['background_card']};
            border: 1px solid {CYBER_COLORS['border']};
            border-radius: 4px;
            gridline-color: {CYBER_COLORS['border']};
        }}
        
        QTableWidget::item {{
            padding: 8px;
        }}
        
        QTableWidget::item:selected {{
            background-color: {CYBER_COLORS['primary']};
            color: {CYBER_COLORS['background']};
        }}
        
        QHeaderView::section {{
            background-color: {CYBER_COLORS['background_card']};
            color: {CYBER_COLORS['primary']};
            border: none;
            border-bottom: 2px solid {CYBER_COLORS['primary']};
            padding: 8px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        QTextEdit {{
            background-color: {CYBER_COLORS['background_secondary']};
            color: {CYBER_COLORS['text']};
            border: 1px solid {CYBER_COLORS['border']};
            border-radius: 4px;
            padding: 8px;
        }}
        
        QProgressBar {{
            background-color: {CYBER_COLORS['background_card']};
            border: 1px solid {CYBER_COLORS['border']};
            border-radius: 4px;
            text-align: center;
            color: {CYBER_COLORS['text']};
        }}
        
        QProgressBar::chunk {{
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 {CYBER_COLORS['primary']},
                stop:1 {CYBER_COLORS['secondary']});
            border-radius: 4px;
        }}
        
        QStatusBar {{
            background-color: {CYBER_COLORS['background_card']};
            color: {CYBER_COLORS['text_muted']};
            border-top: 1px solid {CYBER_COLORS['border']};
        }}
        
        QGroupBox {{
            border: 1px solid {CYBER_COLORS['border']};
            border-radius: 8px;
            margin-top: 16px;
            padding-top: 16px;
            color: {CYBER_COLORS['primary']};
            font-weight: bold;
        }}
        
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 16px;
            padding: 0 8px;
        }}
        
        QScrollBar:vertical {{
            background-color: {CYBER_COLORS['background_secondary']};
            width: 12px;
            border-radius: 6px;
        }}
        
        QScrollBar::handle:vertical {{
            background-color: {CYBER_COLORS['primary']};
            border-radius: 6px;
            min-height: 20px;
        }}
        
        QScrollBar::handle:vertical:hover {{
            background-color: {CYBER_COLORS['secondary']};
        }}
        
        QTreeWidget {{
            background-color: {CYBER_COLORS['background_secondary']};
            border: 1px solid {CYBER_COLORS['border']};
            border-radius: 4px;
        }}
        
        QTreeWidget::item {{
            padding: 4px;
        }}
        
        QTreeWidget::item:selected {{
            background-color: {CYBER_COLORS['primary']};
            color: {CYBER_COLORS['background']};
        }}
        
        QMenu {{
            background-color: {CYBER_COLORS['background_card']};
            color: {CYBER_COLORS['text']};
            border: 1px solid {CYBER_COLORS['border']};
        }}
        
        QMenu::item:selected {{
            background-color: {CYBER_COLORS['primary']};
            color: {CYBER_COLORS['background']};
        }}
        
        QSplitter::handle {{
            background-color: {CYBER_COLORS['border']};
        }}
        
        QComboBox {{
            background-color: {CYBER_COLORS['background_card']};
            color: {CYBER_COLORS['text']};
            border: 1px solid {CYBER_COLORS['border']};
            border-radius: 4px;
            padding: 4px 8px;
        }}
        
        QComboBox::drop-down {{
            border: none;
        }}
        
        QLineEdit {{
            background-color: {CYBER_COLORS['background_secondary']};
            color: {CYBER_COLORS['text']};
            border: 1px solid {CYBER_COLORS['border']};
            border-radius: 4px;
            padding: 8px;
        }}
        
        QLineEdit:focus {{
            border-color: {CYBER_COLORS['primary']};
        }}
        
        QLabel {{
            color: {CYBER_COLORS['text']};
        }}
        
        QLabel#titleLabel {{
            color: {CYBER_COLORS['primary']};
            font-size: 18px;
            font-weight: bold;
        }}
        
        QFrame#separator {{
            background-color: {CYBER_COLORS['primary']};
        }}
        
        QSpinBox {{
            background-color: {CYBER_COLORS['background_secondary']};
            color: {CYBER_COLORS['text']};
            border: 1px solid {CYBER_COLORS['border']};
            border-radius: 4px;
            padding: 4px 8px;
        }}
        
        QListWidget {{
            background-color: {CYBER_COLORS['background_secondary']};
            border: 1px solid {CYBER_COLORS['border']};
            border-radius: 4px;
        }}
        
        QListWidget::item:selected {{
            background-color: {CYBER_COLORS['primary']};
            color: {CYBER_COLORS['background']};
        }}
        
        QCheckBox {{
            color: {CYBER_COLORS['text']};
        }}
        
        QCheckBox::indicator {{
            width: 18px;
            height: 18px;
            border: 2px solid {CYBER_COLORS['border']};
            border-radius: 4px;
        }}
        
        QCheckBox::indicator:checked {{
            background-color: {CYBER_COLORS['primary']};
            border-color: {CYBER_COLORS['primary']};
        }}
        
        QRadioButton {{
            color: {CYBER_COLORS['text']};
        }}
        
        QRadioButton::indicator {{
            width: 18px;
            height: 18px;
            border: 2px solid {CYBER_COLORS['border']};
            border-radius: 9px;
        }}
        
        QRadioButton::indicator:checked {{
            background-color: {CYBER_COLORS['primary']};
            border-color: {CYBER_COLORS['primary']};
        }}
        '''


class ScanWorker(QThread):
    """Background worker for running scans."""
    
    progress = pyqtSignal(int, int, str)
    detection = pyqtSignal(object)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    cancelled = pyqtSignal()
    
    def __init__(self, scanner, target=None, deep_analysis=False):
        super().__init__()
        self.scanner = scanner
        self.target = target
        self.deep_analysis = deep_analysis
        self._is_cancelled = False
    
    def run(self):
        try:
            # Reset cancellation flag
            self.scanner.reset_cancel()
            self.scanner.set_progress_callback(self._on_progress)
            self.scanner.set_detection_callback(self._on_detection)
            
            # Pass deep_analysis flag to scanner if it supports it
            import inspect
            scan_sig = inspect.signature(self.scanner.scan)
            if 'deep_analysis' in scan_sig.parameters:
                result = self.scanner.scan(self.target, deep_analysis=self.deep_analysis)
            else:
                result = self.scanner.scan(self.target)
            
            # Check if scan was cancelled
            if self.scanner.is_cancelled():
                result.status = ScanStatus.CANCELLED
                self.cancelled.emit()
            
            self.finished.emit(result)
        except Exception as e:
            import traceback
            logger.error(f"Scan error: {traceback.format_exc()}")
            self.error.emit(str(e))
    
    def _on_progress(self, current, total, message):
        self.progress.emit(current, total, message)
    
    def _on_detection(self, detection):
        self.detection.emit(detection)
    
    def cancel_scan(self):
        """Request scan cancellation."""
        self._is_cancelled = True
        self.scanner.cancel()


class AIAnalysisWorker(QThread):
    """Background worker for AI analysis."""
    
    finished = pyqtSignal(object)  # AnalysisResult
    error = pyqtSignal(str)
    
    def __init__(self, detection_data: Dict, provider=None):
        super().__init__()
        self.detection_data = detection_data
        self.provider = provider
        self._is_cancelled = False
    
    def run(self):
        """Run AI analysis in background thread with robust error handling."""
        try:
            if not AI_ANALYSIS_AVAILABLE:
                self.error.emit("AI analysis module not available")
                return
            
            logger.info(f"Starting AI analysis for detection: {self.detection_data.get('detection_type', 'unknown')}")
            
            # Check cancellation before starting
            if self._is_cancelled:
                self.error.emit("Analysis cancelled")
                return
            
            analyzer = get_ai_analyzer()
            
            # Check if providers are configured
            configured = analyzer.get_configured_providers()
            if not configured:
                self.error.emit("No AI provider configured. Please add an API key in Settings > AI Analysis.")
                return
            
            # Check cancellation before API call
            if self._is_cancelled:
                self.error.emit("Analysis cancelled")
                return
            
            result = analyzer.analyze_detection(self.detection_data, self.provider)
            
            # Check cancellation before emitting result
            if self._is_cancelled:
                self.error.emit("Analysis cancelled")
                return
            
            if result:
                logger.info(f"AI analysis completed successfully. Verdict: {result.verdict.value}")
                self.finished.emit(result)
            else:
                self.error.emit("Analysis returned no result. The AI provider may not have responded correctly.")
        except Exception as e:
            import traceback
            error_detail = traceback.format_exc()
            logger.error(f"AI analysis error: {error_detail}")
            # Ensure we emit the error safely
            try:
                self.error.emit(f"Analysis error: {str(e)}")
            except:
                pass  # If even error emission fails, just log it
    
    def cancel(self):
        """Cancel the analysis."""
        self._is_cancelled = True


class DetectionTable(QTableWidget):
    """Table widget for displaying detections."""
    
    action_requested = pyqtSignal(str, object)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_detections: List[Detection] = []
        self.setup_ui()
    
    def setup_ui(self):
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels([
            'Risk', 'Type', 'Indicator', 'Description', 'Confidence', 'Action'
        ])
        
        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
    
    def add_detection(self, detection: Detection):
        """Add a detection to the table."""
        self._all_detections.append(detection)
        self._add_detection_row(detection)
    
    def _get_risk_color(self, risk_level: RiskLevel) -> QColor:
        colors = {
            RiskLevel.CRITICAL: QColor(CYBER_COLORS['critical']),
            RiskLevel.HIGH: QColor(CYBER_COLORS['high']),
            RiskLevel.MEDIUM: QColor(CYBER_COLORS['medium']),
            RiskLevel.LOW: QColor(CYBER_COLORS['low']),
            RiskLevel.INFO: QColor(CYBER_COLORS['info']),
        }
        return colors.get(risk_level, QColor(CYBER_COLORS['text']))
    
    def _show_detection_details(self, detection: Detection):
        dialog = DetectionDialog(detection, self)
        dialog.action_requested.connect(self._on_action_requested)
        dialog.exec_()
    
    def _on_action_requested(self, action: str, detection: Detection):
        self.action_requested.emit(action, detection)
    
    def filter_by_risk(self, risk_level: str):
        """Filter the table to show only detections of a specific risk level.
        
        Args:
            risk_level: Risk level to filter by ('All', 'Critical', 'High', 'Medium', 'Low', 'Info')
        """
        # Clear the table
        self.setRowCount(0)
        
        # Determine which detections to show
        risk_filter = risk_level.lower()
        
        for detection in self._all_detections:
            detection_risk = detection.risk_level.value.lower()
            
            # Check if this detection matches the filter
            if risk_filter == 'all':
                show = True
            elif risk_filter == 'critical' and detection_risk == 'critical':
                show = True
            elif risk_filter == 'high' and detection_risk == 'high':
                show = True
            elif risk_filter == 'medium' and detection_risk == 'medium':
                show = True
            elif risk_filter == 'low' and detection_risk == 'low':
                show = True
            elif risk_filter == 'info' and detection_risk == 'info':
                show = True
            else:
                show = False
            
            if show:
                self._add_detection_row(detection)
    
    def _add_detection_row(self, detection: Detection):
        """Add a single detection row to the table (internal helper)."""
        row = self.rowCount()
        self.insertRow(row)
        
        risk_item = QTableWidgetItem(detection.risk_level.value.upper())
        risk_item.setForeground(self._get_risk_color(detection.risk_level))
        risk_item.setFont(QFont('Consolas', 10, QFont.Bold))
        self.setItem(row, 0, risk_item)
        
        self.setItem(row, 1, QTableWidgetItem(detection.detection_type))
        self.setItem(row, 2, QTableWidgetItem(detection.indicator[:100]))
        self.setItem(row, 3, QTableWidgetItem(detection.description[:150]))
        
        confidence_item = QTableWidgetItem(f"{detection.confidence:.0%}")
        self.setItem(row, 4, confidence_item)
        
        view_btn = QPushButton("View Details")
        view_btn.setProperty('detection', detection)
        view_btn.clicked.connect(lambda: self._show_detection_details(detection))
        self.setCellWidget(row, 5, view_btn)
    
    def clear_detections(self):
        self.setRowCount(0)
        self._all_detections.clear()


class DetectionDialog(QDialog):
    """Dialog for displaying detection details with AI analysis."""
    
    action_requested = pyqtSignal(str, object)
    
    def __init__(self, detection: Detection, parent=None):
        super().__init__(parent)
        self.detection = detection
        self.ai_result: Optional[Any] = None
        self.ai_worker: Optional[AIAnalysisWorker] = None
        self._dialog_closing = False
        self._is_whitelisted = False  # Track whitelist status
        self.whitelist_btn: Optional[QPushButton] = None  # Store button reference
        
        self.setWindowTitle(f"Detection Details - {detection.detection_type}")
        self.setMinimumSize(950, 850)
        self.resize(1000, 900)
        self._check_whitelist_status()
        self.setup_ui()
    
    def _check_whitelist_status(self):
        """Check if the detection is already whitelisted."""
        try:
            whitelist = get_whitelist()
            
            # Check various identifiers
            identifiers_to_check = []
            
            if self.detection.file_path:
                identifiers_to_check.append(self.detection.file_path)
            if self.detection.process_name:
                identifiers_to_check.append(self.detection.process_name)
            if self.detection.indicator:
                identifiers_to_check.append(self.detection.indicator)
            if self.detection.evidence:
                if 'key_path' in self.detection.evidence:
                    identifiers_to_check.append(self.detection.evidence['key_path'])
                if 'sha256' in self.detection.evidence:
                    identifiers_to_check.append(self.detection.evidence['sha256'])
            
            # Check if any identifier is whitelisted
            for identifier in identifiers_to_check:
                if whitelist.is_whitelisted(identifier):
                    self._is_whitelisted = True
                    return
            
            self._is_whitelisted = False
        except Exception as e:
            logger.debug(f"Error checking whitelist status: {e}")
            self._is_whitelisted = False
    
    def closeEvent(self, event):
        """Handle dialog close event - clean up worker thread."""
        self._dialog_closing = True
        if self.ai_worker and self.ai_worker.isRunning():
            # Cancel the worker and wait for it to finish
            self.ai_worker.cancel()
            self.ai_worker.quit()
            if not self.ai_worker.wait(2000):  # Wait up to 2 seconds
                logger.warning("AI worker did not finish in time")
        event.accept()
    
    def reject(self):
        """Handle dialog rejection (ESC key or close button)."""
        self._dialog_closing = True
        if self.ai_worker and self.ai_worker.isRunning():
            self.ai_worker.cancel()
            self.ai_worker.quit()
            self.ai_worker.wait(1000)
        super().reject()
    
    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        
        # Create scroll area for content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        
        scroll_widget = QWidget()
        layout = QVBoxLayout(scroll_widget)
        layout.setSpacing(15)
        
        # ============ HEADER SECTION ============
        header_frame = QFrame()
        header_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {CYBER_COLORS['background_card']};
                border: 2px solid {CYBER_COLORS['border']};
                border-radius: 10px;
                padding: 15px;
            }}
        """)
        header_layout = QHBoxLayout(header_frame)
        
        # Risk badge
        risk_label = QLabel(self.detection.risk_level.value.upper())
        risk_label.setFont(QFont('Consolas', 18, QFont.Bold))
        risk_label.setStyleSheet(f"""
            color: white;
            background-color: {self._get_risk_color()};
            padding: 10px 25px;
            border-radius: 8px;
        """)
        header_layout.addWidget(risk_label)
        
        # Type and info
        info_layout = QVBoxLayout()
        type_label = QLabel(self.detection.detection_type)
        type_label.setFont(QFont('Consolas', 16, QFont.Bold))
        type_label.setStyleSheet(f"color: {CYBER_COLORS['secondary']};")
        info_layout.addWidget(type_label)
        
        confidence_label = QLabel(f"Confidence: {self.detection.confidence:.0%}")
        confidence_label.setStyleSheet(f"color: {CYBER_COLORS['text_muted']}; font-size: 12px;")
        info_layout.addWidget(confidence_label)
        header_layout.addLayout(info_layout)
        
        header_layout.addStretch()
        layout.addWidget(header_frame)
        
        # ============ DETECTION INFO SECTION ============
        info_group = QGroupBox("Detection Information")
        info_group.setStyleSheet(f"""
            QGroupBox {{
                font-size: 14px;
                font-weight: bold;
                border: 2px solid {CYBER_COLORS['border']};
                border-radius: 8px;
                margin-top: 20px;
                padding-top: 20px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px;
                color: {CYBER_COLORS['primary']};
            }}
        """)
        info_layout = QVBoxLayout(info_group)
        info_layout.setSpacing(10)
        
        # Indicator
        indicator_label = QLabel("Indicator:")
        indicator_label.setStyleSheet(f"color: {CYBER_COLORS['primary']}; font-weight: bold; font-size: 13px;")
        info_layout.addWidget(indicator_label)
        indicator_text = QTextEdit()
        indicator_text.setPlainText(self.detection.indicator)
        indicator_text.setReadOnly(True)
        indicator_text.setMinimumHeight(70)
        indicator_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {CYBER_COLORS['background_secondary']};
                border: 1px solid {CYBER_COLORS['border']};
                border-radius: 5px;
                padding: 8px;
                font-size: 12px;
            }}
        """)
        info_layout.addWidget(indicator_text)
        
        # Description
        desc_label = QLabel("Description:")
        desc_label.setStyleSheet(f"color: {CYBER_COLORS['primary']}; font-weight: bold; font-size: 13px;")
        info_layout.addWidget(desc_label)
        desc_text = QTextEdit()
        desc_text.setPlainText(self.detection.description)
        desc_text.setReadOnly(True)
        desc_text.setMinimumHeight(70)
        desc_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {CYBER_COLORS['background_secondary']};
                border: 1px solid {CYBER_COLORS['border']};
                border-radius: 5px;
                padding: 8px;
                font-size: 12px;
            }}
        """)
        info_layout.addWidget(desc_text)
        
        # Detection reason
        reason_label = QLabel("Detection Reason:")
        reason_label.setStyleSheet(f"color: {CYBER_COLORS['primary']}; font-weight: bold; font-size: 13px;")
        info_layout.addWidget(reason_label)
        reason_text = QTextEdit()
        reason_text.setPlainText(self.detection.detection_reason)
        reason_text.setReadOnly(True)
        reason_text.setMinimumHeight(60)
        reason_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {CYBER_COLORS['background_secondary']};
                border: 1px solid {CYBER_COLORS['border']};
                border-radius: 5px;
                padding: 8px;
                font-size: 12px;
            }}
        """)
        info_layout.addWidget(reason_text)
        
        layout.addWidget(info_group)
        
        # ============ EVIDENCE SECTION ============
        if self.detection.evidence:
            evidence_group = QGroupBox("Evidence")
            evidence_group.setStyleSheet(f"""
                QGroupBox {{
                    font-size: 14px;
                    font-weight: bold;
                    border: 2px solid {CYBER_COLORS['border']};
                    border-radius: 8px;
                    margin-top: 20px;
                    padding-top: 20px;
                }}
                QGroupBox::title {{
                    subcontrol-origin: margin;
                    left: 15px;
                    padding: 0 10px;
                    color: {CYBER_COLORS['primary']};
                }}
            """)
            evidence_layout = QVBoxLayout(evidence_group)
            evidence_text = QTextEdit()
            evidence_text.setPlainText(json.dumps(self.detection.evidence, indent=2))
            evidence_text.setReadOnly(True)
            evidence_text.setMinimumHeight(100)
            evidence_text.setMaximumHeight(150)
            evidence_text.setStyleSheet(f"""
                QTextEdit {{
                    background-color: #000;
                    color: {CYBER_COLORS['primary']};
                    border: 1px solid {CYBER_COLORS['border']};
                    border-radius: 5px;
                    padding: 8px;
                    font-family: 'Consolas', monospace;
                    font-size: 11px;
                }}
            """)
            evidence_layout.addWidget(evidence_text)
            layout.addWidget(evidence_group)
        
        # ============ AI ANALYSIS SECTION ============
        ai_group = QGroupBox("AI-Powered Analysis")
        ai_group.setStyleSheet(f"""
            QGroupBox {{
                font-size: 14px;
                font-weight: bold;
                border: 2px solid {CYBER_COLORS['secondary']};
                border-radius: 8px;
                margin-top: 20px;
                padding-top: 20px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px;
                color: {CYBER_COLORS['secondary']};
            }}
        """)
        ai_layout = QVBoxLayout(ai_group)
        ai_layout.setSpacing(12)
        
        # AI Provider selection row
        provider_frame = QFrame()
        provider_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {CYBER_COLORS['background_card']};
                border: 1px solid {CYBER_COLORS['border']};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        provider_layout = QHBoxLayout(provider_frame)
        
        provider_label = QLabel("Select AI Provider:")
        provider_label.setStyleSheet(f"color: {CYBER_COLORS['text']}; font-size: 13px; font-weight: bold;")
        provider_layout.addWidget(provider_label)
        
        self.ai_provider_combo = QComboBox()
        self.ai_provider_combo.addItems(['Auto (First Available)', 'Deepseek', 'OpenAI', 'Gemini'])
        self.ai_provider_combo.setMinimumWidth(200)
        provider_layout.addWidget(self.ai_provider_combo)
        
        provider_layout.addStretch()
        
        # Analyze button
        self.ai_analyze_btn = QPushButton(" ANALYZE WITH AI")
        self.ai_analyze_btn.setObjectName("aiButton")
        self.ai_analyze_btn.setMinimumHeight(45)
        self.ai_analyze_btn.setMinimumWidth(180)
        self.ai_analyze_btn.setFont(QFont('Consolas', 12, QFont.Bold))
        self.ai_analyze_btn.clicked.connect(self._start_ai_analysis)
        provider_layout.addWidget(self.ai_analyze_btn)
        
        ai_layout.addWidget(provider_frame)
        
        # AI Status label
        self.ai_progress_label = QLabel("Ready to analyze. Click the button above to start AI analysis.")
        self.ai_progress_label.setStyleSheet(f"""
            color: {CYBER_COLORS['text_muted']}; 
            font-size: 12px;
            padding: 5px;
        """)
        ai_layout.addWidget(self.ai_progress_label)
        
        # AI result area with styled frame
        result_frame = QFrame()
        result_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {CYBER_COLORS['background_secondary']};
                border: 2px solid {CYBER_COLORS['border']};
                border-radius: 8px;
            }}
        """)
        result_layout = QVBoxLayout(result_frame)
        result_layout.setContentsMargins(10, 10, 10, 10)
        
        self.ai_result_text = QTextEdit()
        self.ai_result_text.setReadOnly(True)
        self.ai_result_text.setMinimumHeight(250)
        self.ai_result_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {CYBER_COLORS['background_secondary']};
                color: {CYBER_COLORS['text']};
                border: none;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
                line-height: 1.5;
            }}
        """)
        self.ai_result_text.setPlaceholderText(
            "════════════════════════════════════════════════════════════\n"
            "                    AI ANALYSIS RESULTS\n"
            "════════════════════════════════════════════════════════════\n\n"
            "Click 'ANALYZE WITH AI' to get a detailed analysis of this\n"
            "detection using artificial intelligence.\n\n"
            "The AI will evaluate:\n"
            "  • Whether the detection is legitimate or malicious\n"
            "  • Risk assessment and confidence level\n"
            "  • Detailed technical analysis\n"
            "  • Specific indicators found\n"
            "  • Recommended actions to take"
        )
        result_layout.addWidget(self.ai_result_text)
        
        # Export button row
        export_layout = QHBoxLayout()
        export_layout.addStretch()
        
        self.export_ai_btn = QPushButton(" Export to HTML")
        self.export_ai_btn.setObjectName("aiButton")
        self.export_ai_btn.setMinimumHeight(35)
        self.export_ai_btn.setFont(QFont('Consolas', 10, QFont.Bold))
        self.export_ai_btn.clicked.connect(self._export_ai_analysis_html)
        self.export_ai_btn.setVisible(False)  # Hidden until analysis is done
        export_layout.addWidget(self.export_ai_btn)
        
        result_layout.addLayout(export_layout)
        
        ai_layout.addWidget(result_frame)
        layout.addWidget(ai_group)
        
        # ============ ACTION BUTTONS SECTION ============
        actions_group = QGroupBox("Available Actions")
        actions_group.setStyleSheet(f"""
            QGroupBox {{
                font-size: 14px;
                font-weight: bold;
                border: 2px solid {CYBER_COLORS['border']};
                border-radius: 8px;
                margin-top: 20px;
                padding-top: 20px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px;
                color: {CYBER_COLORS['primary']};
            }}
        """)
        actions_layout = QHBoxLayout(actions_group)
        actions_layout.setSpacing(10)
        
        if self.detection.process_id and self.detection.process_id > 0:
            kill_btn = QPushButton(" Kill Process")
            kill_btn.setObjectName("dangerButton")
            kill_btn.setMinimumHeight(40)
            kill_btn.setFont(QFont('Consolas', 11, QFont.Bold))
            kill_btn.clicked.connect(lambda: self._request_action("kill_process"))
            kill_btn.setToolTip(f"Terminate process PID: {self.detection.process_id}")
            actions_layout.addWidget(kill_btn)
            
            suspend_btn = QPushButton(" Suspend Process")
            suspend_btn.setObjectName("warningButton")
            suspend_btn.setMinimumHeight(40)
            suspend_btn.setFont(QFont('Consolas', 11, QFont.Bold))
            suspend_btn.clicked.connect(lambda: self._request_action("suspend_process"))
            actions_layout.addWidget(suspend_btn)
        
        if self.detection.file_path:
            delete_btn = QPushButton(" Delete File")
            delete_btn.setObjectName("dangerButton")
            delete_btn.setMinimumHeight(40)
            delete_btn.setFont(QFont('Consolas', 11, QFont.Bold))
            delete_btn.clicked.connect(lambda: self._request_action("delete_file"))
            delete_btn.setToolTip(f"Delete: {self.detection.file_path}")
            actions_layout.addWidget(delete_btn)
            
            quarantine_btn = QPushButton(" Quarantine File")
            quarantine_btn.setMinimumHeight(40)
            quarantine_btn.setFont(QFont('Consolas', 11, QFont.Bold))
            quarantine_btn.clicked.connect(lambda: self._request_action("quarantine_file"))
            actions_layout.addWidget(quarantine_btn)
        
        whitelist_btn = QPushButton(" Add to Whitelist")
        whitelist_btn.setMinimumHeight(40)
        whitelist_btn.setFont(QFont('Consolas', 11, QFont.Bold))
        
        # Set initial text, style, and action based on whitelist status
        if self._is_whitelisted:
            whitelist_btn.setText("✓ Remove from Whitelist")
            whitelist_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {CYBER_COLORS['low']};
                    color: white;
                    border: 2px solid {CYBER_COLORS['low']};
                    border-radius: 8px;
                    padding: 8px 16px;
                    font-size: 11px;
                    font-weight: bold;
                }}
                QPushButton:hover {{
                    background-color: #5ab868;
                    border-color: #5ab868;
                }}
            """)
            whitelist_btn.clicked.connect(lambda: self._request_action("remove_whitelist"))
        else:
            whitelist_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {CYBER_COLORS['background_card']};
                    color: {CYBER_COLORS['primary']};
                    border: 2px solid {CYBER_COLORS['primary']};
                    border-radius: 8px;
                    padding: 8px 16px;
                }}
                QPushButton:hover {{
                    background-color: {CYBER_COLORS['primary']};
                    color: {CYBER_COLORS['background']};
                }}
            """)
            whitelist_btn.clicked.connect(lambda: self._request_action("add_whitelist"))
        
        # Store reference for later updates
        self.whitelist_btn = whitelist_btn
        actions_layout.addWidget(whitelist_btn)
        
        if self.detection.file_path:
            open_loc_btn = QPushButton(" Open Location")
            open_loc_btn.setMinimumHeight(40)
            open_loc_btn.setFont(QFont('Consolas', 11, QFont.Bold))
            open_loc_btn.clicked.connect(lambda: self._request_action("open_location"))
            actions_layout.addWidget(open_loc_btn)
        
        actions_layout.addStretch()
        layout.addWidget(actions_group)
        
        # Add stretch at end
        layout.addStretch()
        
        # Set scroll widget
        scroll.setWidget(scroll_widget)
        main_layout.addWidget(scroll)
        
        # ============ CLOSE BUTTON ============
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_btn = QPushButton(" Close")
        close_btn.setMinimumWidth(120)
        close_btn.setMinimumHeight(40)
        close_btn.setFont(QFont('Consolas', 12, QFont.Bold))
        close_btn.clicked.connect(self.reject)
        button_layout.addWidget(close_btn)
        
        button_layout.addStretch()
        main_layout.addLayout(button_layout)
        
        # Check if AI is available and configured (wrap in try-except to prevent crash)
        try:
            self._check_ai_availability()
        except Exception as e:
            logger.error(f"Error during AI availability check: {e}")
            # Set a safe default state
            self.ai_analyze_btn.setEnabled(False)
            self.ai_analyze_btn.setText(" AI ERROR")
    
    def _check_ai_availability(self):
        """Check if AI analysis is available and configured."""
        if not AI_ANALYSIS_AVAILABLE:
            self.ai_analyze_btn.setEnabled(False)
            self.ai_analyze_btn.setText(" AI UNAVAILABLE")
            self.ai_result_text.setPlaceholderText(
                "════════════════════════════════════════════════════════════\n"
                "                    AI ANALYSIS UNAVAILABLE\n"
                "════════════════════════════════════════════════════════════\n\n"
                "The AI analysis module is not available.\n\n"
                "Please ensure the ai_analysis module is properly installed\n"
                "and all dependencies (requests) are available."
            )
            return
        
        # Check if any providers are configured
        try:
            analyzer = get_ai_analyzer()
            configured_providers = analyzer.get_configured_providers()
            
            if not configured_providers:
                self.ai_analyze_btn.setEnabled(False)
                self.ai_analyze_btn.setText(" NO API KEY")
                self.ai_progress_label.setText(
                    "⚠ No AI provider configured. Go to Settings > AI Analysis to add an API key."
                )
                self.ai_progress_label.setStyleSheet(
                    f"color: {CYBER_COLORS['high']}; font-size: 12px; padding: 5px;"
                )
                self.ai_result_text.setPlaceholderText(
                    "════════════════════════════════════════════════════════════\n"
                    "                    NO AI PROVIDER CONFIGURED\n"
                    "════════════════════════════════════════════════════════════\n\n"
                    "To use AI-powered analysis, you need to configure at least\n"
                    "one AI provider with an API key.\n\n"
                    "Supported providers:\n"
                    "  • Deepseek (recommended)\n"
                    "  • OpenAI (GPT-4)\n"
                    "  • Google Gemini\n\n"
                    "Go to Settings > AI Analysis to add your API key."
                )
                # Update provider combo to show status
                self.ai_provider_combo.clear()
                self.ai_provider_combo.addItem("No providers configured")
                self.ai_provider_combo.setEnabled(False)
            else:
                # Provider(s) are configured - enable the button
                self.ai_analyze_btn.setEnabled(True)
                self.ai_analyze_btn.setText(" ANALYZE WITH AI")
                
                # Update combo box with available providers
                self.ai_provider_combo.clear()
                self.ai_provider_combo.addItem('Auto (First Available)')
                for provider in configured_providers:
                    self.ai_provider_combo.addItem(provider.value.title())
                
                provider_names = ', '.join([p.value.title() for p in configured_providers])
                self.ai_progress_label.setText(
                    f"✓ Ready to analyze. Configured providers: {provider_names}"
                )
                self.ai_progress_label.setStyleSheet(
                    f"color: {CYBER_COLORS['low']}; font-size: 12px; padding: 5px;"
                )
        except Exception as e:
            logger.error(f"Error checking AI availability: {e}")
            self.ai_analyze_btn.setEnabled(False)
            self.ai_analyze_btn.setText(" AI ERROR")
            self.ai_progress_label.setText(f"Error checking AI providers: {str(e)}")
            self.ai_progress_label.setStyleSheet(
                f"color: {CYBER_COLORS['critical']}; font-size: 12px; padding: 5px;"
            )
    
    def _get_risk_color(self) -> str:
        colors = {
            RiskLevel.CRITICAL: CYBER_COLORS['critical'],
            RiskLevel.HIGH: CYBER_COLORS['high'],
            RiskLevel.MEDIUM: CYBER_COLORS['medium'],
            RiskLevel.LOW: CYBER_COLORS['low'],
            RiskLevel.INFO: CYBER_COLORS['info'],
        }
        return colors.get(self.detection.risk_level, CYBER_COLORS['text'])
    
    def _start_ai_analysis(self):
        """Start AI analysis in background with VirusTotal IOC checking."""
        if not AI_ANALYSIS_AVAILABLE:
            QMessageBox.warning(self, "Not Available", "AI analysis module not available.")
            return
        
        # Get selected provider
        provider_idx = self.ai_provider_combo.currentIndex()
        provider = None
        if provider_idx == 1:
            provider = AIProvider.DEEPSEEK
        elif provider_idx == 2:
            provider = AIProvider.OPENAI
        elif provider_idx == 3:
            provider = AIProvider.GEMINI
        
        # Check if provider is configured
        if provider:
            analyzer = get_ai_analyzer()
            if not analyzer.is_provider_configured(provider):
                QMessageBox.warning(
                    self, "Provider Not Configured",
                    f"{provider.value.title()} API key is not configured.\n\n"
                    f"Please add your API key in Settings > AI Analysis."
                )
                return
        
        # Prepare detection data
        detection_data = {
            'detection_type': self.detection.detection_type,
            'risk_level': self.detection.risk_level.value,
            'indicator': self.detection.indicator,
            'description': self.detection.description,
            'detection_reason': self.detection.detection_reason,
            'evidence': self.detection.evidence or {},
            'process_name': self.detection.process_name or '',
            'process_id': self.detection.process_id or 0,
            'file_path': self.detection.file_path or '',
            'command_line': self.detection.command_line or '',
            'user': self.detection.user or '',
        }
        
        # Check IOCs against VirusTotal if API key is configured
        vt_result = None
        if VIRUSTOTAL_AVAILABLE and is_virustotal_available():
            try:
                self.ai_progress_label.setText("Checking IOCs against VirusTotal...")
                self.ai_progress_label.setStyleSheet(f"color: {CYBER_COLORS['secondary']}; font-size: 12px; padding: 5px;")
                
                vt_checker = get_virustotal_checker()
                vt_result = vt_checker.check_iocs_from_evidence(self.detection.evidence or {})
                
                # Add VirusTotal results to detection data
                detection_data['virustotal_result'] = {
                    'iocs_checked': vt_result.iocs_checked,
                    'iocs_malicious': vt_result.iocs_malicious,
                    'iocs_clean': vt_result.iocs_clean,
                    'overall_risk_adjustment': vt_result.overall_risk_adjustment,
                    'highest_risk_level': vt_result.highest_risk_level,
                    'vt_summary': vt_result.vt_summary,
                    'all_iocs': vt_result.all_iocs,
                    # Include detailed results
                    'hash_results': [
                        {
                            'hash_value': r.hash_value[:16] + '...',
                            'is_malicious': r.is_malicious,
                            'detection_ratio': r.detection_ratio,
                            'threat_names': r.threat_names[:3]
                        } for r in vt_result.hash_results if r.is_malicious
                    ],
                    'ip_results': [
                        {
                            'ip_address': r.ip_address,
                            'is_malicious': r.is_malicious,
                            'detection_ratio': r.detection_ratio,
                            'country': r.country,
                            'as_owner': r.as_owner
                        } for r in vt_result.ip_results if r.is_malicious
                    ],
                    'domain_results': [
                        {
                            'domain': r.domain,
                            'is_malicious': r.is_malicious,
                            'detection_ratio': r.detection_ratio,
                            'categories': r.categories
                        } for r in vt_result.domain_results if r.is_malicious
                    ],
                    'url_results': [
                        {
                            'url': r.url[:50] + '...' if len(r.url) > 50 else r.url,
                            'is_malicious': r.is_malicious,
                            'detection_ratio': r.detection_ratio
                        } for r in vt_result.url_results if r.is_malicious
                    ]
                }
                
                # Update risk level based on VirusTotal results
                if vt_result.iocs_malicious > 0:
                    original_risk = self.detection.risk_level
                    # Adjust risk level
                    if vt_result.highest_risk_level == 'critical':
                        if original_risk != RiskLevel.CRITICAL:
                            detection_data['risk_level'] = 'critical'
                            detection_data['risk_adjusted_by_vt'] = True
                    elif vt_result.highest_risk_level == 'high':
                        if original_risk not in [RiskLevel.CRITICAL]:
                            detection_data['risk_level'] = 'high'
                            detection_data['risk_adjusted_by_vt'] = True
                
                logger.info(f"[VIRUSTOTAL] IOC check complete: {vt_result.iocs_checked} checked, {vt_result.iocs_malicious} malicious")
                
            except Exception as e:
                logger.warning(f"VirusTotal IOC check failed: {e}")
                # Continue without VT results
                vt_result = None
        
        # Start worker
        self.ai_analyze_btn.setEnabled(False)
        self.ai_analyze_btn.setText(" ANALYZING...")
        
        # Build status message
        status_msg = "Connecting to AI provider and analyzing detection..."
        if vt_result and vt_result.iocs_checked > 0:
            status_msg = f"VT: {vt_result.iocs_checked} IOCs checked ({vt_result.iocs_malicious} malicious). Analyzing with AI..."
        
        self.ai_progress_label.setText(status_msg)
        self.ai_progress_label.setStyleSheet(f"color: {CYBER_COLORS['secondary']}; font-size: 12px; padding: 5px;")
        
        # Build waiting message
        vt_info = ""
        if vt_result and vt_result.iocs_checked > 0:
            vt_info = f"\n\nVirusTotal Results:\n"
            vt_info += f"  • IOCs Checked: {vt_result.iocs_checked}\n"
            vt_info += f"  • Malicious: {vt_result.iocs_malicious}\n"
            vt_info += f"  • Clean: {vt_result.iocs_clean}\n"
            if vt_result.vt_summary:
                vt_info += f"\n  Summary: {vt_result.vt_summary[:100]}...\n"
        
        self.ai_result_text.setPlainText(
            "════════════════════════════════════════════════════════════\n"
            "                    ANALYZING DETECTION...\n"
            "════════════════════════════════════════════════════════════\n\n"
            "Please wait while the AI analyzes this detection.\n\n"
            "This may take 10-30 seconds depending on the complexity\n"
            "of the detection and the AI provider response time.\n\n"
            "Analyzing:\n"
            f"  • Detection Type: {self.detection.detection_type}\n"
            f"  • Risk Level: {self.detection.risk_level.value.upper()}\n"
            f"  • Indicator: {self.detection.indicator[:50]}...{vt_info}"
        )
        
        self.ai_worker = AIAnalysisWorker(detection_data, provider)
        self.ai_worker.finished.connect(self._on_ai_finished)
        self.ai_worker.error.connect(self._on_ai_error)
        self.ai_worker.start()
    
    def _on_ai_finished(self, result):
        """Handle AI analysis completion."""
        # Check if dialog is still valid
        if self._dialog_closing:
            return
            
        try:
            self.ai_result = result
            self.ai_analyze_btn.setEnabled(True)
            self.ai_analyze_btn.setText(" ANALYZE WITH AI")
            
            # Show export button
            self.export_ai_btn.setVisible(True)
            
            # Format result with improved styling
            verdict_colors = {
                Verdict.LEGITIMATE: CYBER_COLORS['low'],
                Verdict.SUSPICIOUS: CYBER_COLORS['medium'],
                Verdict.MALICIOUS: CYBER_COLORS['critical'],
                Verdict.NEEDS_INVESTIGATION: CYBER_COLORS['high'],
                Verdict.UNKNOWN: CYBER_COLORS['text_muted'],
            }
            
            verdict_icons = {
                Verdict.LEGITIMATE: "✓ SAFE / LEGITIMATE",
                Verdict.SUSPICIOUS: "⚠ SUSPICIOUS",
                Verdict.MALICIOUS: "✗ MALICIOUS",
                Verdict.NEEDS_INVESTIGATION: "? NEEDS INVESTIGATION",
                Verdict.UNKNOWN: "? UNKNOWN",
            }
            
            color = verdict_colors.get(result.verdict, CYBER_COLORS['text'])
            
            # Update progress label with verdict
            self.ai_progress_label.setText(
                f"Analysis Complete | Verdict: {verdict_icons.get(result.verdict, 'UNKNOWN')} | "
                f"Confidence: {result.confidence:.0%} | Risk Score: {result.risk_score}/100"
            )
            self.ai_progress_label.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 13px; padding: 8px;")
            
            # Build formatted result text
            threat_type = getattr(result, 'threat_type', 'unknown').upper()
            mitre_techniques = getattr(result, 'mitre_techniques', [])
            severity_justification = getattr(result, 'severity_justification', '')
            
            result_text = f"""{'═'*60}
                    AI ANALYSIS RESULTS
{'═'*60}

┌{'─'*58}┐
│  VERDICT: {verdict_icons.get(result.verdict, 'UNKNOWN'):<30}       │
│  CONFIDENCE: {result.confidence:.0%:<10}  RISK SCORE: {result.risk_score}/100          │
│  PROVIDER: {result.provider.value.title():<15}                           │
│  THREAT TYPE: {threat_type:<20}                    │
└{'─'*58}┘

{'═'*60}
                    EXECUTIVE SUMMARY
{'═'*60}

{result.summary}

{'═'*60}
                   DETAILED ANALYSIS
{'═'*60}

{result.detailed_analysis}
"""
            
            # Add MITRE ATT&CK techniques if available
            if mitre_techniques:
                result_text += f"""
{'═'*60}
                  MITRE ATT&CK TECHNIQUES
{'═'*60}

"""
                for technique in mitre_techniques:
                    result_text += f"  • {technique}\n"
            
            # Add indicators section
            if result.indicators:
                result_text += f"""
{'═'*60}
                    INDICATORS OF COMPROMISE
{'═'*60}

"""
                for i, indicator in enumerate(result.indicators, 1):
                    result_text += f"  [{i}] {indicator}\n"
            else:
                result_text += f"""
{'═'*60}
                    INDICATORS OF COMPROMISE
{'═'*60}

  No specific indicators identified.
"""
            
            # Add recommendations section
            if result.recommendations:
                result_text += f"""
{'═'*60}
                     RECOMMENDATIONS
{'═'*60}

"""
                for i, rec in enumerate(result.recommendations, 1):
                    result_text += f"  {i}. {rec}\n\n"
            
            # Add severity justification
            if severity_justification:
                result_text += f"""
{'═'*60}
                  SEVERITY JUSTIFICATION
{'═'*60}

{severity_justification}
"""
            
            result_text += f"\n{'═'*60}\n"
            
            self.ai_result_text.setPlainText(result_text)
        except Exception as e:
            logger.error(f"Error updating AI result UI: {e}")
    
    def _on_ai_error(self, error: str):
        """Handle AI analysis error."""
        # Check if dialog is still valid
        if self._dialog_closing:
            return
            
        try:
            self.ai_analyze_btn.setEnabled(True)
            self.ai_analyze_btn.setText(" ANALYZE WITH AI")
            self.ai_progress_label.setText("Analysis failed - see details below")
            self.ai_progress_label.setStyleSheet(f"color: {CYBER_COLORS['critical']}; font-weight: bold; font-size: 13px; padding: 8px;")
            self.ai_result_text.setPlainText(
                "════════════════════════════════════════════════════════════\n"
                "                    ANALYSIS FAILED\n"
                "════════════════════════════════════════════════════════════\n\n"
                f"Error: {error}\n\n"
                "Possible solutions:\n"
                "  1. Check your API key in Settings > AI Analysis\n"
                "  2. Verify your internet connection\n"
                "  3. Try a different AI provider\n"
                "  4. Check if the API service is available\n\n"
                "If the problem persists, please check the application logs."
            )
        except Exception as e:
            logger.error(f"Error updating AI error UI: {e}")
    
    def _request_action(self, action: str):
        self.action_requested.emit(action, self.detection)
    
    def update_whitelist_button(self, is_whitelisted: bool):
        """Update the whitelist button after an action is completed.
        
        Args:
            is_whitelisted: True if the detection is now whitelisted
        """
        self._is_whitelisted = is_whitelisted
        if self.whitelist_btn:
            # Disconnect old connections
            try:
                self.whitelist_btn.clicked.disconnect()
            except:
                pass
            
            if is_whitelisted:
                self.whitelist_btn.setText("✓ Remove from Whitelist")
                self.whitelist_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {CYBER_COLORS['low']};
                        color: white;
                        border: 2px solid {CYBER_COLORS['low']};
                        border-radius: 8px;
                        padding: 12px 24px;
                        font-size: 14px;
                        font-weight: bold;
                    }}
                    QPushButton:hover {{
                        background-color: #5ab868;
                        border-color: #5ab868;
                    }}
                """)
                self.whitelist_btn.clicked.connect(lambda: self._request_action("remove_whitelist"))
            else:
                self.whitelist_btn.setText(" Add to Whitelist")
                self.whitelist_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {CYBER_COLORS['background_card']};
                        color: {CYBER_COLORS['primary']};
                        border: 2px solid {CYBER_COLORS['primary']};
                        border-radius: 8px;
                        padding: 12px 24px;
                        font-size: 14px;
                        font-weight: bold;
                    }}
                    QPushButton:hover {{
                        background-color: {CYBER_COLORS['primary']};
                        color: {CYBER_COLORS['background']};
                    }}
                """)
                self.whitelist_btn.clicked.connect(lambda: self._request_action("add_whitelist"))
    
    def _export_ai_analysis_html(self):
        """Export AI analysis results to an HTML file with cyber theme."""
        if not self.ai_result:
            QMessageBox.warning(self, "No Analysis", "No AI analysis to export. Run analysis first.")
            return
        
        # Ask user for save location
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export AI Analysis", 
            f"ai_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            "HTML Files (*.html)"
        )
        
        if not filepath:
            return
        
        try:
            # Build HTML with cyber theme
            html_content = self._generate_ai_analysis_html()
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"AI analysis exported to: {filepath}")
            reply = QMessageBox.information(
                self, "Export Complete",
                f"AI analysis exported successfully to:\n{filepath}\n\nWould you like to open it?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                webbrowser.open(f"file://{filepath}")
        except Exception as e:
            logger.error(f"Failed to export AI analysis: {e}")
            QMessageBox.critical(self, "Export Failed", f"Failed to export analysis: {str(e)}")
    
    def _generate_ai_analysis_html(self) -> str:
        """Generate HTML content for AI analysis export with cyber theme."""
        result = self.ai_result
        detection = self.detection
        
        # Verdict colors and icons
        verdict_styles = {
            Verdict.LEGITIMATE: ('#6bcb77', '✓ SAFE / LEGITIMATE'),
            Verdict.SUSPICIOUS: ('#ffd93d', '⚠ SUSPICIOUS'),
            Verdict.MALICIOUS: ('#ff0040', '✗ MALICIOUS'),
            Verdict.NEEDS_INVESTIGATION: ('#ff6b35', '? NEEDS INVESTIGATION'),
            Verdict.UNKNOWN: ('#8a8a8a', '? UNKNOWN'),
        }
        
        color, icon = verdict_styles.get(result.verdict, ('#8a8a8a', '? UNKNOWN'))
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberGuardian AI Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0f0f 0%, #121a1a 50%, #1a2424 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        .header {{
            background: linear-gradient(90deg, #1a2424, #0a0f0f);
            border: 2px solid #00ff9d;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 0 30px rgba(0, 255, 157, 0.2);
        }}
        
        .header h1 {{
            color: #00ff9d;
            font-size: 2.5em;
            text-transform: uppercase;
            letter-spacing: 5px;
            text-shadow: 0 0 20px rgba(0, 255, 157, 0.5);
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            color: #00b8ff;
            font-size: 1.1em;
        }}
        
        .verdict-box {{
            background: linear-gradient(135deg, {color}22, {color}11);
            border: 3px solid {color};
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 0 25px {color}44;
        }}
        
        .verdict-box .verdict-text {{
            color: {color};
            font-size: 2em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 3px;
        }}
        
        .verdict-box .meta {{
            margin-top: 15px;
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
        }}
        
        .verdict-box .meta-item {{
            background: #0a0f0f;
            padding: 10px 20px;
            border-radius: 8px;
            border: 1px solid {color}66;
        }}
        
        .verdict-box .meta-label {{
            color: #8a8a8a;
            font-size: 0.85em;
        }}
        
        .verdict-box .meta-value {{
            color: {color};
            font-size: 1.2em;
            font-weight: bold;
        }}
        
        .section {{
            background: #121a1a;
            border: 1px solid #2a3a3a;
            border-left: 4px solid #00ff9d;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
        }}
        
        .section h2 {{
            color: #00ff9d;
            font-size: 1.3em;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #2a3a3a;
        }}
        
        .section p {{
            line-height: 1.8;
            color: #c0c0c0;
        }}
        
        .detection-info {{
            background: #0a0f0f;
            border: 1px solid #2a3a3a;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
        }}
        
        .detection-info .row {{
            display: flex;
            padding: 8px 0;
            border-bottom: 1px solid #1a2424;
        }}
        
        .detection-info .row:last-child {{
            border-bottom: none;
        }}
        
        .detection-info .label {{
            color: #00ff9d;
            width: 150px;
            flex-shrink: 0;
        }}
        
        .detection-info .value {{
            color: #e0e0e0;
            word-break: break-all;
        }}
        
        .indicators-list, .recommendations-list, .mitre-list {{
            list-style: none;
            padding: 0;
        }}
        
        .indicators-list li, .recommendations-list li, .mitre-list li {{
            background: #0a0f0f;
            border-left: 3px solid #00b8ff;
            padding: 12px 15px;
            margin-bottom: 10px;
            border-radius: 0 8px 8px 0;
        }}
        
        .recommendations-list li {{
            border-left-color: #ff6b35;
        }}
        
        .mitre-list li {{
            border-left-color: #ff00ff;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: #8a8a8a;
            border-top: 1px solid #2a3a3a;
            margin-top: 30px;
        }}
        
        .footer .logo {{
            color: #00ff9d;
            font-size: 1.5em;
            font-weight: bold;
        }}
        
        .scan-lines {{
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            pointer-events: none;
            background: repeating-linear-gradient(
                0deg,
                rgba(0, 255, 157, 0.03) 0px,
                rgba(0, 255, 157, 0.03) 1px,
                transparent 1px,
                transparent 2px
            );
            z-index: 1000;
        }}
        
        @media print {{
            body {{
                background: white;
                color: black;
            }}
            .section {{
                background: #f5f5f5;
                border-color: #ddd;
            }}
            .verdict-box {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="scan-lines"></div>
    <div class="container">
        <div class="header">
            <h1>⚔ CyberGuardian</h1>
            <div class="subtitle">AI-Powered Threat Analysis Report</div>
        </div>
        
        <div class="verdict-box">
            <div class="verdict-text">{icon}</div>
            <div class="meta">
                <div class="meta-item">
                    <div class="meta-label">CONFIDENCE</div>
                    <div class="meta-value">{result.confidence:.0%}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">RISK SCORE</div>
                    <div class="meta-value">{result.risk_score}/100</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">PROVIDER</div>
                    <div class="meta-value">{result.provider.value.title()}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">THREAT TYPE</div>
                    <div class="meta-value">{result.threat_type.upper()}</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>📋 Detection Information</h2>
            <div class="detection-info">
                <div class="row">
                    <span class="label">Type:</span>
                    <span class="value">{detection.detection_type}</span>
                </div>
                <div class="row">
                    <span class="label">Risk Level:</span>
                    <span class="value">{detection.risk_level.value.upper()}</span>
                </div>
                <div class="row">
                    <span class="label">Indicator:</span>
                    <span class="value">{detection.indicator}</span>
                </div>
                <div class="row">
                    <span class="label">Description:</span>
                    <span class="value">{detection.description}</span>
                </div>
                <div class="row">
                    <span class="label">Process:</span>
                    <span class="value">{detection.process_name or 'N/A'}</span>
                </div>
                <div class="row">
                    <span class="label">File Path:</span>
                    <span class="value">{detection.file_path or 'N/A'}</span>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <p>{result.summary}</p>
        </div>
        
        <div class="section">
            <h2>🔬 Detailed Analysis</h2>
            <p>{result.detailed_analysis.replace(chr(10), '<br>')}</p>
        </div>'''
        
        # Add MITRE techniques if available
        if result.mitre_techniques:
            html += f'''
        <div class="section">
            <h2>🎯 MITRE ATT&CK Techniques</h2>
            <ul class="mitre-list">
'''
            for technique in result.mitre_techniques:
                html += f'                <li>{technique}</li>\n'
            html += '''            </ul>
        </div>'''
        
        # Add indicators
        if result.indicators:
            html += f'''
        <div class="section">
            <h2>🔍 Indicators of Compromise</h2>
            <ul class="indicators-list">
'''
            for indicator in result.indicators:
                html += f'                <li>{indicator}</li>\n'
            html += '''            </ul>
        </div>'''
        
        # Add recommendations
        if result.recommendations:
            html += f'''
        <div class="section">
            <h2>✅ Recommendations</h2>
            <ol class="recommendations-list">
'''
            for i, rec in enumerate(result.recommendations, 1):
                html += f'                <li><strong>{i}.</strong> {rec}</li>\n'
            html += '''            </ol>
        </div>'''
        
        # Add severity justification
        if result.severity_justification:
            html += f'''
        <div class="section">
            <h2>⚖ Severity Justification</h2>
            <p>{result.severity_justification}</p>
        </div>'''
        
        # Footer
        html += f'''
        <div class="footer">
            <div class="logo">CyberGuardian</div>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p>AI Provider: {result.provider.value.title()} | Analysis ID: {datetime.now().strftime('%Y%m%d%H%M%S')}</p>
        </div>
    </div>
</body>
</html>'''
        
        return html


class SettingsDialog(QDialog):
    """Settings configuration dialog."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.config = get_config()
        self.setWindowTitle("Settings - CyberGuardian")
        self.setMinimumSize(750, 600)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        tabs = QTabWidgetInner()
        
        general_tab = self._create_general_tab()
        tabs.addTab(general_tab, "General")
        
        scan_tab = self._create_scan_tab()
        tabs.addTab(scan_tab, "Scan")
        
        api_tab = self._create_api_tab()
        tabs.addTab(api_tab, "API Keys")
        
        ai_tab = self._create_ai_tab()
        tabs.addTab(ai_tab, "AI Analysis")
        
        yara_tab = self._create_yara_tab()
        tabs.addTab(yara_tab, "Yara Rules")
        
        layout.addWidget(tabs)
        
        button_layout = QHBoxLayout()
        
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        button_layout.addWidget(save_btn)
        
        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.clicked.connect(self.reset_settings)
        button_layout.addWidget(reset_btn)
        
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
    
    def _create_general_tab(self) -> QWidget:
        widget = QWidget()
        layout = QFormLayout(widget)
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(['cyber_dark', 'cyber_light', 'standard'])
        self.theme_combo.setCurrentText(self.config.config.ui.theme)
        layout.addRow("Theme:", self.theme_combo)
        
        self.font_size = QSpinBox()
        self.font_size.setRange(8, 16)
        self.font_size.setValue(self.config.config.ui.font_size)
        layout.addRow("Font Size:", self.font_size)
        
        self.show_popups = QCheckBox()
        self.show_popups.setChecked(self.config.config.ui.show_popup_alerts)
        layout.addRow("Show Popup Alerts:", self.show_popups)
        
        self.sound_alerts = QCheckBox()
        self.sound_alerts.setChecked(self.config.config.ui.sound_alerts)
        layout.addRow("Sound Alerts:", self.sound_alerts)
        
        self.log_level = QComboBox()
        self.log_level.addItems(['DEBUG', 'INFO', 'WARNING', 'ERROR'])
        self.log_level.setCurrentText(self.config.config.log_level)
        layout.addRow("Log Level:", self.log_level)
        
        self.max_threads = QSpinBox()
        self.max_threads.setRange(1, 16)
        self.max_threads.setValue(self.config.config.max_scan_threads)
        layout.addRow("Max Scan Threads:", self.max_threads)
        
        self.scan_timeout = QSpinBox()
        self.scan_timeout.setRange(30, 600)
        self.scan_timeout.setValue(self.config.config.scan_timeout_seconds)
        layout.addRow("Scan Timeout (seconds):", self.scan_timeout)
        
        return widget
    
    def _create_scan_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        process_group = QGroupBox("Process Scanning")
        process_layout = QVBoxLayout(process_group)
        
        self.scan_process_memory = QCheckBox("Scan process memory")
        self.scan_process_memory.setChecked(self.config.config.scan.process_scan_memory)
        process_layout.addWidget(self.scan_process_memory)
        
        self.scan_process_behavior = QCheckBox("Behavioral analysis")
        self.scan_process_behavior.setChecked(self.config.config.scan.process_scan_behavior)
        process_layout.addWidget(self.scan_process_behavior)
        
        self.scan_process_hashes = QCheckBox("Hash reputation lookup")
        self.scan_process_hashes.setChecked(self.config.config.scan.process_scan_hashes)
        process_layout.addWidget(self.scan_process_hashes)
        
        self.scan_process_signatures = QCheckBox("Digital signature verification")
        self.scan_process_signatures.setChecked(self.config.config.scan.process_scan_signatures)
        process_layout.addWidget(self.scan_process_signatures)
        
        layout.addWidget(process_group)
        
        file_group = QGroupBox("File Scanning")
        file_layout = QVBoxLayout(file_group)
        
        self.scan_file_yara = QCheckBox("Yara rule scanning")
        self.scan_file_yara.setChecked(self.config.config.scan.file_scan_yara)
        file_layout.addWidget(self.scan_file_yara)
        
        self.scan_file_entropy = QCheckBox("Entropy analysis")
        self.scan_file_entropy.setChecked(self.config.config.scan.file_scan_entropy)
        file_layout.addWidget(self.scan_file_entropy)
        
        self.scan_file_pe = QCheckBox("PE analysis")
        self.scan_file_pe.setChecked(self.config.config.scan.file_scan_pe)
        file_layout.addWidget(self.scan_file_pe)
        
        self.scan_file_stego = QCheckBox("Steganography detection")
        self.scan_file_stego.setChecked(self.config.config.scan.file_scan_stego)
        file_layout.addWidget(self.scan_file_stego)
        
        self.scan_file_hashes = QCheckBox("Hash reputation lookup")
        self.scan_file_hashes.setChecked(self.config.config.scan.file_scan_hashes)
        file_layout.addWidget(self.scan_file_hashes)
        
        layout.addWidget(file_group)
        
        network_group = QGroupBox("Network Scanning")
        network_layout = QVBoxLayout(network_group)
        
        self.scan_network_dns = QCheckBox("DNS resolution")
        self.scan_network_dns.setChecked(self.config.config.scan.network_resolve_dns)
        network_layout.addWidget(self.scan_network_dns)
        
        self.scan_network_threat = QCheckBox("Threat intelligence lookup")
        self.scan_network_threat.setChecked(self.config.config.scan.network_threat_lookup)
        network_layout.addWidget(self.scan_network_threat)
        
        self.scan_network_beacon = QCheckBox("Beaconing detection")
        self.scan_network_beacon.setChecked(self.config.config.scan.network_detect_beaconing)
        network_layout.addWidget(self.scan_network_beacon)
        
        layout.addWidget(network_group)
        layout.addStretch()
        return widget
    
    def _create_api_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Load API keys from secure storage
        secure_storage = get_secure_storage()
        saved_keys = load_all_api_keys()
        
        # Threat Intelligence APIs
        ti_group = QGroupBox("Threat Intelligence APIs")
        ti_layout = QFormLayout(ti_group)
        
        self.vt_api_key = QLineEdit()
        self.vt_api_key.setEchoMode(QLineEdit.Password)
        self.vt_api_key.setText(saved_keys.get('virustotal_api_key', '') or '')
        self.vt_api_key.setPlaceholderText("Enter VirusTotal API key")
        ti_layout.addRow("VirusTotal API Key:", self.vt_api_key)
        
        self.abuseipdb_api_key = QLineEdit()
        self.abuseipdb_api_key.setEchoMode(QLineEdit.Password)
        self.abuseipdb_api_key.setText(saved_keys.get('abuseipdb_api_key', '') or '')
        self.abuseipdb_api_key.setPlaceholderText("Enter AbuseIPDB API key")
        ti_layout.addRow("AbuseIPDB API Key:", self.abuseipdb_api_key)
        
        self.alienvault_api_key = QLineEdit()
        self.alienvault_api_key.setEchoMode(QLineEdit.Password)
        self.alienvault_api_key.setText(saved_keys.get('alienvault_api_key', '') or '')
        self.alienvault_api_key.setPlaceholderText("Enter AlienVault OTX API key")
        ti_layout.addRow("AlienVault OTX API Key:", self.alienvault_api_key)
        
        layout.addWidget(ti_group)
        
        # Cache settings
        cache_group = QGroupBox("Cache Settings")
        cache_layout = QFormLayout(cache_group)
        
        self.cache_ttl = QSpinBox()
        self.cache_ttl.setRange(1, 168)
        self.cache_ttl.setValue(self.config.config.api.cache_ttl_hours)
        cache_layout.addRow("Cache TTL (hours):", self.cache_ttl)
        
        layout.addWidget(cache_group)
        
        # Security info
        storage_type = secure_storage.get_storage_type()
        info_label = QLabel(
            f"🔒 API keys are stored securely using:\n{storage_type}\n\n"
            "Keys are encrypted and never stored in plain text."
        )
        info_label.setStyleSheet(f"color: {CYBER_COLORS['primary']}; font-style: italic;")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        layout.addStretch()
        return widget
    
    def _create_ai_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Load API keys from secure storage
        saved_keys = load_all_api_keys()
        
        # AI Provider API Keys
        ai_group = QGroupBox("AI Provider API Keys")
        ai_layout = QFormLayout(ai_group)
        
        self.deepseek_api_key = QLineEdit()
        self.deepseek_api_key.setEchoMode(QLineEdit.Password)
        self.deepseek_api_key.setText(saved_keys.get('deepseek_api_key', '') or '')
        self.deepseek_api_key.setPlaceholderText("Enter Deepseek API key")
        ai_layout.addRow("Deepseek API Key:", self.deepseek_api_key)
        
        self.openai_api_key = QLineEdit()
        self.openai_api_key.setEchoMode(QLineEdit.Password)
        self.openai_api_key.setText(saved_keys.get('openai_api_key', '') or '')
        self.openai_api_key.setPlaceholderText("Enter OpenAI API key")
        ai_layout.addRow("OpenAI API Key:", self.openai_api_key)
        
        self.gemini_api_key = QLineEdit()
        self.gemini_api_key.setEchoMode(QLineEdit.Password)
        self.gemini_api_key.setText(saved_keys.get('gemini_api_key', '') or '')
        self.gemini_api_key.setPlaceholderText("Enter Google Gemini API key")
        ai_layout.addRow("Gemini API Key:", self.gemini_api_key)
        
        layout.addWidget(ai_group)
        
        # AI Settings
        settings_group = QGroupBox("AI Analysis Settings")
        settings_layout = QFormLayout(settings_group)
        
        self.ai_enabled = QCheckBox()
        self.ai_enabled.setChecked(getattr(self.config.config.api, 'ai_analysis_enabled', True))
        settings_layout.addRow("Enable AI Analysis:", self.ai_enabled)
        
        self.ai_auto_analyze = QCheckBox()
        self.ai_auto_analyze.setChecked(getattr(self.config.config.api, 'ai_auto_analyze', False))
        settings_layout.addRow("Auto-analyze detections:", self.ai_auto_analyze)
        
        self.ai_preferred = QComboBox()
        self.ai_preferred.addItems(['deepseek', 'openai', 'gemini'])
        self.ai_preferred.setCurrentText(getattr(self.config.config.api, 'ai_preferred_provider', 'deepseek'))
        settings_layout.addRow("Preferred Provider:", self.ai_preferred)
        
        layout.addWidget(settings_group)
        
        # Status
        status_group = QGroupBox("Provider Status")
        status_layout = QVBoxLayout(status_group)
        
        if AI_ANALYSIS_AVAILABLE:
            analyzer = get_ai_analyzer()
            providers = analyzer.get_configured_providers()
            if providers:
                status_text = "Configured providers: " + ", ".join(p.value.title() for p in providers)
                status_label = QLabel(status_text)
                status_label.setStyleSheet(f"color: {CYBER_COLORS['primary']};")
            else:
                status_label = QLabel("No AI providers configured. Add API keys above.")
                status_label.setStyleSheet(f"color: {CYBER_COLORS['high']};")
        else:
            status_label = QLabel("AI analysis module not available.")
            status_label.setStyleSheet(f"color: {CYBER_COLORS['critical']};")
        
        status_layout.addWidget(status_label)
        layout.addWidget(status_group)
        
        # Security info
        secure_storage = get_secure_storage()
        storage_type = secure_storage.get_storage_type()
        info_label = QLabel(
            f"🔒 AI API keys are stored securely using:\n{storage_type}\n\n"
            "AI analysis uses LLMs to provide deeper analysis of detections.\n"
            "Deepseek offers cost-effective analysis, OpenAI provides high-quality results,\n"
            "and Gemini integrates with Google's AI capabilities."
        )
        info_label.setStyleSheet(f"color: {CYBER_COLORS['text_muted']};")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        layout.addStretch()
        return widget
    
    def _create_yara_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        yara_manager = get_yara_manager()
        stats = yara_manager.get_rule_stats()
        
        info_group = QGroupBox("Yara Rules Statistics")
        info_layout = QFormLayout(info_group)
        
        self.ruleset_count = QLabel(str(stats.get('total_rulesets', 0)))
        info_layout.addRow("Loaded Rulesets:", self.ruleset_count)
        
        self.rule_count = QLabel(str(stats.get('total_rules', 0)))
        info_layout.addRow("Total Rules:", self.rule_count)
        
        layout.addWidget(info_group)
        
        actions_group = QGroupBox("Actions")
        actions_layout = QHBoxLayout(actions_group)
        
        reload_btn = QPushButton("Reload Rules")
        reload_btn.clicked.connect(self._reload_yara_rules)
        actions_layout.addWidget(reload_btn)
        
        open_dir_btn = QPushButton("Open Rules Directory")
        open_dir_btn.clicked.connect(self._open_yara_dir)
        actions_layout.addWidget(open_dir_btn)
        
        actions_layout.addStretch()
        layout.addWidget(actions_group)
        
        auto_group = QGroupBox("Auto-Update")
        auto_layout = QVBoxLayout(auto_group)
        
        self.auto_update_rules = QCheckBox("Automatically update Yara rules")
        self.auto_update_rules.setChecked(self.config.config.auto_update_rules)
        auto_layout.addWidget(self.auto_update_rules)
        
        layout.addWidget(auto_group)
        layout.addStretch()
        return widget
    
    def _reload_yara_rules(self):
        yara_manager = get_yara_manager()
        yara_manager.load_rules(force_reload=True)
        stats = yara_manager.get_rule_stats()
        self.ruleset_count.setText(str(stats.get('total_rulesets', 0)))
        self.rule_count.setText(str(stats.get('total_rules', 0)))
        QMessageBox.information(self, "Rules Reloaded", 
            f"Successfully reloaded {stats.get('total_rules', 0)} Yara rules.")
    
    def _open_yara_dir(self):
        from utils.config import YARA_RULES_DIR
        subprocess.Popen(f'explorer "{YARA_RULES_DIR}"')
    
    def save_settings(self):
        """Save all settings to configuration."""
        # General settings
        self.config.set('ui.theme', self.theme_combo.currentText())
        self.config.set('ui.font_size', self.font_size.value())
        self.config.set('ui.show_popup_alerts', self.show_popups.isChecked())
        self.config.set('ui.sound_alerts', self.sound_alerts.isChecked())
        self.config.set('log_level', self.log_level.currentText())
        self.config.set('max_scan_threads', self.max_threads.value())
        self.config.set('scan_timeout_seconds', self.scan_timeout.value())
        
        # Scan settings
        self.config.set('scan.process_scan_memory', self.scan_process_memory.isChecked())
        self.config.set('scan.process_scan_behavior', self.scan_process_behavior.isChecked())
        self.config.set('scan.process_scan_hashes', self.scan_process_hashes.isChecked())
        self.config.set('scan.process_scan_signatures', self.scan_process_signatures.isChecked())
        
        self.config.set('scan.file_scan_yara', self.scan_file_yara.isChecked())
        self.config.set('scan.file_scan_entropy', self.scan_file_entropy.isChecked())
        self.config.set('scan.file_scan_pe', self.scan_file_pe.isChecked())
        self.config.set('scan.file_scan_stego', self.scan_file_stego.isChecked())
        self.config.set('scan.file_scan_hashes', self.scan_file_hashes.isChecked())
        
        self.config.set('scan.network_resolve_dns', self.scan_network_dns.isChecked())
        self.config.set('scan.network_threat_lookup', self.scan_network_threat.isChecked())
        self.config.set('scan.network_detect_beaconing', self.scan_network_beacon.isChecked())
        
        # Save cache TTL to config
        self.config.set('api.cache_ttl_hours', self.cache_ttl.value())
        
        # Save API keys to secure storage
        secure_storage = get_secure_storage()
        
        # Threat Intelligence API keys
        secure_storage.save_api_key('virustotal_api_key', self.vt_api_key.text())
        secure_storage.save_api_key('abuseipdb_api_key', self.abuseipdb_api_key.text())
        secure_storage.save_api_key('alienvault_api_key', self.alienvault_api_key.text())
        
        # AI Provider API keys
        secure_storage.save_api_key('deepseek_api_key', self.deepseek_api_key.text())
        secure_storage.save_api_key('openai_api_key', self.openai_api_key.text())
        secure_storage.save_api_key('gemini_api_key', self.gemini_api_key.text())
        
        # AI settings (non-sensitive, save to config)
        self.config.set('api.ai_analysis_enabled', self.ai_enabled.isChecked())
        self.config.set('api.ai_auto_analyze', self.ai_auto_analyze.isChecked())
        self.config.set('api.ai_preferred_provider', self.ai_preferred.currentText())
        
        # Auto-update
        self.config.set('auto_update_rules', self.auto_update_rules.isChecked())
        
        # Save config to file
        self.config.save()
        
        # Apply log level change immediately
        from utils.logging_utils import set_log_level
        set_log_level(self.log_level.currentText())
        
        # Update AI analyzer with new keys
        if AI_ANALYSIS_AVAILABLE:
            from ai_analysis.analyzer import reset_analyzer
            reset_analyzer()
        
        QMessageBox.information(self, "Settings Saved", 
            "Settings have been saved successfully.\n\nAPI keys are stored securely using Windows Credential Manager.\nSome changes may require a restart.")
    
    def reset_settings(self):
        """Reset settings to defaults."""
        reply = QMessageBox.question(self, "Reset Settings",
            "Are you sure you want to reset all settings to defaults?",
            QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.theme_combo.setCurrentText('cyber_dark')
            self.font_size.setValue(10)
            self.show_popups.setChecked(True)
            self.sound_alerts.setChecked(False)
            self.log_level.setCurrentText('INFO')
            self.max_threads.setValue(4)
            self.scan_timeout.setValue(300)
            
            self.scan_process_memory.setChecked(True)
            self.scan_process_behavior.setChecked(True)
            self.scan_process_hashes.setChecked(True)
            self.scan_process_signatures.setChecked(True)
            
            self.scan_file_yara.setChecked(True)
            self.scan_file_entropy.setChecked(True)
            self.scan_file_pe.setChecked(True)
            self.scan_file_stego.setChecked(True)
            self.scan_file_hashes.setChecked(True)
            
            self.scan_network_dns.setChecked(True)
            self.scan_network_threat.setChecked(True)
            self.scan_network_beacon.setChecked(True)
            
            self.ai_enabled.setChecked(True)
            self.ai_auto_analyze.setChecked(False)
            self.ai_preferred.setCurrentText('deepseek')


class AddWhitelistDialog(QDialog):
    """Dialog for adding a new whitelist entry."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Whitelist Entry")
        self.setMinimumSize(450, 300)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        form_layout = QFormLayout()
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(['hash', 'path', 'name', 'ip', 'domain', 'signature'])
        self.type_combo.currentTextChanged.connect(self._on_type_changed)
        form_layout.addRow("Entry Type:", self.type_combo)
        
        self.identifier_edit = QLineEdit()
        self.identifier_edit.setPlaceholderText("Enter the value to whitelist")
        form_layout.addRow("Identifier:", self.identifier_edit)
        
        self.description_edit = QLineEdit()
        self.description_edit.setPlaceholderText("Optional description")
        form_layout.addRow("Description:", self.description_edit)
        
        layout.addLayout(form_layout)
        
        self.hint_label = QLabel()
        self.hint_label.setStyleSheet(f"color: {CYBER_COLORS['text_muted']}; font-style: italic;")
        self.hint_label.setWordWrap(True)
        layout.addWidget(self.hint_label)
        self._on_type_changed('hash')
        
        layout.addStretch()
        
        button_layout = QHBoxLayout()
        
        add_btn = QPushButton("Add Entry")
        add_btn.clicked.connect(self.accept)
        button_layout.addWidget(add_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
    
    def _on_type_changed(self, entry_type: str):
        hints = {
            'hash': 'Enter SHA256, MD5, or SHA1 hash of the file to whitelist.',
            'path': 'Enter full file path (e.g., C:\\Program Files\\MyApp\\app.exe)',
            'name': 'Enter process or file name (e.g., myapp.exe)',
            'ip': 'Enter IP address or CIDR range (e.g., 192.168.1.0/24)',
            'domain': 'Enter domain name (e.g., example.com)',
            'signature': 'Enter digital signature publisher name (e.g., Microsoft Corporation)',
        }
        self.hint_label.setText(hints.get(entry_type, ''))
    
    def get_entry_data(self) -> Dict[str, str]:
        return {
            'entry_type': self.type_combo.currentText(),
            'identifier': self.identifier_edit.text().strip(),
            'description': self.description_edit.text().strip() or f"User added {self.type_combo.currentText()} entry"
        }


class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self):
        super().__init__()
        
        self.is_admin = is_admin()
        
        self.config = get_config()
        self.report_generator = ReportGenerator()
        
        # Initialize Yara rules
        self.yara_manager = get_yara_manager()
        self.yara_manager.load_rules()
        
        # Initialize AI analyzer
        if AI_ANALYSIS_AVAILABLE:
            self.ai_analyzer = get_ai_analyzer()
        else:
            self.ai_analyzer = None
        
        # Scanners
        self.process_scanner = ProcessScanner()
        self.file_scanner = FileScanner()
        self.registry_scanner = RegistryScanner()
        self.network_scanner = NetworkScanner()
        self.realtime_monitor = RealTimeMonitor()
        
        # Workers
        self.current_worker: Optional[ScanWorker] = None
        
        # Results
        self.scan_results: List[ScanResult] = []
        
        # Setup UI
        admin_suffix = " [ADMIN]" if self.is_admin else " [NON-ADMIN]"
        self.setWindowTitle(f"CyberGuardian - Malware & Anomaly Detection Tool{admin_suffix}")
        self.setMinimumSize(1400, 900)
        self.setStyleSheet(CyberStyle.get_stylesheet())
        
        self.setup_ui()
        self.setup_tray()
        self.setup_statusbar()
        
        # Load settings
        self.settings = QSettings('CyberGuardian', 'CyberGuardian')
        self.load_settings()
        
        # Show admin warning if not running as admin
        if not self.is_admin:
            QTimer.singleShot(500, self._show_admin_warning)
    
    def _show_admin_warning(self):
        """Show warning about running without admin privileges."""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Administrator Privileges Required")
        msg.setText("CyberGuardian is not running with administrator privileges.")
        msg.setInformativeText(
            "Some features may be limited:\n"
            "- Cannot scan protected system processes\n"
            "- Cannot scan all registry keys\n"
            "- Cannot terminate elevated processes\n"
            "- Cannot delete protected files\n\n"
            "Would you like to restart as administrator?"
        )
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg.setDefaultButton(QMessageBox.Yes)
        
        if msg.exec_() == QMessageBox.Yes:
            if run_as_admin():
                QApplication.quit()
    
    def setup_ui(self):
        """Setup the main UI components."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        self.setup_header(main_layout)
        self.setup_action_buttons(main_layout)
        self.setup_content_area(main_layout)
    
    def setup_header(self, layout: QVBoxLayout):
        """Setup the header section."""
        header_frame = QFrame()
        header_layout = QHBoxLayout(header_frame)
        
        title_label = QLabel("CYBERGUARDIAN")
        title_label.setObjectName('titleLabel')
        title_label.setFont(QFont('Consolas', 24, QFont.Bold))
        title_label.setStyleSheet(f"color: {CYBER_COLORS['primary']};")
        header_layout.addWidget(title_label)
        
        # Admin mode switch button
        self.admin_btn = QPushButton()
        self.admin_btn.setFont(QFont('Consolas', 10, QFont.Bold))
        self.admin_btn.setMinimumHeight(32)
        self.admin_btn.clicked.connect(self._toggle_admin_mode)
        
        if self.is_admin:
            self.admin_btn.setText(" ADMIN MODE")
            self.admin_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {CYBER_COLORS['primary']};
                    color: {CYBER_COLORS['background']};
                    border: 2px solid {CYBER_COLORS['primary']};
                    border-radius: 6px;
                    padding: 4px 12px;
                }}
                QPushButton:hover {{
                    background-color: #00cc7a;
                    border-color: #00cc7a;
                }}
            """)
            self.admin_btn.setToolTip("Running with Administrator privileges - Click to restart as normal user")
        else:
            self.admin_btn.setText(" RUN AS ADMIN")
            self.admin_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: transparent;
                    color: {CYBER_COLORS['high']};
                    border: 2px solid {CYBER_COLORS['high']};
                    border-radius: 6px;
                    padding: 4px 12px;
                }}
                QPushButton:hover {{
                    background-color: {CYBER_COLORS['high']};
                    color: white;
                }}
            """)
            self.admin_btn.setToolTip("Click to restart with Administrator privileges")
        
        header_layout.addWidget(self.admin_btn)
        header_layout.addStretch()
        
        version_label = QLabel(f"v{self.config.config.version}")
        version_label.setStyleSheet(f"color: {CYBER_COLORS['text_muted']};")
        header_layout.addWidget(version_label)
        
        layout.addWidget(header_frame)
        
        separator = QFrame()
        separator.setObjectName('separator')
        separator.setFrameShape(QFrame.HLine)
        separator.setFixedHeight(2)
        layout.addWidget(separator)
    
    def _toggle_admin_mode(self):
        """Toggle between admin and non-admin mode."""
        if self.is_admin:
            # Already admin - offer to restart as normal user
            reply = QMessageBox.question(
                self, "Switch to User Mode",
                "You are currently running as Administrator.\n\n"
                "Would you like to restart CyberGuardian in normal user mode?\n\n"
                "Note: Some features like scanning protected processes and\n"
                "deleting system files will be limited.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self._restart_as_normal_user()
        else:
            # Not admin - offer to elevate
            reply = QMessageBox.question(
                self, "Run as Administrator",
                "Running as Administrator enables full functionality:\n\n"
                "✓ Scan protected system processes\n"
                "✓ Scan all registry keys\n"
                "✓ Terminate elevated processes\n"
                "✓ Delete protected files\n\n"
                "Would you like to restart CyberGuardian with\n"
                "Administrator privileges?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            
            if reply == QMessageBox.Yes:
                if run_as_admin():
                    self.quit_application()
                else:
                    QMessageBox.critical(
                        self, "Elevation Failed",
                        "Failed to elevate privileges. Please right-click the application\n"
                        "and select 'Run as administrator' manually."
                    )
    
    def _restart_as_normal_user(self):
        """Restart the application as a normal user (non-admin)."""
        try:
            # Use explorer.exe to launch the process without elevation
            # This effectively drops admin privileges
            script = os.path.abspath(sys.argv[0])
            params = ' '.join(sys.argv[1:])
            
            # Use cmd.exe with runas verb to run as invoker (non-elevated)
            # Note: This uses the "runasinvoker" compatibility flag
            import subprocess
            
            # Method: Use explorer to launch (runs as non-elevated user)
            subprocess.Popen(
                f'explorer "{script}"',
                shell=True
            )
            
            self.quit_application()
        except Exception as e:
            logger.error(f"Failed to restart as normal user: {e}")
            QMessageBox.critical(
                self, "Restart Failed",
                f"Could not restart in user mode: {str(e)}\n\n"
                "Please close and restart the application manually."
            )
    
    def setup_action_buttons(self, layout: QVBoxLayout):
        """Setup the main action buttons."""
        buttons_frame = QFrame()
        buttons_layout = QHBoxLayout(buttons_frame)
        buttons_layout.setSpacing(15)
        
        self.process_btn = QPushButton("Process Analysis")
        self.process_btn.setToolTip("Scan running processes for malware")
        self.process_btn.clicked.connect(self.start_process_scan)
        buttons_layout.addWidget(self.process_btn)
        
        self.file_btn = QPushButton("File Analysis")
        self.file_btn.setToolTip("Scan files and folders for threats")
        self.file_btn.clicked.connect(self.start_file_scan)
        buttons_layout.addWidget(self.file_btn)
        
        self.registry_btn = QPushButton("Registry Analysis")
        self.registry_btn.setToolTip("Scan Windows registry for persistence")
        self.registry_btn.clicked.connect(self.start_registry_scan)
        buttons_layout.addWidget(self.registry_btn)
        
        self.network_btn = QPushButton("Network Analysis")
        self.network_btn.setToolTip("Analyze network connections")
        self.network_btn.clicked.connect(self.start_network_scan)
        buttons_layout.addWidget(self.network_btn)
        
        self.realtime_btn = QPushButton("Real-Time Monitor")
        self.realtime_btn.setToolTip("Start real-time threat monitoring")
        self.realtime_btn.clicked.connect(self.toggle_realtime_monitoring)
        buttons_layout.addWidget(self.realtime_btn)
        
        # Stop scan button (initially hidden)
        self.stop_btn = QPushButton(" STOP SCAN")
        self.stop_btn.setObjectName("dangerButton")
        self.stop_btn.setToolTip("Cancel the current scan")
        self.stop_btn.clicked.connect(self.stop_current_scan)
        self.stop_btn.setVisible(False)
        self.stop_btn.setMinimumHeight(45)
        self.stop_btn.setFont(QFont('Consolas', 12, QFont.Bold))
        buttons_layout.addWidget(self.stop_btn)
        
        layout.addWidget(buttons_frame)
        
        # Deep Analysis Mode section
        deep_analysis_frame = QFrame()
        deep_analysis_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {CYBER_COLORS['background_card']};
                border: 1px solid {CYBER_COLORS['border']};
                border-radius: 6px;
                padding: 5px;
            }}
        """)
        deep_analysis_layout = QHBoxLayout(deep_analysis_frame)
        deep_analysis_layout.setContentsMargins(15, 8, 15, 8)
        
        # Deep Analysis checkbox
        self.deep_analysis_checkbox = QCheckBox("Deep Analysis Mode")
        self.deep_analysis_checkbox.setChecked(False)
        
        # Set tooltip based on admin status
        if self.is_admin:
            self.deep_analysis_checkbox.setToolTip(
                "Enable comprehensive forensic analysis during scans:\n\n"
                "• Windows Event Log analysis (Security, System, PowerShell)\n"
                "• Process memory and loaded modules inspection\n"
                "• Registry persistence artifacts collection\n"
                "• Network forensics (DNS cache, hosts file)\n"
                "• File system artifacts (Alternate Data Streams, Prefetch)\n\n"
                "Provides more detailed results but scans will take longer.\n"
                "Recommended for in-depth security investigations."
            )
            self.deep_analysis_checkbox.setStyleSheet(f"""
                QCheckBox {{
                    color: {CYBER_COLORS['primary']};
                    font-size: 14px;
                    font-weight: bold;
                    spacing: 10px;
                }}
                QCheckBox::indicator {{
                    width: 22px;
                    height: 22px;
                    border-radius: 4px;
                }}
                QCheckBox::indicator:unchecked {{
                    border: 2px solid {CYBER_COLORS['border']};
                    background: {CYBER_COLORS['background_secondary']};
                }}
                QCheckBox::indicator:unchecked:hover {{
                    border: 2px solid {CYBER_COLORS['secondary']};
                }}
                QCheckBox::indicator:checked {{
                    border: 2px solid {CYBER_COLORS['primary']};
                    background: {CYBER_COLORS['primary']};
                }}
            """)
        else:
            # Disable checkbox if not admin
            self.deep_analysis_checkbox.setEnabled(False)
            self.deep_analysis_checkbox.setToolTip(
                "⚠ REQUIRES ADMINISTRATOR PRIVILEGES\n\n"
                "Deep Analysis Mode requires Administrator access to:\n"
                "• Read Windows Event Logs\n"
                "• Access protected registry keys\n"
                "• Inspect system processes\n\n"
                "Please restart the application as Administrator\n"
                "to enable this feature."
            )
            self.deep_analysis_checkbox.setStyleSheet(f"""
                QCheckBox {{
                    color: {CYBER_COLORS['text_muted']};
                    font-size: 14px;
                    font-weight: bold;
                    spacing: 10px;
                }}
                QCheckBox::indicator {{
                    width: 22px;
                    height: 22px;
                    border-radius: 4px;
                }}
                QCheckBox::indicator:unchecked {{
                    border: 2px solid {CYBER_COLORS['border']};
                    background: {CYBER_COLORS['background_secondary']};
                }}
            """)
        
        deep_analysis_layout.addWidget(self.deep_analysis_checkbox)
        
        # Deep analysis info label
        if self.is_admin:
            deep_info_label = QLabel("Enhanced forensic scanning with Windows artifacts")
            deep_info_label.setStyleSheet(f"color: {CYBER_COLORS['text_muted']}; font-size: 12px;")
        else:
            deep_info_label = QLabel("🔒 Requires Administrator privileges")
            deep_info_label.setStyleSheet(f"color: {CYBER_COLORS['high']}; font-size: 12px; font-weight: bold;")
        deep_analysis_layout.addWidget(deep_info_label)
        
        # VirusTotal note
        vt_available = VIRUSTOTAL_AVAILABLE and is_virustotal_available()
        if vt_available:
            vt_note = QLabel("✓ VirusTotal API key configured")
            vt_note.setStyleSheet(f"color: {CYBER_COLORS['low']}; font-size: 11px; margin-left: 10px;")
        else:
            vt_note = QLabel("⚠ Add VirusTotal API key in Settings for IOC checking")
            vt_note.setStyleSheet(f"color: {CYBER_COLORS['medium']}; font-size: 11px; margin-left: 10px;")
        deep_analysis_layout.addWidget(vt_note)
        
        # VT Analysis Depth selector
        if vt_available:
            depth_label = QLabel("VT Depth:")
            depth_label.setStyleSheet(f"color: {CYBER_COLORS['text_muted']}; font-size: 11px; margin-left: 15px;")
            deep_analysis_layout.addWidget(depth_label)
            
            self.vt_depth_combo = QComboBox()
            self.vt_depth_combo.addItems(['Standard', 'Deep', 'Full'])
            self.vt_depth_combo.setCurrentIndex(0)  # Default to Standard
            self.vt_depth_combo.setToolTip(
                "VirusTotal Analysis Depth:\n\n"
                "Standard: Hashes, IPs, Domains, URLs (~3-5 min)\n"
                "Deep: + Relations data (contacted hosts, dropped files)\n"
                "Full: + Community data + Secondary IOC discovery"
            )
            self.vt_depth_combo.setStyleSheet(f"""
                QComboBox {{
                    background-color: {CYBER_COLORS['background_secondary']};
                    color: {CYBER_COLORS['text']};
                    border: 1px solid {CYBER_COLORS['border']};
                    border-radius: 4px;
                    padding: 3px 8px;
                    font-size: 11px;
                    min-width: 80px;
                }}
                QComboBox::drop-down {{
                    border: none;
                }}
                QComboBox QAbstractItemView {{
                    background-color: {CYBER_COLORS['background_card']};
                    color: {CYBER_COLORS['text']};
                    selection-background-color: {CYBER_COLORS['primary']};
                }}
            """)
            deep_analysis_layout.addWidget(self.vt_depth_combo)
        
        deep_analysis_layout.addStretch()
        
        # Estimated time label
        if self.is_admin:
            self.deep_time_label = QLabel("Standard scan time")
            self.deep_time_label.setStyleSheet(f"color: {CYBER_COLORS['secondary']}; font-size: 11px;")
        else:
            self.deep_time_label = QLabel("Disabled - Run as Admin")
            self.deep_time_label.setStyleSheet(f"color: {CYBER_COLORS['high']}; font-size: 11px;")
        deep_analysis_layout.addWidget(self.deep_time_label)
        
        # Connect checkbox to update time estimate (only if enabled)
        if self.is_admin:
            self.deep_analysis_checkbox.stateChanged.connect(self._update_deep_analysis_status)
        
        layout.addWidget(deep_analysis_frame)
    
    def setup_content_area(self, layout: QVBoxLayout):
        """Setup the main content area with tabs."""
        self.tabs = QTabWidget()
        
        self.overview_tab = self.create_overview_tab()
        self.tabs.addTab(self.overview_tab, "Overview")
        
        self.detections_tab = self.create_detections_tab()
        self.tabs.addTab(self.detections_tab, "Detections")
        
        self.logs_tab = self.create_logs_tab()
        self.tabs.addTab(self.logs_tab, "Logs")
        
        self.whitelist_tab = self.create_whitelist_tab()
        self.tabs.addTab(self.whitelist_tab, "Whitelist")
        
        layout.addWidget(self.tabs)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)
    
    def create_overview_tab(self) -> QWidget:
        """Create the overview tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        summary_layout = QHBoxLayout()
        
        self.total_scanned = self.create_summary_card("Total Scanned", "0", CYBER_COLORS['secondary'])
        self.clean_count = self.create_summary_card("Clean", "0", CYBER_COLORS['low'])
        self.suspicious_count = self.create_summary_card("Suspicious", "0", CYBER_COLORS['medium'])
        self.malicious_count = self.create_summary_card("Malicious", "0", CYBER_COLORS['critical'])
        
        summary_layout.addWidget(self.total_scanned)
        summary_layout.addWidget(self.clean_count)
        summary_layout.addWidget(self.suspicious_count)
        summary_layout.addWidget(self.malicious_count)
        
        layout.addLayout(summary_layout)
        
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout(activity_group)
        
        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setMaximumHeight(200)
        activity_layout.addWidget(self.activity_log)
        
        layout.addWidget(activity_group)
        
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout(actions_group)
        
        export_btn = QPushButton("Export Report")
        export_btn.clicked.connect(self.export_report)
        actions_layout.addWidget(export_btn)
        
        clear_btn = QPushButton("Clear Results")
        clear_btn.clicked.connect(self.clear_results)
        actions_layout.addWidget(clear_btn)
        
        settings_btn = QPushButton("Settings")
        settings_btn.clicked.connect(self.open_settings)
        actions_layout.addWidget(settings_btn)
        
        help_btn = QPushButton("Help")
        help_btn.clicked.connect(self.show_help)
        actions_layout.addWidget(help_btn)
        
        layout.addWidget(actions_group)
        layout.addStretch()
        
        return widget
    
    def create_summary_card(self, title: str, value: str, color: str) -> QFrame:
        """Create a summary card widget."""
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: {CYBER_COLORS['background_card']};
                border: 1px solid {CYBER_COLORS['border']};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        
        layout = QVBoxLayout(frame)
        
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {CYBER_COLORS['text_muted']}; font-size: 12px;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        value_label = QLabel(value)
        value_label.setObjectName('valueLabel')
        value_label.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")
        value_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(value_label)
        
        return frame
    
    def create_detections_tab(self) -> QWidget:
        """Create the detections tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        filter_layout = QHBoxLayout()
        
        filter_label = QLabel("Filter by risk:")
        filter_layout.addWidget(filter_label)
        
        self.risk_filter = QComboBox()
        self.risk_filter.addItems(['All', 'Critical', 'High', 'Medium', 'Low', 'Info'])
        filter_layout.addWidget(self.risk_filter)
        
        filter_layout.addStretch()
        
        export_detections = QPushButton("Export Detections")
        export_detections.clicked.connect(self.export_detections)
        filter_layout.addWidget(export_detections)
        
        layout.addLayout(filter_layout)
        
        self.detection_table = DetectionTable()
        self.detection_table.action_requested.connect(self.handle_detection_action)
        
        # Connect the risk filter dropdown to the table's filter method
        self.risk_filter.currentTextChanged.connect(self.detection_table.filter_by_risk)
        
        layout.addWidget(self.detection_table)
        
        return widget
    
    def create_logs_tab(self) -> QWidget:
        """Create the logs tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: #000;
                color: {CYBER_COLORS['primary']};
                font-family: 'Consolas', monospace;
                font-size: 12px;
            }}
        """)
        layout.addWidget(self.log_text)
        
        btn_layout = QHBoxLayout()
        
        clear_logs = QPushButton("Clear Logs")
        clear_logs.clicked.connect(lambda: self.log_text.clear())
        btn_layout.addWidget(clear_logs)
        
        save_logs = QPushButton("Save Logs")
        save_logs.clicked.connect(self.save_logs)
        btn_layout.addWidget(save_logs)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        return widget
    
    def create_whitelist_tab(self) -> QWidget:
        """Create the whitelist management tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        info_label = QLabel("Whitelisted items are excluded from detection scans.")
        info_label.setStyleSheet(f"color: {CYBER_COLORS['text_muted']};")
        layout.addWidget(info_label)
        
        self.whitelist_tree = QTreeWidget()
        self.whitelist_tree.setHeaderLabels(['Entry', 'Type', 'Source', 'Description'])
        self.whitelist_tree.setColumnWidth(0, 300)
        self.whitelist_tree.setColumnWidth(1, 80)
        self.whitelist_tree.setColumnWidth(2, 100)
        layout.addWidget(self.whitelist_tree)
        
        btn_layout = QHBoxLayout()
        
        add_btn = QPushButton("Add Entry")
        add_btn.clicked.connect(self.add_whitelist_entry)
        btn_layout.addWidget(add_btn)
        
        remove_btn = QPushButton("Remove Selected")
        remove_btn.clicked.connect(self.remove_whitelist_entry)
        btn_layout.addWidget(remove_btn)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_whitelist)
        btn_layout.addWidget(refresh_btn)
        
        export_btn = QPushButton("Export")
        export_btn.clicked.connect(self.export_whitelist)
        btn_layout.addWidget(export_btn)
        
        import_btn = QPushButton("Import")
        import_btn.clicked.connect(self.import_whitelist)
        btn_layout.addWidget(import_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        self.refresh_whitelist()
        
        return widget
    
    def setup_tray(self):
        """Setup system tray icon."""
        self.tray_icon = QSystemTrayIcon(self)
        
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setPen(QPen(QColor(CYBER_COLORS['primary']), 3))
        painter.setBrush(QColor(CYBER_COLORS['primary']))
        painter.drawEllipse(8, 8, 48, 48)
        painter.end()
        
        self.tray_icon.setIcon(QIcon(pixmap))
        self.tray_icon.setToolTip("CyberGuardian")
        
        tray_menu = QMenu()
        
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        scan_action = QAction("Quick Scan", self)
        scan_action.triggered.connect(self.start_process_scan)
        tray_menu.addAction(scan_action)
        
        tray_menu.addSeparator()
        
        quit_action = QAction("Exit", self)
        quit_action.triggered.connect(self.quit_application)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
    
    def setup_statusbar(self):
        """Setup the status bar."""
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        
        admin_text = "ADMIN" if self.is_admin else "NON-ADMIN"
        admin_color = CYBER_COLORS['primary'] if self.is_admin else CYBER_COLORS['high']
        self.admin_label = QLabel(admin_text)
        self.admin_label.setStyleSheet(f"color: {admin_color}; font-weight: bold; padding: 0 10px;")
        self.statusbar.addPermanentWidget(self.admin_label)
        
        self.status_label = QLabel("Ready")
        self.statusbar.addPermanentWidget(self.status_label)
        
        self.mode_label = QLabel("Mode: Manual")
        self.statusbar.addPermanentWidget(self.mode_label)
    
    def load_settings(self):
        """Load application settings."""
        geometry = self.settings.value('geometry')
        if geometry:
            self.restoreGeometry(geometry)
    
    def save_settings(self):
        """Save application settings."""
        self.settings.setValue('geometry', self.saveGeometry())
    
    def start_process_scan(self):
        """Start process scan with deep analysis support."""
        deep_analysis = self.deep_analysis_checkbox.isChecked() and self.is_admin
        self.start_scan(self.process_scanner, "Process Analysis", deep_analysis=deep_analysis)
    
    def start_file_scan(self):
        """Start file scan with deep analysis support."""
        deep_analysis = self.deep_analysis_checkbox.isChecked() and self.is_admin
        
        folder = QFileDialog.getExistingDirectory(
            self, "Select Folder to Scan", "",
            QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks
        )
        
        if folder:
            self.start_scan(self.file_scanner, "File Analysis", folder, deep_analysis=deep_analysis)
        else:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Select File to Scan", "",
                "All Files (*.*)"
            )
            if file_path:
                self.start_scan(self.file_scanner, "File Analysis", file_path, deep_analysis=deep_analysis)
    
    def start_registry_scan(self):
        """Start registry scan with deep analysis support."""
        deep_analysis = self.deep_analysis_checkbox.isChecked() and self.is_admin
        self.start_scan(self.registry_scanner, "Registry Analysis", deep_analysis=deep_analysis)
    
    def start_network_scan(self):
        """Start network scan with deep analysis support."""
        deep_analysis = self.deep_analysis_checkbox.isChecked() and self.is_admin
        self.start_scan(self.network_scanner, "Network Analysis", deep_analysis=deep_analysis)
    
    def start_scan(self, scanner, scan_name: str, target=None, deep_analysis=False):
        """Start a scan in background thread.
        
        Args:
            scanner: The scanner instance to use
            scan_name: Human-readable name for the scan
            target: Optional target (file path, IP, etc.)
            deep_analysis: Enable deep/forensic analysis mode
        """
        self.set_ui_busy(True)
        self._current_scan_name = scan_name
        self.status_label.setText(f"Running {scan_name}{' (Deep Analysis)' if deep_analysis else ''}...")
        
        # Show stop button
        self.stop_btn.setVisible(True)
        
        if deep_analysis:
            self.log(f"Starting {scan_name} with Deep Analysis mode...")
        else:
            self.log(f"Starting {scan_name}...")
        
        self.current_worker = ScanWorker(scanner, target, deep_analysis=deep_analysis)
        self.current_worker.progress.connect(self.on_scan_progress)
        self.current_worker.detection.connect(self.on_detection)
        self.current_worker.finished.connect(self.on_scan_finished)
        self.current_worker.error.connect(self.on_scan_error)
        self.current_worker.cancelled.connect(self.on_scan_cancelled)
        self.current_worker.start()
    
    def _update_deep_analysis_status(self, state):
        """Update the deep analysis status label when checkbox is toggled."""
        if not self.is_admin:
            return  # Should not happen, but safety check
        
        if state:
            self.deep_analysis_checkbox.setText("Deep Analysis Mode ✓")
            self.deep_time_label.setText("⚠ Extended scan time (30-60s additional)")
            self.deep_time_label.setStyleSheet(f"color: {CYBER_COLORS['medium']}; font-size: 11px; font-weight: bold;")
            self.log("Deep Analysis mode enabled - scans will include forensic artifact collection")
        else:
            self.deep_analysis_checkbox.setText("Deep Analysis Mode")
            self.deep_time_label.setText("Standard scan time")
            self.deep_time_label.setStyleSheet(f"color: {CYBER_COLORS['secondary']}; font-size: 11px;")
            self.log("Deep Analysis mode disabled - standard scanning mode")
    
    def stop_current_scan(self):
        """Stop the current scan."""
        if self.current_worker and self.current_worker.isRunning():
            reply = QMessageBox.question(
                self, "Stop Scan",
                f"Are you sure you want to stop the current {getattr(self, '_current_scan_name', 'scan')}?\n\n"
                f"Any detections found so far will be preserved.",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.log("Stopping scan...")
                self.status_label.setText("Stopping scan...")
                self.current_worker.cancel_scan()
    
    def on_scan_cancelled(self):
        """Handle scan cancellation."""
        self.log("Scan was cancelled by user")
        self.status_label.setText("Scan cancelled")
        self.add_activity(f"{getattr(self, '_current_scan_name', 'Scan')} was cancelled")
    
    def toggle_realtime_monitoring(self):
        """Toggle real-time monitoring."""
        if self.realtime_monitor.is_running():
            try:
                self.realtime_monitor.stop()
                self.realtime_btn.setText("Real-Time Monitor")
                self.realtime_btn.setStyleSheet("")
                self.mode_label.setText("Mode: Manual")
                self.log("Real-time monitoring stopped")
            except Exception as e:
                logger.error(f"Error stopping real-time monitor: {e}")
                QMessageBox.warning(self, "Error", f"Failed to stop monitoring: {str(e)}")
        else:
            try:
                self.realtime_monitor.set_detection_callback(self.on_realtime_detection)
                success = self.realtime_monitor.start()
                
                if success:
                    self.realtime_btn.setText("Stop Monitor")
                    self.realtime_btn.setStyleSheet(f"""
                        QPushButton {{
                            background-color: {CYBER_COLORS['critical']};
                            color: white;
                            border-color: {CYBER_COLORS['critical']};
                        }}
                        QPushButton:hover {{
                            background-color: #ff2040;
                        }}
                    """)
                    self.mode_label.setText("Mode: Real-Time")
                    self.log("Real-time monitoring started")
                    # Don't hide the window automatically - let user minimize if desired
                    # self.hide()
                    # self.tray_icon.show()
                else:
                    QMessageBox.warning(self, "Error", "Failed to start real-time monitoring.")
            except Exception as e:
                logger.error(f"Error starting real-time monitor: {e}")
                import traceback
                traceback.print_exc()
                QMessageBox.critical(self, "Error", f"Failed to start monitoring: {str(e)}")
    
    def on_realtime_detection(self, detection: Detection):
        """Handle real-time detection."""
        QTimer.singleShot(0, lambda: self._handle_realtime_detection(detection))
    
    def _handle_realtime_detection(self, detection: Detection):
        """Handle real-time detection in main thread."""
        try:
            # Show tray notification if tray icon is visible
            if self.tray_icon.isVisible():
                self.tray_icon.showMessage(
                    f"Threat Detected: {detection.risk_level.value.upper()}",
                    detection.description[:100],
                    QSystemTrayIcon.Warning,
                    10000
                )
            
            # Add to detection table
            self.detection_table.add_detection(detection)
            self.update_summary()
            self.log(f"DETECTION: {detection.detection_type} - {detection.indicator}")
        except Exception as e:
            logger.error(f"Error handling real-time detection: {e}")
    
    def on_scan_progress(self, current: int, total: int, message: str):
        """Handle scan progress update."""
        self.progress_bar.setVisible(True)
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.progress_bar.setFormat(f"{message} ({current}/{total})")
    
    def on_detection(self, detection: Detection):
        """Handle detection during scan."""
        self.detection_table.add_detection(detection)
        self.log(f"Found: {detection.detection_type} - {detection.indicator[:50]}")
    
    def on_scan_finished(self, result: ScanResult):
        """Handle scan completion."""
        self.scan_results.append(result)
        self.set_ui_busy(False)
        self.progress_bar.setVisible(False)
        self.stop_btn.setVisible(False)
        
        # Count all detections (including LOW risk)
        total_detections = len(result.detections)
        
        # Count by risk level for detailed message
        critical_count = sum(1 for d in result.detections if d.risk_level == RiskLevel.CRITICAL)
        high_count = sum(1 for d in result.detections if d.risk_level == RiskLevel.HIGH)
        medium_count = sum(1 for d in result.detections if d.risk_level == RiskLevel.MEDIUM)
        low_count = sum(1 for d in result.detections if d.risk_level == RiskLevel.LOW)
        
        # Build summary message
        risk_summary = []
        if critical_count > 0:
            risk_summary.append(f"{critical_count} Critical")
        if high_count > 0:
            risk_summary.append(f"{high_count} High")
        if medium_count > 0:
            risk_summary.append(f"{medium_count} Medium")
        if low_count > 0:
            risk_summary.append(f"{low_count} Low")
        
        risk_summary_str = ", ".join(risk_summary) if risk_summary else "0"
        
        # Check if scan was cancelled
        if result.status == ScanStatus.CANCELLED:
            self.status_label.setText(f"Scan cancelled: {total_detections} detections found")
            self.log(f"Scan cancelled. Found {total_detections} detections before cancellation ({risk_summary_str}).")
            self.add_activity(f"{result.scan_type.title()} scan cancelled: {total_detections} detections found")
        else:
            self.status_label.setText(f"Scan completed: {total_detections} detections")
            self.log(f"Scan completed. Found {total_detections} detections ({risk_summary_str}).")
            self.add_activity(f"{result.scan_type.title()} scan completed: {total_detections} detections")
        
        self.update_summary()
    
    def on_scan_error(self, error: str):
        """Handle scan error."""
        self.set_ui_busy(False)
        self.progress_bar.setVisible(False)
        self.stop_btn.setVisible(False)
        
        self.status_label.setText(f"Scan failed")
        self.log(f"ERROR: {error}")
        
        QMessageBox.critical(self, "Scan Error", f"Scan failed: {error}")
    
    def set_ui_busy(self, busy: bool):
        """Set UI busy state."""
        buttons = [
            self.process_btn, self.file_btn, self.registry_btn,
            self.network_btn, self.realtime_btn
        ]
        
        for btn in buttons:
            btn.setEnabled(not busy)
        
        # Show/hide stop button based on busy state
        self.stop_btn.setVisible(busy)
    
    def update_summary(self):
        """Update summary cards."""
        total = sum(r.total_items for r in self.scan_results)
        clean = sum(r.clean_items for r in self.scan_results)
        suspicious = sum(r.suspicious_items for r in self.scan_results)
        malicious = sum(r.malicious_items for r in self.scan_results)
        
        self.total_scanned.findChild(QLabel, 'valueLabel').setText(str(total))
        self.clean_count.findChild(QLabel, 'valueLabel').setText(str(clean))
        self.suspicious_count.findChild(QLabel, 'valueLabel').setText(str(suspicious))
        self.malicious_count.findChild(QLabel, 'valueLabel').setText(str(malicious))
    
    def add_activity(self, message: str):
        """Add activity to the log."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.activity_log.append(f"[{timestamp}] {message}")
    
    def log(self, message: str):
        """Add message to log."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.log_text.append(f"[{timestamp}] {message}")
    
    def on_tray_activated(self, reason):
        """Handle tray icon activation."""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.tray_icon.hide()
    
    def handle_detection_action(self, action: str, detection: Detection):
        """Handle actions from detection dialog."""
        try:
            if action == "kill_process":
                self._kill_process(detection)
            elif action == "suspend_process":
                self._suspend_process(detection)
            elif action == "delete_file":
                self._delete_file(detection)
            elif action == "quarantine_file":
                self._quarantine_file(detection)
            elif action == "add_whitelist":
                self._add_to_whitelist(detection)
            elif action == "remove_whitelist":
                self._remove_from_whitelist(detection)
            elif action == "open_location":
                self._open_file_location(detection)
        except Exception as e:
            QMessageBox.critical(self, "Action Failed", f"Failed to perform action: {str(e)}")
    
    def _kill_process(self, detection: Detection):
        """Kill the process associated with detection."""
        if not detection.process_id:
            QMessageBox.warning(self, "No Process", "No process ID associated with this detection.")
            return
        
        reply = QMessageBox.question(
            self, "Confirm Kill Process",
            f"Are you sure you want to terminate process {detection.process_name} (PID: {detection.process_id})?\n\n"
            f"This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                import psutil
                process = psutil.Process(detection.process_id)
                process.kill()
                self.log(f"Killed process: {detection.process_name} (PID: {detection.process_id})")
                QMessageBox.information(self, "Success", f"Process {detection.process_name} has been terminated.")
            except psutil.NoSuchProcess:
                QMessageBox.warning(self, "Process Not Found", "The process is no longer running.")
            except psutil.AccessDenied:
                QMessageBox.critical(self, "Access Denied", 
                    "Cannot kill process. Run CyberGuardian as administrator.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to kill process: {str(e)}")
    
    def _suspend_process(self, detection: Detection):
        """Suspend the process associated with detection."""
        if not detection.process_id:
            QMessageBox.warning(self, "No Process", "No process ID associated with this detection.")
            return
        
        try:
            import psutil
            process = psutil.Process(detection.process_id)
            process.suspend()
            self.log(f"Suspended process: {detection.process_name} (PID: {detection.process_id})")
            QMessageBox.information(self, "Success", f"Process {detection.process_name} has been suspended.")
        except psutil.NoSuchProcess:
            QMessageBox.warning(self, "Process Not Found", "The process is no longer running.")
        except psutil.AccessDenied:
            QMessageBox.critical(self, "Access Denied", 
                "Cannot suspend process. Run CyberGuardian as administrator.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to suspend process: {str(e)}")
    
    def _delete_file(self, detection: Detection):
        """Delete the file associated with detection."""
        if not detection.file_path:
            QMessageBox.warning(self, "No File", "No file path associated with this detection.")
            return
        
        reply = QMessageBox.question(
            self, "Confirm Delete File",
            f"Are you sure you want to DELETE this file?\n\n{detection.file_path}\n\n"
            f"This action cannot be undone!",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                os.remove(detection.file_path)
                self.log(f"Deleted file: {detection.file_path}")
                QMessageBox.information(self, "Success", "File has been deleted.")
            except PermissionError:
                QMessageBox.critical(self, "Access Denied", 
                    "Cannot delete file. Run CyberGuardian as administrator.")
            except FileNotFoundError:
                QMessageBox.warning(self, "File Not Found", "The file no longer exists.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete file: {str(e)}")
    
    def _quarantine_file(self, detection: Detection):
        """Move file to quarantine."""
        if not detection.file_path:
            QMessageBox.warning(self, "No File", "No file path associated with this detection.")
            return
        
        quarantine_dir = Path(APP_DIR) / "quarantine"
        quarantine_dir.mkdir(exist_ok=True)
        
        source_path = Path(detection.file_path)
        dest_path = quarantine_dir / f"{source_path.name}.quarantine"
        
        try:
            import shutil
            shutil.move(str(source_path), str(dest_path))
            self.log(f"Quarantined file: {detection.file_path} -> {dest_path}")
            QMessageBox.information(self, "Success", f"File has been quarantined to:\n{dest_path}")
        except PermissionError:
            QMessageBox.critical(self, "Access Denied", 
                "Cannot quarantine file. Run CyberGuardian as administrator.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to quarantine file: {str(e)}")
    
    def _add_to_whitelist(self, detection: Detection):
        """Add detection indicator to whitelist."""
        whitelist = get_whitelist()
        
        identifier = None
        entry_type = None
        
        # Check for file path
        if detection.file_path:
            identifier = detection.file_path
            entry_type = 'path'
        # Check for process name
        elif detection.process_name:
            identifier = detection.process_name
            entry_type = 'name'
        # Check for registry key (from indicator_type or detection type)
        elif detection.indicator_type == 'registry_key' or 'registry' in detection.detection_type.lower():
            # Get registry key from indicator or evidence
            key_path = detection.indicator
            if detection.evidence:
                key_path = detection.evidence.get('key_path', key_path) or key_path
            if key_path:
                identifier = key_path
                entry_type = 'registry_key'
        # Fallback to indicator if it looks like a valid identifier
        elif detection.indicator:
            identifier = detection.indicator
            # Try to determine type from indicator
            if identifier.startswith(('HKEY_', 'HKLM', 'HKCU', 'HKCR', 'HKU', 'HKCC')):
                entry_type = 'registry_key'
            elif identifier.startswith(('http://', 'https://')):
                entry_type = 'domain'
            elif '\\' in identifier or '/' in identifier:
                entry_type = 'path'
            else:
                entry_type = 'name'
        
        if identifier and entry_type:
            reply = QMessageBox.question(
                self, "Add to Whitelist",
                f"Add the following to whitelist?\n\nType: {entry_type}\nIdentifier: {identifier[:100]}{'...' if len(identifier) > 100 else ''}",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                whitelist.add_entry(
                    identifier=identifier,
                    entry_type=entry_type,
                    source='user',
                    description=f"Added from detection: {detection.detection_type}"
                )
                self.log(f"Added to whitelist: {entry_type}={identifier[:50]}")
                QMessageBox.information(self, "Success", "Entry added to whitelist.")
                self.refresh_whitelist()
                
                # Store the identifier on the detection for later removal
                detection._whitelist_identifier = identifier
                detection._whitelist_entry_type = entry_type
                
                # Notify any open dialogs to update their buttons
                self._notify_whitelist_change(detection, True)
        else:
            QMessageBox.warning(self, "Cannot Add", 
                f"No suitable identifier found for whitelisting.\n\n"
                f"Detection type: {detection.detection_type}\n"
                f"Indicator: {detection.indicator[:50] if detection.indicator else 'N/A'}")
    
    def _remove_from_whitelist(self, detection: Detection):
        """Remove detection indicator from whitelist."""
        whitelist = get_whitelist()
        
        identifier = getattr(detection, '_whitelist_identifier', None)
        entry_type = getattr(detection, '_whitelist_entry_type', None)
        
        # If not stored, try to determine it again
        if not identifier:
            # Check for file path
            if detection.file_path:
                identifier = detection.file_path
                entry_type = 'path'
            elif detection.process_name:
                identifier = detection.process_name
                entry_type = 'name'
            elif detection.indicator_type == 'registry_key' or 'registry' in detection.detection_type.lower():
                key_path = detection.indicator
                if detection.evidence:
                    key_path = detection.evidence.get('key_path', key_path) or key_path
                if key_path:
                    identifier = key_path
                    entry_type = 'registry_key'
            elif detection.indicator:
                identifier = detection.indicator
                if identifier.startswith(('HKEY_', 'HKLM', 'HKCU', 'HKCR', 'HKU', 'HKCC')):
                    entry_type = 'registry_key'
                elif identifier.startswith(('http://', 'https://')):
                    entry_type = 'domain'
                elif '\\' in identifier or '/' in identifier:
                    entry_type = 'path'
                else:
                    entry_type = 'name'
        
        if identifier:
            reply = QMessageBox.question(
                self, "Remove from Whitelist",
                f"Remove the following from whitelist?\n\nType: {entry_type}\nIdentifier: {identifier[:100]}{'...' if len(identifier) > 100 else ''}",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                whitelist.remove_entry(identifier)
                self.log(f"Removed from whitelist: {entry_type}={identifier[:50]}")
                QMessageBox.information(self, "Success", "Entry removed from whitelist.")
                self.refresh_whitelist()
                
                # Notify any open dialogs to update their buttons
                self._notify_whitelist_change(detection, False)
        else:
            QMessageBox.warning(self, "Cannot Remove", 
                f"No identifier found to remove from whitelist.\n\n"
                f"Detection type: {detection.detection_type}")
    
    def _notify_whitelist_change(self, detection: Detection, is_whitelisted: bool):
        """Notify open dialogs about whitelist change.
        
        Args:
            detection: The detection that was changed
            is_whitelisted: True if now whitelisted, False if removed
        """
        # Find any open DetectionDialogs and update them
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, DetectionDialog):
                if widget.detection.detection_id == detection.detection_id:
                    widget.update_whitelist_button(is_whitelisted)
    
    def _open_file_location(self, detection: Detection):
        """Open file location in explorer."""
        if not detection.file_path:
            QMessageBox.warning(self, "No File", "No file path associated with this detection.")
            return
        
        path = Path(detection.file_path)
        if path.exists():
            subprocess.Popen(f'explorer /select,"{path}"')
        else:
            QMessageBox.warning(self, "File Not Found", "The file no longer exists.")
    
    def open_settings(self):
        """Open settings dialog."""
        dialog = SettingsDialog(self)
        dialog.exec_()
    
    def show_help(self):
        """Show help dialog."""
        help_text = """
CyberGuardian - Malware & Anomaly Detection Tool
================================================

MAIN FEATURES:
- Process Analysis - Scan running processes for malware indicators
- File Analysis - Scan files and folders for threats
- Registry Analysis - Detect persistence mechanisms
- Network Analysis - Identify suspicious network connections
- Real-Time Monitor - Continuous threat monitoring
- AI Analysis - Deep analysis using Deepseek, OpenAI, or Gemini

DETECTION METHODS:
- Yara rules for signature matching
- Behavioral heuristics
- Hash reputation lookup (VirusTotal)
- Digital signature verification
- Entropy analysis for packed files
- PE file analysis
- Steganography detection

AI ANALYSIS:
Configure API keys in Settings > AI Analysis to enable AI-powered
deep analysis of detections. Supported providers:
- Deepseek (cost-effective)
- OpenAI (high-quality results)
- Google Gemini (Google AI capabilities)

ACTIONS:
- Kill/Suspend suspicious processes
- Delete/Quarantine malicious files
- Add items to whitelist
- AI-powered analysis and recommendations

TIPS:
- Run as Administrator for full functionality
- Configure API keys for threat intelligence and AI analysis
- Add custom Yara rules to the yara_rules directory
- Use whitelist to reduce false positives

For more information, see the USER_GUIDE.md file.
        """
        
        msg = QMessageBox(self)
        msg.setWindowTitle("Help - CyberGuardian")
        msg.setText(help_text)
        msg.setTextInteractionFlags(Qt.TextSelectableByMouse)
        msg.exec_()
    
    def add_whitelist_entry(self):
        """Add a new whitelist entry."""
        dialog = AddWhitelistDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_entry_data()
            if data['identifier']:
                whitelist = get_whitelist()
                success = whitelist.add_entry(
                    identifier=data['identifier'],
                    entry_type=data['entry_type'],
                    source='user',
                    description=data['description']
                )
                if success:
                    self.log(f"Added whitelist entry: {data['entry_type']}={data['identifier']}")
                    self.refresh_whitelist()
                    QMessageBox.information(self, "Success", "Whitelist entry added.")
                else:
                    QMessageBox.warning(self, "Duplicate", "Entry already exists in whitelist.")
            else:
                QMessageBox.warning(self, "Invalid", "Please enter an identifier value.")
    
    def remove_whitelist_entry(self):
        """Remove selected whitelist entry."""
        selected = self.whitelist_tree.selectedItems()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select an entry to remove.")
            return
        
        item = selected[0]
        identifier = item.text(0)
        entry_type = item.text(1).lower()
        
        reply = QMessageBox.question(
            self, "Confirm Removal",
            f"Remove this whitelist entry?\n\n{identifier}",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            whitelist = get_whitelist()
            whitelist.remove_entry(identifier, entry_type)
            self.log(f"Removed whitelist entry: {entry_type}={identifier}")
            self.refresh_whitelist()
            QMessageBox.information(self, "Success", "Whitelist entry removed.")
    
    def refresh_whitelist(self):
        """Refresh whitelist display."""
        self.whitelist_tree.clear()
        whitelist = get_whitelist()
        
        for entry in whitelist.get_all_entries():
            item = QTreeWidgetItem([
                entry.identifier[:60],
                entry.entry_type,
                entry.source,
                entry.description[:50] if entry.description else ""
            ])
            self.whitelist_tree.addTopLevelItem(item)
    
    def export_whitelist(self):
        """Export whitelist to file."""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Whitelist", "whitelist.json",
            "JSON Files (*.json)"
        )
        
        if filepath:
            whitelist = get_whitelist()
            if whitelist.export_whitelist(Path(filepath)):
                self.log(f"Exported whitelist to: {filepath}")
                QMessageBox.information(self, "Success", "Whitelist exported successfully.")
            else:
                QMessageBox.critical(self, "Error", "Failed to export whitelist.")
    
    def import_whitelist(self):
        """Import whitelist from file."""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Import Whitelist", "",
            "JSON Files (*.json)"
        )
        
        if filepath:
            whitelist = get_whitelist()
            if whitelist.import_whitelist(Path(filepath)):
                self.log(f"Imported whitelist from: {filepath}")
                self.refresh_whitelist()
                QMessageBox.information(self, "Success", "Whitelist imported successfully.")
            else:
                QMessageBox.critical(self, "Error", "Failed to import whitelist.")
    
    def export_report(self):
        """Export scan report."""
        if not self.scan_results:
            QMessageBox.information(self, "No Results", "No scan results to export.")
            return
        
        filepath = self.report_generator.generate_html_report(self.scan_results)
        
        reply = QMessageBox.question(
            self, "Report Generated",
            f"Report saved to:\n{filepath}\n\nOpen in browser?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            webbrowser.open(f"file://{filepath}")
    
    def export_detections(self):
        """Export detections to file."""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Save Detections", "",
            "JSON Files (*.json);;Text Files (*.txt)"
        )
        
        if filepath:
            detections_data = []
            for result in self.scan_results:
                for detection in result.detections:
                    detections_data.append({
                        'risk_level': detection.risk_level.value,
                        'type': detection.detection_type,
                        'indicator': detection.indicator,
                        'description': detection.description,
                        'confidence': detection.confidence,
                        'remediation': detection.remediation,
                        'evidence': detection.evidence
                    })
            
            with open(filepath, 'w') as f:
                json.dump(detections_data, f, indent=2)
            
            self.log(f"Detections exported to {filepath}")
    
    def clear_results(self):
        """Clear all scan results."""
        self.scan_results.clear()
        self.detection_table.clear_detections()
        self.update_summary()
        self.log("Results cleared")
    
    def save_logs(self):
        """Save logs to file."""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Save Logs", "",
            "Text Files (*.txt)"
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(self.log_text.toPlainText())
            self.log(f"Logs saved to {filepath}")
    
    def quit_application(self):
        """Quit the application."""
        self.save_settings()
        
        if self.realtime_monitor.is_running():
            self.realtime_monitor.stop()
        
        QApplication.quit()


def run_application():
    """Run the application."""
    app = QApplication(sys.argv)
    app.setApplicationName("CyberGuardian")
    app.setApplicationDisplayName("CyberGuardian - Malware & Anomaly Detection Tool")
    
    app.setStyle('Fusion')
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec_())
