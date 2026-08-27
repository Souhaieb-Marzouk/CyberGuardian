"""
CyberGuardian Reporting Module
==============================
Generates HTML and PDF reports with cyber-themed styling.
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import base64

from scanners.base_scanner import ScanResult, Detection, RiskLevel
from utils.config import REPORTS_DIR, get_config
from utils.logging_utils import get_logger

logger = get_logger('reporting.generator')


class ReportGenerator:
    """
    Generates styled HTML reports from scan results.
    """
    
    # Cyber theme colors
    COLORS = {
        'background': '#0a0f0f',
        'background_secondary': '#121a1a',
        'background_card': '#1a2424',
        'primary': '#00ff9d',
        'secondary': '#00b8ff',
        'critical': '#ff0040',
        'high': '#ff6b35',
        'medium': '#ffd93d',
        'low': '#6bcb77',
        'info': '#4d96ff',
        'text': '#e0e0e0',
        'text_muted': '#8a8a8a',
        'border': '#2a3a3a',
    }
    
    def __init__(self):
        self.config = get_config()
        self.reports_dir = REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_html_report(
        self,
        results: List[ScanResult],
        title: str = "CyberGuardian Security Report",
        include_summary: bool = True
    ) -> Path:
        """
        Generate an HTML report from scan results.
        
        Args:
            results: List of scan results
            title: Report title
            include_summary: Whether to include executive summary
        
        Returns:
            Path to generated report
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"cyberguardian_report_{timestamp}.html"
        filepath = self.reports_dir / filename
        
        html_content = self._build_html(results, title, include_summary)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Generated report: {filepath}")
        return filepath
    
    def _build_html(
        self,
        results: List[ScanResult],
        title: str,
        include_summary: bool
    ) -> str:
        """Build complete HTML document."""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    {self._build_header(title)}
    {self._build_summary(results) if include_summary else ''}
    {self._build_scan_results(results)}
    {self._build_footer()}
</body>
</html>'''
    
    def _get_css(self) -> str:
        """Get CSS styles for the report."""
        return f'''
        :root {{
            --bg-primary: {self.COLORS['background']};
            --bg-secondary: {self.COLORS['background_secondary']};
            --bg-card: {self.COLORS['background_card']};
            --color-primary: {self.COLORS['primary']};
            --color-secondary: {self.COLORS['secondary']};
            --color-critical: {self.COLORS['critical']};
            --color-high: {self.COLORS['high']};
            --color-medium: {self.COLORS['medium']};
            --color-low: {self.COLORS['low']};
            --color-text: {self.COLORS['text']};
            --color-muted: {self.COLORS['text_muted']};
            --border-color: {self.COLORS['border']};
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            background-color: var(--bg-primary);
            color: var(--color-text);
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            text-align: center;
            padding: 40px 20px;
            border-bottom: 2px solid var(--color-primary);
            margin-bottom: 40px;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            color: var(--color-primary);
            text-shadow: 0 0 20px rgba(0, 255, 157, 0.5);
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            color: var(--color-secondary);
            font-size: 1.1em;
        }}
        
        .header .timestamp {{
            color: var(--color-muted);
            margin-top: 10px;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .summary-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        
        .summary-card h3 {{
            color: var(--color-muted);
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }}
        
        .summary-card .value {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        
        .summary-card.total .value {{ color: var(--color-secondary); }}
        .summary-card.clean .value {{ color: var(--color-low); }}
        .summary-card.suspicious .value {{ color: var(--color-medium); }}
        .summary-card.malicious .value {{ color: var(--color-critical); }}
        
        .scan-section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 30px;
            overflow: hidden;
        }}
        
        .scan-header {{
            background: var(--bg-card);
            padding: 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .scan-header h2 {{
            color: var(--color-primary);
            font-size: 1.3em;
        }}
        
        .scan-header .meta {{
            color: var(--color-muted);
            font-size: 0.9em;
        }}
        
        .detection {{
            border-bottom: 1px solid var(--border-color);
            padding: 20px;
        }}
        
        .detection:last-child {{
            border-bottom: none;
        }}
        
        .detection-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }}
        
        .detection-indicator {{
            font-size: 1.1em;
            font-weight: bold;
            word-break: break-all;
        }}
        
        .risk-badge {{
            padding: 5px 15px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
            white-space: nowrap;
        }}
        
        .risk-critical {{ background: var(--color-critical); color: white; }}
        .risk-high {{ background: var(--color-high); color: white; }}
        .risk-medium {{ background: var(--color-medium); color: #333; }}
        .risk-low {{ background: var(--color-low); color: #333; }}
        .risk-info {{ background: var(--color-info); color: white; }}
        
        .detection-details {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }}
        
        .detail-group {{
            background: var(--bg-card);
            padding: 15px;
            border-radius: 4px;
        }}
        
        .detail-group h4 {{
            color: var(--color-secondary);
            font-size: 0.85em;
            text-transform: uppercase;
            margin-bottom: 8px;
        }}
        
        .detail-group p {{
            color: var(--color-text);
            word-break: break-all;
        }}
        
        .remediation {{
            background: rgba(0, 255, 157, 0.1);
            border-left: 3px solid var(--color-primary);
            padding: 15px;
            margin-top: 10px;
        }}
        
        .remediation h4 {{
            color: var(--color-primary);
            margin-bottom: 10px;
        }}
        
        .remediation ul {{
            list-style-position: inside;
            color: var(--color-text);
        }}
        
        .remediation li {{
            margin-bottom: 5px;
        }}
        
        .remediation button {{
            background: var(--color-primary);
            color: var(--bg-primary);
            border: none;
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-family: inherit;
            font-size: 0.85em;
            margin-top: 10px;
        }}
        
        .remediation button:hover {{
            opacity: 0.9;
        }}
        
        .evidence {{
            background: var(--bg-card);
            padding: 15px;
            border-radius: 4px;
            margin-top: 10px;
        }}
        
        .evidence h4 {{
            color: var(--color-secondary);
            margin-bottom: 10px;
        }}
        
        .evidence pre {{
            background: var(--bg-primary);
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 0.85em;
            color: var(--color-muted);
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: var(--color-muted);
            border-top: 1px solid var(--border-color);
            margin-top: 40px;
        }}
        
        .no-detections {{
            text-align: center;
            padding: 40px;
            color: var(--color-low);
        }}
        
        .no-detections h3 {{
            font-size: 1.5em;
            margin-bottom: 10px;
        }}
        
        @media print {{
            body {{
                background: white;
                color: black;
            }}
            
            .summary-card, .scan-section, .detection, .detail-group {{
                background: #f5f5f5;
                border: 1px solid #ddd;
            }}
        }}
        '''
    
    def _build_header(self, title: str) -> str:
        """Build report header."""
        return f'''
        <div class="header">
            <h1>🛡️ {title}</h1>
            <div class="subtitle">Comprehensive Security Analysis Report</div>
            <div class="timestamp">Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
        </div>
        '''
    
    def _build_summary(self, results: List[ScanResult]) -> str:
        """Build executive summary section."""
        total_items = sum(r.total_items for r in results)
        total_clean = sum(r.clean_items for r in results)
        total_suspicious = sum(r.suspicious_items for r in results)
        total_malicious = sum(r.malicious_items for r in results)
        
        critical = sum(1 for r in results for d in r.detections if d.risk_level == RiskLevel.CRITICAL)
        high = sum(1 for r in results for d in r.detections if d.risk_level == RiskLevel.HIGH)
        medium = sum(1 for r in results for d in r.detections if d.risk_level == RiskLevel.MEDIUM)
        low = sum(1 for r in results for d in r.detections if d.risk_level == RiskLevel.LOW)
        
        return f'''
        <div class="summary">
            <div class="summary-card total">
                <h3>Total Items Scanned</h3>
                <div class="value">{total_items}</div>
            </div>
            <div class="summary-card clean">
                <h3>Clean</h3>
                <div class="value">{total_clean}</div>
            </div>
            <div class="summary-card suspicious">
                <h3>Suspicious</h3>
                <div class="value">{total_suspicious}</div>
            </div>
            <div class="summary-card malicious">
                <h3>Malicious</h3>
                <div class="value">{total_malicious}</div>
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Critical Detections</h3>
                <div class="value" style="color: var(--color-critical);">{critical}</div>
            </div>
            <div class="summary-card">
                <h3>High Detections</h3>
                <div class="value" style="color: var(--color-high);">{high}</div>
            </div>
            <div class="summary-card">
                <h3>Medium Detections</h3>
                <div class="value" style="color: var(--color-medium);">{medium}</div>
            </div>
            <div class="summary-card">
                <h3>Low Detections</h3>
                <div class="value" style="color: var(--color-low);">{low}</div>
            </div>
        </div>
        '''
    
    def _build_scan_results(self, results: List[ScanResult]) -> str:
        """Build detailed scan results sections."""
        sections = []
        
        for result in results:
            section = self._build_scan_section(result)
            sections.append(section)
        
        return '\n'.join(sections)
    
    def _build_scan_section(self, result: ScanResult) -> str:
        """Build a single scan section."""
        # Sort detections by risk level
        risk_order = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 3,
            RiskLevel.INFO: 4,
        }
        
        sorted_detections = sorted(
            result.detections,
            key=lambda d: risk_order.get(d.risk_level, 5)
        )
        
        detections_html = ''
        
        if sorted_detections:
            for detection in sorted_detections:
                detections_html += self._build_detection_html(detection)
        else:
            detections_html = f'''
            <div class="no-detections">
                <h3>✓ No Threats Detected</h3>
                <p>All scanned items were clean.</p>
            </div>
            '''
        
        return f'''
        <div class="scan-section">
            <div class="scan-header">
                <h2>🔍 {result.scan_type.title()} Analysis</h2>
                <div class="meta">
                    Duration: {result.scan_duration_seconds:.2f}s | 
                    Items: {result.total_items} |
                    Detections: {len(result.detections)}
                </div>
            </div>
            {detections_html}
        </div>
        '''
    
    def _build_detection_html(self, detection: Detection) -> str:
        """Build HTML for a single detection."""
        risk_class = f"risk-{detection.risk_level.value}"
        
        details_html = ''
        
        # Build detail groups
        if detection.file_path:
            details_html += f'''
            <div class="detail-group">
                <h4>File Path</h4>
                <p>{detection.file_path}</p>
            </div>
            '''
        
        if detection.process_name:
            details_html += f'''
            <div class="detail-group">
                <h4>Process</h4>
                <p>{detection.process_name} (PID: {detection.process_id})</p>
            </div>
            '''
        
        if detection.command_line:
            details_html += f'''
            <div class="detail-group">
                <h4>Command Line</h4>
                <p>{detection.command_line[:200]}</p>
            </div>
            '''
        
        # Detection reason
        details_html += f'''
        <div class="detail-group">
            <h4>Detection Reason</h4>
            <p>{detection.detection_reason}</p>
        </div>
        '''
        
        # Remediation
        remediation_html = ''
        if detection.remediation:
            remediation_items = '\n'.join(f'<li>{r}</li>' for r in detection.remediation)
            remediation_html = f'''
            <div class="remediation">
                <h4>🔧 Remediation Steps</h4>
                <ul>
                    {remediation_items}
                </ul>
            </div>
            '''
        
        # Evidence (collapsible)
        evidence_html = ''
        if detection.evidence:
            evidence_json = json.dumps(detection.evidence, indent=2)
            evidence_html = f'''
            <div class="evidence">
                <h4>📋 Evidence</h4>
                <pre>{evidence_json}</pre>
            </div>
            '''
        
        return f'''
        <div class="detection">
            <div class="detection-header">
                <div class="detection-indicator">{detection.indicator}</div>
                <span class="risk-badge {risk_class}">{detection.risk_level.value}</span>
            </div>
            <p style="margin-bottom: 15px;">{detection.description}</p>
            <div class="detection-details">
                {details_html}
            </div>
            {remediation_html}
            {evidence_html}
        </div>
        '''
    
    def _build_footer(self) -> str:
        """Build report footer."""
        return f'''
        <div class="footer">
            <p>CyberGuardian Security Scanner v{self.config.config.version}</p>
            <p>Report generated at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        '''
    
    def generate_pdf_report(
        self,
        results: List[ScanResult],
        title: str = "CyberGuardian Security Report"
    ) -> Optional[Path]:
        """
        Generate a PDF report (requires weasyprint or pdfkit).
        
        Args:
            results: List of scan results
            title: Report title
        
        Returns:
            Path to generated PDF or None if failed
        """
        # Generate HTML first
        html_path = self.generate_html_report(results, title)
        
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        pdf_filename = f"cyberguardian_report_{timestamp}.pdf"
        pdf_path = self.reports_dir / pdf_filename
        
        try:
            # Try weasyprint
            try:
                from weasyprint import HTML
                HTML(str(html_path)).write_pdf(str(pdf_path))
                logger.info(f"Generated PDF report: {pdf_path}")
                return pdf_path
            except ImportError:
                pass
            
            # Try pdfkit
            try:
                import pdfkit
                pdfkit.from_file(str(html_path), str(pdf_path))
                logger.info(f"Generated PDF report: {pdf_path}")
                return pdf_path
            except ImportError:
                pass
            
            logger.warning("PDF generation requires weasyprint or pdfkit")
            return None
            
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return None
    
    def export_json(
        self,
        results: List[ScanResult],
        title: str = "CyberGuardian Security Report"
    ) -> Path:
        """Export scan results as JSON."""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"cyberguardian_report_{timestamp}.json"
        filepath = self.reports_dir / filename
        
        data = {
            'title': title,
            'generated_at': datetime.utcnow().isoformat(),
            'version': self.config.config.version,
            'results': [r.to_dict() for r in results]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"Exported JSON report: {filepath}")
        return filepath


def generate_report(
    results: List[ScanResult],
    format: str = 'html',
    title: str = "CyberGuardian Security Report"
) -> Path:
    """
    Convenience function to generate a report.
    
    Args:
        results: Scan results
        format: Output format ('html', 'pdf', 'json')
        title: Report title
    
    Returns:
        Path to generated report
    """
    generator = ReportGenerator()
    
    if format == 'pdf':
        result = generator.generate_pdf_report(results, title)
        if result:
            return result
        # Fall back to HTML if PDF fails
        format = 'html'
    
    if format == 'json':
        return generator.export_json(results, title)
    
    return generator.generate_html_report(results, title)
