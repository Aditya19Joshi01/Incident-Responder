"""
Database utilities for storing incident reports in SQLite.
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class IncidentDB:
    """SQLite database manager for incident reports."""
    
    def __init__(self, db_path: str = "incident_reports.db"):
        """
        Initialize the database connection.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize the database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                mitre_technique TEXT,
                summary TEXT,
                remediation TEXT,
                full_trace_json TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {self.db_path}")
    
    def save_report(self, report: Dict[str, Any]) -> int:
        """
        Save an incident report to the database.
        
        Args:
            report: Dictionary containing report data
            
        Returns:
            The ID of the inserted report
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        timestamp = report.get("timestamp", datetime.utcnow().isoformat())
        alert_type = report.get("alert", "Unknown")
        mitre_technique = report.get("mitre_mapping", "")
        summary = json.dumps(report.get("parsed_details", {}))
        remediation = json.dumps(report.get("recommended_actions", []))
        full_trace = json.dumps(report)
        
        cursor.execute("""
            INSERT INTO reports 
            (timestamp, alert_type, mitre_technique, summary, remediation, full_trace_json)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp, alert_type, mitre_technique, summary, remediation, full_trace))
        
        report_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f"Report saved with ID: {report_id}")
        return report_id
    
    def get_report(self, report_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve a report by ID.
        
        Args:
            report_id: The ID of the report to retrieve
            
        Returns:
            Dictionary containing the report data, or None if not found
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return {
            "id": row[0],
            "timestamp": row[1],
            "alert_type": row[2],
            "mitre_technique": row[3],
            "summary": json.loads(row[4]) if row[4] else {},
            "remediation": json.loads(row[5]) if row[5] else [],
            "full_trace_json": json.loads(row[6]) if row[6] else {},
            "created_at": row[7]
        }
    
    def list_reports(self, limit: int = 10) -> list:
        """
        List recent reports.
        
        Args:
            limit: Maximum number of reports to return
            
        Returns:
            List of report dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, timestamp, alert_type, mitre_technique 
            FROM reports 
            ORDER BY created_at DESC 
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                "id": row[0],
                "timestamp": row[1],
                "alert_type": row[2],
                "mitre_technique": row[3]
            }
            for row in rows
        ]

