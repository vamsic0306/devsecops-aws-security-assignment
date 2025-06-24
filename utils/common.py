"""
Common utilities for AWS security scripts
"""
import json
import csv
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional
import os

def setup_logging(log_level: str = 'INFO') -> None:
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('aws_security_audit.log')
        ]
    )

def save_to_json(data: Any, filename: str, directory: str = '/tmp') -> str:
    """Save data to JSON file"""
    try:
        os.makedirs(directory, exist_ok=True)
        filepath = os.path.join(directory, filename)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        logging.info(f"Data saved to {filepath}")
        return filepath
    except Exception as e:
        logging.error(f"Failed to save JSON file: {str(e)}")
        raise

def save_to_csv(data: List[Dict], filename: str, directory: str = '/tmp') -> str:
    """Save data to CSV file"""
    try:
        if not data:
            logging.warning("No data to save to CSV")
            return ""
            
        os.makedirs(directory, exist_ok=True)
        filepath = os.path.join(directory, filename)
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        
        logging.info(f"Data saved to {filepath}")
        return filepath
    except Exception as e:
        logging.error(f"Failed to save CSV file: {str(e)}")
        raise

def days_between(date1: datetime, date2: datetime = None) -> int:
    """Calculate days between two dates"""
    if date2 is None:
        date2 = datetime.now(timezone.utc)
    
    # Ensure both dates are timezone-aware
    if date1.tzinfo is None:
        date1 = date1.replace(tzinfo=timezone.utc)
    if date2.tzinfo is None:
        date2 = date2.replace(tzinfo=timezone.utc)
    
    return (date2 - date1).days

def format_bytes(bytes_size: int) -> str:
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"

def validate_aws_response(response: Dict) -> bool:
    """Validate AWS API response"""
    return (
        response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200
    )

class SecurityViolation:
    """Class to represent security violations"""
    
    def __init__(self, resource_type: str, resource_id: str, 
                 violation_type: str, severity: str, details: str):
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.violation_type = violation_type
        self.severity = severity
        self.details = details
        self.timestamp = datetime.now(timezone.utc)
    
    def to_dict(self) -> Dict:
        return {
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'violation_type': self.violation_type,
            'severity': self.severity,
            'details': self.details,
            'timestamp': self.timestamp.isoformat()
        }