"""
Helper utilities for network anomaly detection system.
Contains common utility functions used across the application.
"""

import ipaddress
import hashlib
import subprocess
import logging
from datetime import datetime
from typing import Dict, Any

# Set up logging
logger = logging.getLogger(__name__)

def is_internal(ip: str) -> bool:
    """Check if an IP address is internal (private)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except (ValueError, ipaddress.AddressValueError):
        return False

def generate_alert_id(alert: dict) -> str:
    """
    Generate a unique identifier for an alert based on its key attributes.
    
    Args:
        alert: Alert dictionary
        
    Returns:
        Unique string identifier for the alert
    """
    # Use more fields to ensure uniqueness, including model scores and anomaly status
    components = [
        alert.get('timestamp', ''),
        alert.get('src_ip', ''),
        alert.get('dst_ip', ''),
        str(alert.get('dst_port', '')),
        str(alert.get('isof_score', '')),
        str(alert.get('ae_error', '')),
        str(alert.get('isof_anomaly', '')),
        str(alert.get('ae_anomaly', '')),
        # Add a microsecond timestamp component for uniqueness
        str(datetime.now().microsecond)
    ]
    
    # Create a hash of the components for a shorter, unique ID
    content = '_'.join(components)
    return hashlib.md5(content.encode()).hexdigest()[:12]

def run_attack_command(command: str, description: str) -> Dict[str, Any]:
    """
    Run an attack simulation command.
    
    Args:
        command: Command to execute
        description: Description of the attack
        
    Returns:
        Dictionary with execution results
    """
    try:
        logger.info(f"Starting {description}...")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            logger.info(f"{description} executed successfully")
            return {'success': True, 'message': f"{description} executed successfully"}
        else:
            logger.warning(f"{description} completed with warnings")
            return {'success': True, 'message': f"{description} completed with warnings"}
            
    except subprocess.TimeoutExpired:
        logger.warning(f"{description} timed out after 30 seconds")
        return {'success': False, 'message': f"{description} timed out after 30 seconds"}
    except Exception as e:
        logger.error(f"Error running {description}: {str(e)}")
        return {'success': False, 'message': f"Error running {description}: {str(e)}"} 