"""
File I/O utilities for network anomaly detection system.
Contains functions for reading logs, writing alerts, and file operations.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Generator

from config import (
    PERSISTENT_ALERTS_DIRECTORY,
    LOG_VERSION,
    DEFAULT_ENCODING
)

# Set up logging
logger = logging.getLogger(__name__)

def log_alert_to_persistent_file(alert_data: Dict[str, Any], alert_type: str = "unknown") -> bool:
    """
    Log alert data to a daily persistent JSON Lines file.
    
    Args:
        alert_data: Complete alert object to log
        alert_type: Type of alert (ml, behavioral, threat_intel, etc.)
    
    Returns:
        bool: True if successfully logged, False otherwise
    """
    try:
        # Create daily filename
        today = datetime.now().strftime("%Y-%m-%d")
        log_dir = PERSISTENT_ALERTS_DIRECTORY
        os.makedirs(log_dir, exist_ok=True)
        
        filename = os.path.join(log_dir, f"persistent_alerts_{today}.jsonl")
        
        # Prepare log entry
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "alert_type": alert_type,
            "alert_data": alert_data,
            "log_version": LOG_VERSION
        }
        
        # Append to file
        with open(filename, 'a', encoding=DEFAULT_ENCODING) as f:
            f.write(json.dumps(log_entry, default=str, ensure_ascii=False) + '\n')
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to log alert to persistent file: {str(e)}")
        return False

def yield_new_lines_in_batches(file_path: str, last_position: int, batch_size: int = 1000) -> Generator[Tuple[List[str], int], None, None]:
    """
    Generator that yields new lines from a file in manageable batches to prevent memory overload.
    
    This function implements a streaming batch-processing architecture that never holds
    the entire log delta in memory. It reads the file in chunks and yields cleaned
    batches of lines along with the new file position.
    
    Args:
        file_path: Path to the file to read
        last_position: Last read position in the file  
        batch_size: Number of lines to read per batch (default: 1000)
        
    Yields:
        Tuple of (batch_of_cleaned_lines, new_file_position)
        - batch_of_cleaned_lines: List of cleaned lines (stripped, non-empty, non-comments)
        - new_file_position: Current file position after reading this batch
    """
    try:
        if not os.path.exists(file_path):
            logger.warning(f"File {file_path} does not exist")
            return
            
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            # Seek to the last known position
            file.seek(last_position)
            
            while True:
                # Track starting position to detect if we're stuck
                starting_position = file.tell()
                
                # Read lines one by one to track position accurately
                # This approach prevents the file position tracking issues
                batch_lines = []
                lines_read_in_batch = 0
                
                while lines_read_in_batch < batch_size:
                    current_position = file.tell()
                    line = file.readline()
                    
                    if not line:
                        # End of file reached
                        break
                    
                    # Clean the line: strip whitespace and ignore empty or commented lines
                    stripped_line = line.strip()
                    if stripped_line and not stripped_line.startswith('#'):
                        batch_lines.append(stripped_line)
                    
                    lines_read_in_batch += 1
                
                # Get final position after reading this batch
                final_position = file.tell()
                
                # Only yield the batch if we have actual lines OR if we read some lines but none were valid
                if batch_lines:
                    yield batch_lines, final_position
                elif lines_read_in_batch > 0:
                    # We read some lines but none were valid, still update position
                    yield [], final_position
                
                # If we didn't read the full batch size, we've reached EOF
                if lines_read_in_batch < batch_size:
                    break
                    
                # Safety check: if position didn't change, we're stuck
                if final_position == starting_position:
                    logger.warning(f"File position stuck at {final_position}, breaking loop")
                    break
                    
                # PERFORMANCE OPTIMIZATION: Yield empty batches if we're reading too fast
                # This prevents UI from being overwhelmed with data
                if lines_read_in_batch == 0:
                    break
                    
    except IOError as e:
        logger.error(f"IO error reading file {file_path}: {str(e)}")
    except UnicodeDecodeError as e:
        logger.error(f"Unicode decode error reading file {file_path}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error reading file {file_path}: {str(e)}")

def read_new_lines(file_path: str, last_position: int) -> Tuple[List[str], int]:
    """
    Read new lines from a file starting from last_position.
    
    Args:
        file_path: Path to the file
        last_position: Last read position in the file
        
    Returns:
        Tuple of (new_lines, new_position)
    """
    new_lines = []
    new_position = last_position
    
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                file.seek(last_position)
                lines = file.readlines()
                new_lines = [line.strip() for line in lines if line.strip()]
                new_position = file.tell()
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {str(e)}")
    
    return new_lines, new_position

def log_feedback(alert_record: dict, feedback_type: str) -> Dict[str, Any]:
    """
    Log user feedback for an ML alert to a persistent file.
    
    Args:
        alert_record: The complete alert dictionary
        feedback_type: Either 'TP' (True Positive) or 'FP' (False Positive)
        
    Returns:
        Dictionary with logging results
    """
    try:
        # Create feedback entry with timestamp and all alert data
        feedback_entry = {
            'feedback_timestamp': datetime.now().isoformat(),
            'feedback_type': feedback_type,
            'alert_data': alert_record
        }
        
        # Log to feedback.log file (one JSON object per line)
        with open('feedback.log', 'a', encoding=DEFAULT_ENCODING) as f:
            f.write(json.dumps(feedback_entry, ensure_ascii=False) + '\n')
        
        logger.info(f"Feedback logged: {feedback_type}")
        return {'success': True, 'message': f"Feedback logged: {feedback_type}"}
        
    except Exception as e:
        logger.error(f"Error logging feedback: {str(e)}")
        return {'success': False, 'message': f"Error logging feedback: {str(e)}"} 