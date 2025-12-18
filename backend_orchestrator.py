"""
Backend Orchestrator for network anomaly detection system.
Main processing loop that coordinates all detection components.
"""

import logging
import time
import os
import threading
import json
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
from collections import defaultdict 

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from core.detection_engine import DetectionEngine
from core.correlation_engine import CorrelationEngine

from components.llm_summarizer import generate_findings_summary, get_hypothesis_from_llm
from config import REDIS_CONFIG, REDIS_KEYS, FIFO_CONFIG
from core.correlation_engine import write_findings_to_jsonl, write_compact_alerts_to_jsonl
import hashlib
# Set up logging
logger = logging.getLogger(__name__)

# Set logging level to INFO to reduce verbose output
logger.setLevel(logging.INFO)


class BackendOrchestrator:
    """
    Main orchestrator that coordinates all backend processing components.
    Handles log processing, detection, correlation, and alert generation.
    """
    
    def __init__(self):
        """Initialize the backend orchestrator with all components."""
        self.detection_engine = DetectionEngine()
        self.correlation_engine = CorrelationEngine()
        
        self.redis_client = None

        
        # LLM client for on-demand AI services - will be set from session state
        self.llm_client = None
        
        # UI callback functions - will be set externally
        self.ui_callbacks = {
            'show_warning': None,
            'show_info': None, 
            'show_success': None,
            'show_error': None
        }
        
        # State tracking
        self.file_positions = {}  # Track file read positions
        self.active_alerts = []   # Current active alerts
        self.processed_findings = []  # Processed findings for UI
        
        #  FIX: Redis log deduplication to prevent duplicate processing
        self.processed_redis_logs = set()  # Track processed Redis log hashes
        self.redis_log_cache = {}  # Cache for Redis log processing results
        self.redis_cache_ttl = 300  # 5 minutes TTL for Redis log cache
        
        #  NEW: FIFO Queue Management for separate log types
        self.fifo_queues = {
            'conn': [],  # FIFO queue for connection logs
            'dns': []    # FIFO queue for DNS logs
        }
        self.queue_timestamps = {
            'conn': {},  # Track timestamp for each log in queue
            'dns': {}    # Track timestamp for each log in queue
        }
        self.processing_priorities = {
            'conn': FIFO_CONFIG['conn_processing_weight'],  # Higher priority for conn logs
            'dns': FIFO_CONFIG['dns_processing_weight']     # Lower priority for DNS logs
        }
        
        #  NEW: Alert Accumulation for Evidence Correlation
        self.pending_alerts = {
            'conn': [],  
            'dns': []   
        }
        self.correlation_threshold = 1   
        self.last_correlation_time = {
            'conn': 0,
            'dns': 0
        }
        self.correlation_interval = 60  # 1 minutes interval

        # Performance metrics
        self.processing_stats = {
            'lines_processed': 0,
            'alerts_generated': 0,
            'last_processing_time': None,
            'processing_errors': 0,
            'fifo_queue_stats': {
                'conn_queue_size': 0,
                'dns_queue_size': 0,
                'total_queued_logs': 0,
                'processing_order_violations': 0
            }
        }
        
        # Redis log type tracking
        self.redis_log_stats = {
            'total_logs_received': 0,
            'logs_by_type': {},  # Track count by log type
            'logs_by_pipeline': {},  # Track count by pipeline
            'filtered_logs': 0,
            'accepted_logs': 0,
            'last_reset_time': time.time(),
            'fifo_processing_stats': {
                'conn_processed_first': 0,
                'dns_processed_first': 0,
                'mixed_processing': 0,
                'queue_overflow_events': 0
            }
        }
        
        # Real-time monitoring components
        self.file_observer = None
        self.file_handler = None
        self.monitoring_active = False
        self.monitoring_thread = None  #  NEW: Store reference to monitoring thread
        self.monitored_directories = set()
        
        try:
            # Truy cập transformer thông qua detection_engine và conn_processor
            transformer = self.detection_engine.conn_processor.transformer
            if transformer:
                transformer.reset()
                logger.info("✅ Initial reset of GroupFeatureTransformer state successful.")
                logger.info("   Runtime state cleared for clean startup - beacon patterns will build from scratch.")
            else:
                logger.warning("⚠️  GroupFeatureTransformer not found in detection_engine.conn_processor")
        except Exception as e:
            logger.error(f"Could not reset GroupFeatureTransformer state on startup: {e}")
            logger.info("   This is normal if transformer hasn't been initialized yet.")
        # =======================================================
    
    
    def _create_redis_connection(self):
        """
        Create Redis connection using configuration from config.py.
        Uses shared connection instance to avoid multiple connections.
        
        Returns:
            redis.Redis: Connected Redis client
            
        Raises:
            ImportError: If redis library not available
            ConnectionError: If Redis connection fails
        """
        #  OPTIMIZATION: Use shared Redis connection if available
        if self.redis_client is not None:
            try:
                # Test existing connection
                self.redis_client.ping()
                logger.debug("[SUCCESS] Using existing shared Redis connection")
                return self.redis_client
            except Exception:
                # Connection lost, create new one
                logger.warning("Shared Redis connection lost, creating new one...")
                self.redis_client = None
        
        logger.info("Creating new Redis connection...")
        
        if not REDIS_AVAILABLE:
            logger.error("Redis library not available")
            raise ImportError("Redis library not available")
        
        try:
            # Create new Redis connection
            self.redis_client = redis.Redis(**REDIS_CONFIG)
            
            # Test connection
            self.redis_client.ping()
            logger.info("[SUCCESS] Shared Redis connection created successfully!")
            
            return self.redis_client
            
        except Exception as e:
            logger.error(f"Redis connection failed: {str(e)}")
            # Connection error details removed for cleaner logging
            raise ConnectionError(f"Cannot connect to Redis: {str(e)}")
    
    def _should_process_log(self, log_message: str, log_type: str = 'conn') -> bool:
        """
        Simplified log filter logic for better performance and reliability.
        
        Args:
            log_message: Raw log message from Redis
            log_type: Type of log ('conn' or 'dns')
            
        Returns:
            bool: True if log should be processed
        """
        try:
            # Update total logs received counter
            self.redis_log_stats['total_logs_received'] += 1
            
            # Simple validation: check if log is not empty
            if not log_message or not log_message.strip():
                self.redis_log_stats['filtered_logs'] += 1
                return False
            
            # For JSON logs, do basic validation
            if log_message.startswith('{'):
                try:
                    import json
                    data = json.loads(log_message)
                    
                    # Track basic statistics
                    source = data.get('log', {}).get('file', {}).get('path', '')
                    pipeline = data.get('pipeline', '')
                    
                    # Simple acceptance logic: accept if log_type matches or pipeline matches
                    if log_type in ['conn', 'dns']:
                        if (log_type in source.lower() or 
                            pipeline == log_type or 
                            f'{log_type}.log' in source):
                            
                            self.redis_log_stats['accepted_logs'] += 1
                            return True
                    
                    # Accept if it's a valid JSON log
                    self.redis_log_stats['accepted_logs'] += 1
                    return True
                    
                except json.JSONDecodeError:
                    # Invalid JSON, but still accept for processing
                    self.redis_log_stats['accepted_logs'] += 1
                    return True
            
            # Accept non-JSON logs as well
            self.redis_log_stats['accepted_logs'] += 1
            return True
            
        except Exception as e:
            logger.warning(f"Error checking log filter: {str(e)}")
            # Default to accepting if unsure
            self.redis_log_stats['accepted_logs'] += 1
            return True


    def _is_redis_log_duplicate(self, redis_log_line: str) -> bool:
        """
        Check if Redis log has already been processed to prevent duplicates.
        
        Args:
            redis_log_line: Raw Redis log line
            
        Returns:
            bool: True if log is duplicate, False if new
        """
        
        # Create hash of log line for deduplication
        log_hash = hashlib.md5(redis_log_line.encode('utf-8')).hexdigest()
        
        # Check if we've already processed this log
        if log_hash in self.processed_redis_logs:
            # Skipping duplicate Redis log
            return True
        
        # Add to processed set
        self.processed_redis_logs.add(log_hash)
        
        # Cleanup old hashes to prevent memory buildup (keep last 10000)
        if len(self.processed_redis_logs) > 10000:
            # Remove oldest 1000 hashes
            old_hashes = list(self.processed_redis_logs)[:1000]
            for old_hash in old_hashes:
                self.processed_redis_logs.discard(old_hash)
            # Cleaned up old Redis log hashes
        
        return False

    def _get_cached_redis_result(self, redis_log_line: str) -> Optional[Dict[str, Any]]:
        """
        Get cached result for Redis log processing.
        
        Args:
            redis_log_line: Raw Redis log line
            
        Returns:
            Optional[Dict]: Cached result or None if not found
        """
        
        log_hash = hashlib.md5(redis_log_line.encode('utf-8')).hexdigest()
        
        if log_hash in self.redis_log_cache:
            cache_entry = self.redis_log_cache[log_hash]
            # Check if cache entry is still valid
            if time.time() - cache_entry['timestamp'] < self.redis_cache_ttl:
                # Using cached result for Redis log
                return cache_entry['result']
            else:
                # Remove expired cache entry
                del self.redis_log_cache[log_hash]
        
        return None

    def _cache_redis_result(self, redis_log_line: str, result: Dict[str, Any]) -> None:
        """
        Cache result for Redis log processing.
        
        Args:
            redis_log_line: Raw Redis log line
            result: Processing result to cache
        """
        
        log_hash = hashlib.md5(redis_log_line.encode('utf-8')).hexdigest()
        
        self.redis_log_cache[log_hash] = {
            'result': result,
            'timestamp': time.time()
        }
        
        # Cleanup old cache entries
        current_time = time.time()
        expired_keys = [
            key for key, entry in self.redis_log_cache.items()
            if current_time - entry['timestamp'] > self.redis_cache_ttl
        ]
        
        for key in expired_keys:
            del self.redis_log_cache[key]
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired Redis cache entries")
    
    def _add_to_fifo_queue(self, log_data: str, log_type: str) -> bool:
        """
        Add log to appropriate FIFO queue with timestamp tracking.
        FIXED: Simplified logic to prevent memory leaks and bottlenecks.
        
        Args:
            log_data: Raw log data from Redis
            log_type: Type of log ('conn' or 'dns')
            
        Returns:
            bool: True if successfully added, False if queue overflow
        """
        try:
            if log_type not in self.fifo_queues:
                logger.warning(f" Unknown log type: {log_type}")
                return False
            
            # FIXED: Simplified queue management - no complex backpressure logic
            queue_size = len(self.fifo_queues[log_type])
            max_size = FIFO_CONFIG['max_queue_size']
            
            # Simple overflow protection - prevent memory leaks
            if queue_size >= max_size * 2:  # 200% overflow protection
                logger.warning(f"🚨 {log_type} queue severely overflowed ({queue_size}/{max_size}) - applying throttling")
                # Apply simple throttling instead of complex backpressure
                time.sleep(0.1)  # 100ms delay
            
            # Add new log to queue (FIFO - append to end)
            self.fifo_queues[log_type].append(log_data)
            
            # Track timestamp for this log
            log_hash = hashlib.md5(log_data.encode('utf-8')).hexdigest()
            self.queue_timestamps[log_type][log_hash] = time.time()
            
            # Update queue statistics
            self.processing_stats['fifo_queue_stats'][f'{log_type}_queue_size'] = len(self.fifo_queues[log_type])
            self.processing_stats['fifo_queue_stats']['total_queued_logs'] = sum(len(q) for q in self.fifo_queues.values())
            
            # Cleanup old timestamps to prevent memory buildup
            current_time = time.time()
            expired_timestamps = [
                hash_val for hash_val, ts in self.queue_timestamps[log_type].items()
                if current_time - ts > 300  # 5 minutes
            ]
            for hash_val in expired_timestamps:
                del self.queue_timestamps[log_type][hash_val]
            
            return True
            
        except Exception as e:
            logger.error(f" Error adding to FIFO queue: {str(e)}")
            return False
    
    def _should_drop_log_intelligently(self, log_data: str, log_type: str) -> bool:
        """
        🚨 CRITICAL FIX: NEVER drop ANY logs - anomaly detection requires ALL data!
        This function now ONLY returns False to ensure NO logs are dropped.
        
        Args:
            log_data: Raw log data to evaluate
            log_type: Type of log ('conn' or 'dns')
            
        Returns:
            bool: ALWAYS False - NO DROPPING ALLOWED
        """
        try:
            # 🚨 CRITICAL: NEVER drop ANY logs for anomaly detection
            # Attack indicators can be hidden in ANY log type
            # Even "normal" logs might contain subtle attack patterns
            
            # Log the attempt to drop for monitoring
            logger.warning(f"🚨 ATTEMPTED LOG DROP BLOCKED: {log_type} log contains potential attack data")
            logger.warning(f"   🚨 ANOMALY DETECTION REQUIRES ALL LOGS - NO DROPPING ALLOWED!")
            logger.warning(f"   🚨 Log preview: {log_data[:100]}...")
            
            # ALWAYS return False - NEVER drop logs
            return False
            
        except Exception as e:
            logger.warning(f" Error in log drop prevention: {e}")
            # On error, still return False to prevent dropping
            return False
    
    def _calculate_log_risk_score(self, log_data: str, log_type: str) -> int:
        """
         NEW: Calculate risk score for log based on attack indicators.
        Higher score = higher priority for processing.
        
        Args:
            log_data: Raw log data to evaluate
            log_type: Type of log ('conn' or 'dns')
            
        Returns:
            int: Risk score (0-100, higher = higher risk)
        """
        try:
            risk_score = 0
            
            if log_type == 'conn':
                # Connection attack indicators (highest priority)
                critical_indicators = ['S0', 'REJ', 'RSTO', 'RSTR', 'RSTOS0', 'RSTRH', 'SH', 'SHR']
                for indicator in critical_indicators:
                    if indicator in log_data:
                        risk_score += 25  # Critical attack indicator
                
                # Suspicious indicators (medium priority)
                suspicious_indicators = ['S1', 'S2', 'S3', 'FIN', 'PUSH']
                for indicator in suspicious_indicators:
                    if indicator in log_data:
                        risk_score += 10  # Suspicious indicator
                
                # Normal indicators (lowest priority)
                normal_indicators = ['SF', 'ESTABLISHED']
                for indicator in normal_indicators:
                    if indicator in log_data:
                        risk_score += 1   # Normal connection
                
                # Port-based risk assessment
                if ':22' in log_data or ':23' in log_data or ':3389' in log_data:
                    risk_score += 15  # SSH, Telnet, RDP - higher risk
                elif ':80' in log_data or ':443' in log_data:
                    risk_score += 5   # HTTP/HTTPS - medium risk
                
            elif log_type == 'dns':
                # DNS attack indicators (highest priority)
                c2_indicators = ['TXT', 'MX', 'CNAME', 'SRV', 'PTR']
                for indicator in c2_indicators:
                    if indicator in log_data:
                        risk_score += 30  # Potential C2 communication
                
                # Suspicious DNS patterns
                if 'dga' in log_data.lower() or 'tunnel' in log_data.lower():
                    risk_score += 25  # DGA or tunneling indicators
                
                # Common queries (lower priority)
                common_queries = ['A', 'AAAA']
                for query in common_queries:
                    if query in log_data:
                        risk_score += 2   # Common DNS query
            
            # Ensure score is within bounds
            return min(100, max(0, risk_score))
            
        except Exception as e:
            logger.warning(f" Error calculating log risk score: {e}")
            return 0  # Default to lowest priority on error
    
    def _get_next_log_from_fifo(self) -> Optional[tuple]:
        """
         FIXED: Get next log from FIFO queues based on ATTACK INDICATORS and priority.
        Prioritizes logs with attack indicators over log type.
        
        Returns:
            Optional[tuple]: (log_data, log_type, timestamp) or None if queues empty
        """
        try:
            available_logs = []
            
            # Check both queues for available logs
            for log_type in ['conn', 'dns']:
                if self.fifo_queues[log_type]:
                    # Get oldest log from this queue (FIFO principle)
                    oldest_log = self.fifo_queues[log_type][0]
                    oldest_hash = hashlib.md5(oldest_log.encode('utf-8')).hexdigest()
                    timestamp = self.queue_timestamps[log_type].get(oldest_hash, 0)
                    
                    #  FIXED: Calculate risk score based on attack indicators
                    risk_score = self._calculate_log_risk_score(oldest_log, log_type)
                    
                    available_logs.append((oldest_log, log_type, timestamp, risk_score))
            
            if not available_logs:
                return None
            
            #  FIXED: Sort by RISK SCORE first, then by priority and timestamp
            if FIFO_CONFIG['priority_processing']:
                # Sort by: 1) Risk Score (attack indicators), 2) Log Type, 3) Timestamp
                available_logs.sort(key=lambda x: (
                    -x[3],  # Risk score DESC (highest risk first)
                    x[1] != 'conn',  # conn logs second (False sorts before True)
                    x[2]  # Then by timestamp (FIFO)
                ))
            else:
                # Pure FIFO with risk score consideration
                available_logs.sort(key=lambda x: (-x[3], x[2]))  # Risk score DESC, then timestamp
            
            # Return the highest risk/priority/earliest log
            return (available_logs[0][0], available_logs[0][1], available_logs[0][2])
            
        except Exception as e:
            logger.error(f" Error getting next log from FIFO: {str(e)}")
            return None
    
    def _remove_log_from_fifo(self, log_data: str, log_type: str) -> bool:
        """
        Remove processed log from FIFO queue.
        
        Args:
            log_data: Raw log data to remove
            log_type: Type of log ('conn' or 'dns')
            
        Returns:
            bool: True if successfully removed
        """
        try:
            if log_type not in self.fifo_queues:
                return False
            
            # Remove from queue (FIFO - remove from front)
            if self.fifo_queues[log_type] and self.fifo_queues[log_type][0] == log_data:
                removed_log = self.fifo_queues[log_type].pop(0)
                
                # Remove timestamp tracking
                log_hash = hashlib.md5(removed_log.encode('utf-8')).hexdigest()
                if log_hash in self.queue_timestamps[log_type]:
                    del self.queue_timestamps[log_type][log_hash]
                
                # Update queue statistics
                self.processing_stats['fifo_queue_stats'][f'{log_type}_queue_size'] = len(self.fifo_queues[log_type])
                self.processing_stats['fifo_queue_stats']['total_queued_logs'] = sum(len(q) for q in self.fifo_queues.values())
                
                # Removed log from FIFO queue
                return True
            
            return False
            
        except Exception as e:
            logger.error(f" Error removing log from FIFO queue: {str(e)}")
            return False
    
    def _collect_logs_from_redis_fifo(self, time_window_seconds: int = 5) -> Dict[str, Any]:
        """
        Collect logs from Redis using FIFO approach with separate keys.
        FIXED: Simplified logic to prevent blocking and improve responsiveness.
        
        Args:
            time_window_seconds: Time window for collection
            
        Returns:
            Dictionary with collection results
        """
        logger.info(f"Starting FIFO Redis collection: {time_window_seconds}s window")
        
        try:
            # Connect to Redis
            r = self._create_redis_connection()
            
            start_time = time.time()
            total_collected = 0
            
            # FIXED: Simplified collection logic with shorter timeouts
            while (time.time() - start_time) < time_window_seconds:
                if not self.monitoring_active:
                    logger.info(" Collection stopped by monitoring flag")
                    break
                
                remaining_time = max(0.1, time_window_seconds - (time.time() - start_time))
                if remaining_time <= 0:
                    break
                
                try:
                    # FIXED: Use shorter timeouts to prevent blocking
                    check_timeout = min(remaining_time, 0.2)  # 200ms max timeout
                    
                    # BATCH COLLECTION: Lấy nhiều logs cùng lúc thay vì 1-1
                    batch_size = 100  # Lấy tối đa 100 logs mỗi lần
                    
                    # Collect conn logs in batch
                    try:
                        conn_logs = r.lrange(REDIS_KEYS['conn'], 0, batch_size - 1)
                        if conn_logs:
                            # Remove collected logs from Redis
                            r.ltrim(REDIS_KEYS['conn'], len(conn_logs), -1)
                            
                            # Add to FIFO queue
                            for log_data in conn_logs:
                                if self._add_to_fifo_queue(log_data, 'conn'):
                                    total_collected += 1
                    except Exception as e:
                        logger.warning(f" Redis conn batch collection error: {str(e)}")
                    
                    # Collect DNS logs in batch  
                    try:
                        dns_logs = r.lrange(REDIS_KEYS['dns'], 0, batch_size - 1)
                        if dns_logs:
                            # Remove collected logs from Redis
                            r.ltrim(REDIS_KEYS['dns'], len(dns_logs), -1)
                            
                            # Add to FIFO queue
                            for log_data in dns_logs:
                                if self._add_to_fifo_queue(log_data, 'dns'):
                                    total_collected += 1
                    except Exception as e:
                        logger.warning(f" Redis DNS batch collection error: {str(e)}")
                    
                    if not self.monitoring_active:
                        logger.info(" Collection stopped by monitoring flag after collection cycle")
                        break
                    
                    # Simple sleep to prevent CPU spinning
                    if total_collected == 0:
                        time.sleep(0.01)  # 10ms sleep when no logs
                    else:
                        time.sleep(0.001)  # 1ms sleep when logs found
                
                except redis.exceptions.TimeoutError:
                    continue
                except Exception as e:
                    logger.warning(f" Redis FIFO collection error: {str(e)}")
                    time.sleep(0.001)
            
            # Log collection statistics
            conn_queue_size = len(self.fifo_queues['conn'])
            dns_queue_size = len(self.fifo_queues['dns'])
            
            logger.info(f" FIFO collection completed: {total_collected} logs collected")
            logger.info(f"  - Conn queue: {conn_queue_size} logs")
            logger.info(f"  - DNS queue: {dns_queue_size} logs")
            logger.info(f"  - Total queued: {conn_queue_size + dns_queue_size} logs")
            
            return {
                'success': True,
                'total_collected': total_collected,
                'conn_queue_size': conn_queue_size,
                'dns_queue_size': dns_queue_size,
                'total_queued': conn_queue_size + dns_queue_size
            }
            
        except Exception as e:
            logger.error(f"Error in FIFO Redis collection: {str(e)}")  
            return {
                'success': False,
                'error': str(e),
                'total_collected': 0
            }
    
    def _process_fifo_queues(self, max_logs_per_cycle: int = 1000) -> Dict[str, Any]:
        """
         OPTIMIZED: Process logs from FIFO queues using BATCH processing for maximum speed.
        
        Args:
            max_logs_per_cycle: Maximum logs to process in this cycle
            
        Returns:
            Dictionary with processing results
        """
        logger.info(f" Starting OPTIMIZED FIFO queue processing (max: {max_logs_per_cycle} logs)")
        
        try:
            total_processed = 0
            total_alerts = 0
            processing_order = []
            
            #  NEW: Collect logs in batches for processing
            conn_batch = []
            dns_batch = []
            
            # Collect logs up to batch size
            while len(conn_batch) + len(dns_batch) < max_logs_per_cycle:
                next_log = self._get_next_log_from_fifo()
                if not next_log:
                    break
                
                log_data, log_type, timestamp = next_log
                
                # Add to appropriate batch
                if log_type == 'conn':
                    conn_batch.append(log_data)
                else:
                    dns_batch.append(log_data)
                
                # Remove from queue immediately
                self._remove_log_from_fifo(log_data, log_type)
            
            #  OPTIMIZED: Process conn logs in batch (higher priority)
            if conn_batch:
                logger.info(f" Processing {len(conn_batch)} conn logs in BATCH...")
                start_time = time.time()
                
                # Use batch processing for maximum speed
                conn_result = self._process_conn_batch(conn_batch)
                
                if conn_result['success']:
                    total_processed += conn_result['lines_processed']
                    total_alerts += conn_result['alerts_generated']
                    processing_order.extend(['conn'] * len(conn_batch))
                    
                    conn_time = time.time() - start_time
                    conn_rate = len(conn_batch) / conn_time if conn_time > 0 else 0
                    logger.info(f" Conn batch completed: {len(conn_batch)} logs in {conn_time:.2f}s ({conn_rate:.1f} logs/sec)")
                else:
                    logger.warning(f" Conn batch processing failed: {conn_result.get('error', 'Unknown error')}")
            
            #  OPTIMIZED: Process DNS logs in batch
            if dns_batch:
                logger.info(f" Processing {len(dns_batch)} DNS logs in BATCH...")
                start_time = time.time()
                
                # Use batch processing for maximum speed
                dns_result = self._process_dns_batch(dns_batch)
                
                if dns_result['success']:
                    total_processed += dns_result['lines_processed']
                    total_alerts += dns_result['alerts_generated']
                    processing_order.extend(['dns'] * len(dns_batch))
                    
                    dns_time = time.time() - start_time
                    dns_rate = len(dns_batch) / dns_time if dns_time > 0 else 0
                    logger.info(f" DNS batch completed: {len(dns_batch)} logs in {dns_time:.2f}s ({dns_rate:.1f} logs/sec)")
                else:
                    logger.warning(f" DNS batch processing failed: {dns_result.get('error', 'Unknown error')}")
            
            # Update FIFO processing statistics
            if processing_order:
                if processing_order[0] == 'conn':
                    self.redis_log_stats['fifo_processing_stats']['conn_processed_first'] += 1
                elif processing_order[0] == 'dns':
                    self.redis_log_stats['fifo_processing_stats']['dns_processed_first'] += 1
                
                # Check for mixed processing
                if len(set(processing_order)) > 1:
                    self.redis_log_stats['fifo_processing_stats']['mixed_processing'] += 1
            
            total_time = time.time() - start_time if 'start_time' in locals() else 0
            overall_rate = total_processed / total_time if total_time > 0 else 0
            
            logger.info(f"OPTIMIZED FIFO processing completed:")
            logger.info(f"  - Total logs: {total_processed}")
            logger.info(f"  - Total alerts: {total_alerts}")
            logger.info(f"  - Overall rate: {overall_rate:.1f} logs/sec")
            
            return {
                'success': True,
                'logs_processed': total_processed,
                'alerts_generated': total_alerts,
                'processing_order': processing_order,
                'conn_queue_remaining': len(self.fifo_queues['conn']),
                'dns_queue_remaining': len(self.fifo_queues['dns']),
                'processing_rate': overall_rate
            }
            
        except Exception as e:
            logger.error(f"Error in OPTIMIZED FIFO queue processing: {str(e)}")  
            return {
                'success': False,
                'error': str(e),
                'logs_processed': 0,
                'alerts_generated': 0
            }
    
    def _process_conn_batch(self, conn_logs: List[str]) -> Dict[str, Any]:
        """
         NEW: Process connection logs in batch using DetectionEngine's batch method.
        This is MUCH faster than processing individual logs.
        
        Args:
            conn_logs: List of connection log lines
            
        Returns:
            Dictionary with processing results
        """
        try:
            if not conn_logs:
                return {'success': True, 'lines_processed': 0, 'alerts_generated': 0}
            
            logger.info(f" Processing {len(conn_logs)} conn logs in BATCH...")
            start_time = time.time()
            
            # Use DetectionEngine's batch processing for maximum speed
            alerts = self.detection_engine.analyze_connections_batch(conn_logs)
            

            try:
                if alerts and len(alerts) > 0:
                    self._debug_log_features(conn_logs, alerts, 'conn')
            except Exception as debug_e:
                logger.warning(f"Debug logging failed: {debug_e}")
            
            processing_time = time.time() - start_time
            processing_rate = len(conn_logs) / processing_time if processing_time > 0 else 0
            
            logger.info(f"Conn batch processing completed:")
            logger.info(f"  - Logs processed: {len(conn_logs)}")
            logger.info(f"  - Alerts generated: {len(alerts)}")
            logger.info(f"  - Processing time: {processing_time:.2f}s")
            logger.info(f"  - Processing rate: {processing_rate:.1f} logs/sec")
            
            
            if alerts:
                self.pending_alerts['conn'].extend(alerts)
                logger.info(f" Added {len(alerts)} conn alerts to pending correlation queue")
                
                #  CRITICAL FIX: Trigger correlation for batch processing
                current_time = time.time()
                alerts_count = len(self.pending_alerts['conn'])
                
                # Check if correlation should be triggered
                should_correlate = (
                    alerts_count >= self.correlation_threshold or  # 5+ alerts accumulated
                    (current_time - self.last_correlation_time['conn']) >= self.correlation_interval 
                )
                
                if should_correlate and alerts_count > 0:
                    logger.info(f" Triggering correlation for {alerts_count} accumulated conn alerts (BATCH)...")
                    
                    # Get accumulated alerts and clear pending
                    accumulated_alerts = self.pending_alerts['conn'].copy()
                    self.pending_alerts['conn'].clear()
                    self.last_correlation_time['conn'] = current_time
                    
                    # Auto-correlate accumulated alerts into findings
                    new_findings = self.correlation_engine.correlate_events(
                        alerts=accumulated_alerts,
                        time_window_minutes=5,  
                        existing_findings=self.processed_findings  # Pass existing findings for merging
                    )
                    
                    # Update processed findings
                    if new_findings:
                        self.processed_findings = new_findings  # Replace with merged findings
                        logger.info(f"[SUCCESS] Batch correlation completed: {len(new_findings)} total findings from {len(accumulated_alerts)} alerts")
                        
                        #  DEBUG: Log findings details
                        for finding in new_findings:
                            logger.info(f"📋 Finding created: {finding.get('finding_id')} | IP: {finding.get('ip')} | Risk: {finding.get('risk_score')} | Evidence: {finding.get('evidence_count')}")
                        
                        # Write findings to JSONL file
                        try:
                            write_findings_to_jsonl(new_findings, 'output/alerts.jsonl')
                            logger.info(f"📝 Written {len(new_findings)} findings to output/alerts.jsonl")
                        except Exception as e:
                            logger.error(f" Error writing findings to JSONL: {str(e)}")
                        # Also write compact Security Onion alerts to separate file
                        try:
                            write_compact_alerts_to_jsonl(new_findings, 'output/alerts_compact.jsonl')
                            logger.info(f"📝 Written compact alerts to output/alerts_compact.jsonl")
                        except Exception as e:
                            logger.error(f" Error writing compact alerts JSONL: {str(e)}")

                    else:
                        logger.warning(f" No findings generated from {len(accumulated_alerts)} accumulated alerts (BATCH)")
            
            return {
                'success': True,
                'lines_processed': len(conn_logs),
                'alerts_generated': len(alerts),
                'processing_time': processing_time,
                'processing_rate': processing_rate
            }
            
        except Exception as e:
            logger.error(f"Error in conn batch processing: {str(e)}")  #  FIXED: Consistent error format
            return {
                'success': False,
                'error': str(e),
                'lines_processed': 0,
                'alerts_generated': 0
            }
    
    def _process_dns_batch(self, dns_logs: List[str]) -> Dict[str, Any]:
        """
         NEW: Process DNS logs in batch using DetectionEngine's batch method.
        This is MUCH faster than processing individual logs.
        
        Args:
            dns_logs: List of DNS log lines
            
        Returns:
            Dictionary with processing results
        """
        try:
            if not dns_logs:
                return {'success': True, 'lines_processed': 0, 'alerts_generated': 0}
            
            logger.info(f" Processing {len(dns_logs)} DNS logs in BATCH...")
            start_time = time.time()
            
            # Use DetectionEngine's batch processing for maximum speed
            alerts = self.detection_engine.analyze_dns_batch(dns_logs)
            
            processing_time = time.time() - start_time
            processing_rate = len(dns_logs) / processing_time if processing_time > 0 else 0
            
            logger.info(f"[SUCCESS] DNS batch processing completed:")
            logger.info(f"  - Logs processed: {len(dns_logs)}")
            logger.info(f"  - Alerts generated: {len(alerts)}")
            logger.info(f"  - Processing time: {processing_time:.2f}s")
            logger.info(f"  - Processing rate: {processing_rate:.1f} logs/sec")
            

            if alerts:
                self.pending_alerts['dns'].extend(alerts)
                logger.info(f" Added {len(alerts)} DNS alerts to pending correlation queue")
                
                #  CRITICAL FIX: Trigger correlation for DNS batch processing
                current_time = time.time()
                alerts_count = len(self.pending_alerts['dns'])
                
                # Check if correlation should be triggered
                should_correlate = (
                    alerts_count >= self.correlation_threshold or  # 5+ alerts accumulated
                    (current_time - self.last_correlation_time['dns']) >= self.correlation_interval 
                )
                
                if should_correlate and alerts_count > 0:
                    logger.info(f" Triggering correlation for {alerts_count} accumulated DNS alerts (BATCH)...")
                    
                    # Get accumulated alerts and clear pending
                    accumulated_alerts = self.pending_alerts['dns'].copy()
                    self.pending_alerts['dns'].clear()
                    self.last_correlation_time['dns'] = current_time
                    
                    # Auto-correlate accumulated alerts into findings
                    new_findings = self.correlation_engine.correlate_events(
                        alerts=accumulated_alerts,
                        time_window_minutes=5,  
                        existing_findings=self.processed_findings  # Pass existing findings for merging
                    )
                    
                    # Update processed findings
                    if new_findings:
                        self.processed_findings = new_findings  # Replace with merged findings
                        logger.info(f"[SUCCESS] DNS batch correlation completed: {len(new_findings)} total findings from {len(accumulated_alerts)} alerts")
                        
                        # Write findings to JSONL file
                        try:
                            write_findings_to_jsonl(new_findings, 'output/alerts.jsonl')
                            logger.info(f"📝 Written {len(new_findings)} findings to output/alerts.jsonl")
                        except Exception as e:
                            logger.error(f" Error writing findings to JSONL: {str(e)}")
                        # Also write compact Security Onion alerts to separate file
                        try:
                            write_compact_alerts_to_jsonl(new_findings, 'output/alerts_compact.jsonl')
                            logger.info(f"📝 Written compact alerts to output/alerts_compact.jsonl")
                        except Exception as e:
                            logger.error(f" Error writing compact alerts JSONL: {str(e)}")
                    else:
                        logger.warning(f" No findings generated from {len(accumulated_alerts)} accumulated DNS alerts (BATCH)")
            
            return {
                'success': True,
                'lines_processed': len(dns_logs),
                'alerts_generated': len(alerts),
                'processing_time': processing_time,
                'processing_rate': processing_rate
            }
            
        except Exception as e:
            logger.error(f"Error in DNS batch processing: {str(e)}")  #  FIXED: Consistent error format
            return {
                'success': False,
                'error': str(e),
                'lines_processed': 0,
                'alerts_generated': 0
            }

    def set_ui_callbacks(self, callbacks: Dict[str, Callable]):
        """Set UI callback functions for displaying messages."""
        self.ui_callbacks.update(callbacks)
    
    def _show_ui_message(self, msg_type: str, message: str):
        """Show UI message if callback is available."""
        callback = self.ui_callbacks.get(f'show_{msg_type}')
        if callback:
            try:
                callback(message)
            except Exception as e:
                logger.warning(f"UI callback error: {e}")
    
    
    def correlate_alerts(self, time_window_minutes: int = 1) -> List[Dict[str, Any]]:
        """
        Delegate correlation to correlation engine for unified processing.
        
        Args:
            time_window_minutes: Time window for correlation in minutes (default: 1)
            
        Returns:
            List of correlated findings
        """
        try:
            logger.info(f"🔗 Delegating correlation to correlation engine for {len(self.active_alerts)} alerts")
            
            if self.active_alerts:
                # Use correlation engine with existing findings context
                new_findings = self.correlation_engine.correlate_events(
                    alerts=self.active_alerts,
                    time_window_minutes=time_window_minutes,
                    existing_findings=self.processed_findings  #  Pass existing findings for merging
                )
                
                if new_findings:
                    # Update processed_findings list
                    self.processed_findings = new_findings
                    
                    logger.info(f"[SUCCESS] Correlation completed: {len(new_findings)} findings total")
                    
                    # Write findings to JSONL file
                    try:
                        write_findings_to_jsonl(new_findings, 'output/alerts.jsonl')
                        logger.info(f"📝 Written {len(new_findings)} findings to output/alerts.jsonl")
                    except Exception as e:
                        logger.error(f"Error writing findings to JSONL: {str(e)}")
                    
                    # Also write compact Security Onion alerts to separate file
                    try:
                        write_compact_alerts_to_jsonl(new_findings, 'output/alerts_compact.jsonl')
                        logger.info(f"📝 Written compact alerts to output/alerts_compact.jsonl")
                    except Exception as e:
                        logger.error(f"Error writing compact alerts JSONL: {str(e)}")
                    
                    return new_findings
                else:
                    logger.info(f"ℹ️ No findings generated from correlation")
                    return []
            else:
                logger.info(f"ℹ️ No active alerts to correlate")
                return []
            
        except Exception as e:
            logger.error(f"Error in correlation delegation: {str(e)}")
            return []
    

    
    def generate_summary_report(self, findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Generate a summary report of current security status.
        
        Args:
            findings: Optional list of findings to summarize
            
        Returns:
            Dictionary with summary report
        """
        try:
            if findings is None:
                findings = self.processed_findings
            
            # Generate findings summary
            summary = generate_findings_summary(findings, "current session")
            
            # Add system status
            summary['system_status'] = self.get_system_status()
            
            # Backpressure disabled for project scope
            # summary['backpressure_status'] = self.backpressure_controller.get_status()
            
            # Add processing statistics
            summary['processing_stats'] = self.processing_stats.copy()
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating summary report: {str(e)}")
            return {
                'error': str(e),
                'summary': 'Failed to generate summary report',
                'total_findings': len(self.processed_findings)
            }
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status."""
        try:
            # Get detection engine status
            detection_status = self.detection_engine.get_model_status()
            
            return {
                'detection_engine': detection_status,
                'active_alerts': len(self.active_alerts),
                'processed_findings': len(self.processed_findings),
                'files_monitored': len(self.file_positions),
                'last_update': datetime.now().isoformat()
                # Backpressure disabled for project scope
                # 'backpressure': self.backpressure_controller.get_status()
            }
            
        except Exception as e:
            logger.error(f"Error getting system status: {str(e)}")
            return {
                'error': str(e),
                'status': 'error'
            }
    
    def cleanup_old_data(self, max_alerts: int = 10000, max_findings: int = 1000) -> Dict[str, int]:
        """
        Clean up old alerts and findings to prevent memory issues.
        
        Args:
            max_alerts: Maximum number of alerts to keep
            max_findings: Maximum number of findings to keep
            
        Returns:
            Dictionary with cleanup statistics
        """
        try:
            alerts_removed = 0
            findings_removed = 0
            
            # Clean up old alerts
            if len(self.active_alerts) > max_alerts:
                # Keep only the most recent alerts
                alerts_to_remove = len(self.active_alerts) - max_alerts
                self.active_alerts = self.active_alerts[-max_alerts:]
                alerts_removed = alerts_to_remove
            
            # Clean up old findings
            if len(self.processed_findings) > max_findings:
                # Keep only the most recent findings
                findings_to_remove = len(self.processed_findings) - max_findings
                self.processed_findings = self.processed_findings[-max_findings:]
                findings_removed = findings_to_remove
            
            # Clean up old IP profiles
            profiles_removed = self.detection_engine.prune_old_profiles()
            
            return {
                'alerts_removed': alerts_removed,
                'findings_removed': findings_removed,
                'profiles_removed': profiles_removed
            }
            
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
            return {
                'error': str(e),
                'alerts_removed': 0,
                'findings_removed': 0,
                'profiles_removed': 0
            }
    

    
    def get_ip_investigation_details(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get detailed investigation information for an IP address."""
        try:
            return self.correlation_engine.get_ip_investigation_details(ip_address, self.active_alerts)
        except Exception as e:
            logger.error(f"Error getting IP investigation details: {str(e)}")
            return None
    
    # Removed flood analysis methods as Redis ingestion makes them obsolete
    
    def get_active_alerts(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get current active alerts."""
        try:
            if limit:
                return self.active_alerts[-limit:]
            return self.active_alerts
        except Exception as e:
            logger.error(f"Error getting active alerts: {str(e)}")
            return []
    
    def get_processed_findings(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get processed findings."""
        try:
            if limit:
                return self.processed_findings[-limit:]
            return self.processed_findings
        except Exception as e:
            logger.error(f"Error getting processed findings: {str(e)}")
            return []
    
    def reset_session(self) -> Dict[str, Any]:
        """Reset the current session data."""
        try:
            alerts_cleared = len(self.active_alerts)
            findings_cleared = len(self.processed_findings)
            
            self.active_alerts.clear()
            self.processed_findings.clear()
            self.file_positions.clear()
            
            # Reset processing stats
            self.processing_stats = {
                'lines_processed': 0,
                'alerts_generated': 0,
                'last_processing_time': None,
                'processing_errors': 0
            }
            
            return {
                'success': True,
                'alerts_cleared': alerts_cleared,
                'findings_cleared': findings_cleared,
                'message': 'Session reset successfully'
            }
            
        except Exception as e:
            logger.error(f"Error resetting session: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _should_whitelist_event(self, event: Dict[str, Any]) -> bool:
        """Check if an event should be whitelisted (filtered out) as benign background traffic."""
        try:
            conn_details = event.get('connection_details', {})
            proto = conn_details.get('proto', '')
            orig_p = str(conn_details.get('id.orig_p', ''))
            resp_p = str(conn_details.get('id.resp_p', ''))
            
            # Whitelist for common network chatter protocols
            known_chatter_ports = {'5353', '5355', '1900', '123'}
            
            # Rule 1: Check for UDP-based chatter (mDNS, LLMNR, SSDP, NTP)
            if proto == 'udp':
                is_chatter = (resp_p in known_chatter_ports or orig_p in known_chatter_ports)
                is_dhcp = (orig_p == '68' and resp_p == '67')
                
                if is_chatter or is_dhcp:
                    return True  # Whitelist (filter out)
            
            # Rule 2: Ignore all standard ICMP management traffic
            if proto == 'icmp':
                return True  # Whitelist (filter out)
            
            return False  # Don't whitelist
            
        except Exception:
            return False  # Don't whitelist on error

    def process_backlog_on_startup(self, log_type: str = 'conn', max_backlog: int = 1000) -> Dict[str, Any]:
        """
        Process any existing backlog when the system starts up.
        
        Args:
            log_type: Type of log ('conn' or 'dns')
            max_backlog: Maximum backlog size to trigger processing
            
        Returns:
            Dictionary with processing results
        """
        try:
            # Connect to Redis using config
            r = self._create_redis_connection()
            redis_key = REDIS_KEYS.get(log_type, 'zeek_logs')  # Use configured key
            
            # Check backlog size
            backlog_size = r.llen(redis_key)
            logger.info(f" Checking Redis backlog: {backlog_size} logs in queue")
            
            if backlog_size == 0:
                return {'success': True, 'lines_processed': 0, 'alerts_generated': 0, 'message': 'No backlog to process'}
            
            if backlog_size < max_backlog:
                logger.info(f" Small backlog ({backlog_size} logs), will process in regular time window")
                return {'success': True, 'lines_processed': 0, 'alerts_generated': 0, 'message': 'Backlog too small, skip bulk processing'}
            
            # Process large backlog in chunks
            logger.info(f" Large backlog detected ({backlog_size} logs), starting bulk processing")
            total_processed = 0
            total_alerts = 0
            chunk_size = 500  # Process 500 logs per chunk
            
            while True:
                # Get chunk of logs using LPOP with count
                chunk_logs = r.lpop(redis_key, chunk_size)
                
                if not chunk_logs:
                    break
                
                # Convert single item to list if needed
                if isinstance(chunk_logs, str):
                    chunk_logs = [chunk_logs]
                
                #  OPTIMIZED: Process chunk using BATCH processing for maximum speed
                if log_type == 'conn':
                    chunk_result = self._process_conn_batch(chunk_logs)
                else:
                    chunk_result = self._process_dns_batch(chunk_logs)
                
                if chunk_result['success']:
                    total_processed += chunk_result['lines_processed']
                    total_alerts += chunk_result['alerts_generated']
                    logger.info(f" Processed chunk: {len(chunk_logs)} logs, total so far: {total_processed}")
                
                    time.sleep(0.01)
            
            logger.info(f" Backlog processing completed: {total_processed} logs processed, {total_alerts} alerts generated")
            return {
                'success': True,
                'lines_processed': total_processed,
                'alerts_generated': total_alerts,
                'message': f'Processed {total_processed} backlog logs'
            }
            
        except Exception as e:
            logger.error(f"Error processing backlog: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'lines_processed': 0,
                'alerts_generated': 0
            }

    def process_fifo_backlog_on_startup(self, max_backlog: int = 1000, processing_cycle_size: int = 1000) -> Dict[str, Any]:
        """
         NEW: Process backlog from both Redis keys using FIFO approach.
        
        Args:
            max_backlog: Maximum backlog size per key to trigger processing
            
        Returns:
            Dictionary with processing results
        """
        logger.info(f" Starting FIFO backlog processing for both log types")
        
        try:
            # Connect to Redis
            r = self._create_redis_connection()
            
            total_processed = 0
            total_alerts = 0
            backlog_stats = {}
            
            # Process backlog for each log type
            for log_type, redis_key in REDIS_KEYS.items():
                logger.info(f" Checking {log_type} backlog on key: {redis_key}")
                
                # Check backlog size
                backlog_size = r.llen(redis_key)
                backlog_stats[log_type] = backlog_size
                
                if backlog_size == 0:
                    logger.info(f" No {log_type} backlog to process")
                    continue
                
                if backlog_size < max_backlog:
                    logger.info(f" Small {log_type} backlog ({backlog_size} logs), will process in regular window")
                    continue
                
                # Process large backlog
                logger.info(f" Processing large {log_type} backlog: {backlog_size} logs")
                
                chunk_size = min(500, processing_cycle_size)  
                type_processed = 0
                type_alerts = 0
                
                while True:
                    # Get chunk of logs
                    chunk_logs = r.lpop(redis_key, chunk_size)
                    
                    if not chunk_logs:
                        break
                    
                    # Convert to list if needed
                    if isinstance(chunk_logs, str):
                        chunk_logs = [chunk_logs]
                    
                    # Add to FIFO queue for processing
                    for log_data in chunk_logs:
                        if self._add_to_fifo_queue(log_data, log_type):
                            type_processed += 1
                    
                    # Brief pause
                    #  OPTIMIZED: Minimal sleep for better performance
                    time.sleep(0.001)
                
                logger.info(f" {log_type} backlog queued: {type_processed} logs added to FIFO queue")
                total_processed += type_processed
            
            # Process queued logs using FIFO processing
            if total_processed > 0:
                logger.info(f" Processing {total_processed} queued logs from FIFO queues")
                
                # Process in larger batches for backlog
                processing_result = self._process_fifo_queues(max_logs_per_cycle=1000)
                
                if processing_result['success']:
                    total_alerts = processing_result['alerts_generated']
                    logger.info(f" FIFO backlog processing completed: {processing_result['logs_processed']} logs, {total_alerts} alerts")
                else:
                    logger.error(f" FIFO backlog processing failed: {processing_result.get('error', 'Unknown error')}")
            
            # Final statistics
            logger.info(f" FIFO backlog processing summary:")
            logger.info(f"  - Conn backlog: {backlog_stats.get('conn', 0)} logs")
            logger.info(f"  - DNS backlog: {backlog_stats.get('dns', 0)} logs")
            logger.info(f"  - Total queued: {total_processed} logs")
            logger.info(f"  - Total alerts: {total_alerts}")
            
            return {
                'success': True,
                'lines_processed': total_processed,
                'alerts_generated': total_alerts,
                'backlog_stats': backlog_stats,
                'message': f'Processed {total_processed} backlog logs using FIFO approach'
            }
            
        except Exception as e:
            logger.error(f"Error in FIFO backlog processing: {str(e)}")  #  FIXED: Consistent error format
            return {
                'success': False,
                'error': str(e),
                'lines_processed': 0,
                'alerts_generated': 0
            }



    def start_fifo_redis_monitoring(self, collection_window_seconds: int = 0.5, processing_cycle_size: int = 1000):
        """
          REAL-TIME: Start FIFO-based Redis monitoring with NON-BLOCKING dashboard updates.
        
        Args:
            collection_window_seconds: Time window for collecting logs from Redis
            processing_cycle_size: Number of logs to process in each cycle
        """
        logger.info(f" Starting REAL-TIME FIFO Redis monitoring")
        logger.info(f" Config: collection_window={collection_window_seconds}s, processing_cycle={processing_cycle_size}")
        logger.info(f"🔑 Redis keys: {REDIS_KEYS}")
        logger.info(f"⚖️ Priority: conn logs (weight: {FIFO_CONFIG['conn_processing_weight']}) > DNS logs (weight: {FIFO_CONFIG['dns_processing_weight']})")
        logger.info(f" FEATURE: Dashboard updates continuously, no blocking!")
        
        total_cycles = 0
        total_logs_collected = 0
        total_logs_processed = 0
        total_alerts_generated = 0
        
        try:
            r = self._create_redis_connection()
            logger.info(f" Redis connection established for monitoring")
        except Exception as e:
            logger.error(f"❌ Failed to create Redis connection: {e}")
            return
        
        try:
            while self.monitoring_active:  #  FIX: Check monitoring_active flag to allow stopping
                cycle_start = time.time()
                total_cycles += 1
                
                #  FIX: Double-check flag after each cycle for immediate response
                if not self.monitoring_active:
                    logger.info(f" Monitoring stopped by user after {total_cycles} cycles")
                    break
                
                # Fixed batch sizing (backpressure disabled for project scope)
                base_batch_size = min(processing_cycle_size, 200)
                batch_size = base_batch_size
                
                # Fixed collection window (backpressure disabled for project scope)
                base_collection_window = collection_window_seconds
                adaptive_collection_window = base_collection_window
                
                # STEP 1: Collect logs from Redis into FIFO queues with backpressure
                logger.debug(f" Cycle {total_cycles}: Collecting logs from Redis...")
                logger.debug(f"    BACKPRESSURE: Adaptive collection window: {adaptive_collection_window:.3f}s (base: {base_collection_window:.3f}s)")
                logger.debug(f"    BACKPRESSURE: Adaptive batch size: {batch_size} (base: {base_batch_size})")
                
                collection_result = self._collect_logs_from_redis_fifo(adaptive_collection_window)
                
                if collection_result['success']:
                    logs_collected = collection_result['total_collected']
                    total_logs_collected += logs_collected
                    
                    if logs_collected > 0:
                        logger.info(f" Cycle {total_cycles}: Collected {logs_collected} logs")
                        logger.info(f" Queue status: conn={collection_result['conn_queue_size']}, DNS={collection_result['dns_queue_size']}")
                    
                    # STEP 2: Process logs from FIFO queues in priority order (NON-BLOCKING)
                    if collection_result['total_queued'] > 0:
                        logger.debug(f" Cycle {total_cycles}: Processing queued logs...")
                        processing_result = self._process_fifo_queues(batch_size)  # Use smaller batch size
                        
                        if processing_result['success']:
                            logs_processed = processing_result['logs_processed']
                            alerts_generated = processing_result['alerts_generated']
                            
                            total_logs_processed += logs_processed
                            total_alerts_generated += alerts_generated
                            
                            logger.info(f" Cycle {total_cycles}: Processed {logs_processed} logs, {alerts_generated} alerts")
                            logger.info(f" Processing rate: {processing_result.get('processing_rate', 0):.1f} logs/sec")
                            
                            # Backpressure disabled; no adaptive processing rate update
                        else:
                            logger.error(f" Cycle {total_cycles} processing failed: {processing_result.get('error', 'Unknown error')}")
                    else:
                        logger.debug(f"⏭️ Cycle {total_cycles}: No logs to process")
                
                else:
                    logger.warning(f" Cycle {total_cycles} collection failed: {collection_result.get('error', 'Unknown error')}")
                
                #  NEW: Log cycle statistics with backpressure information
                cycle_duration = time.time() - cycle_start
                if total_cycles % 5 == 0:  # Log every 5 cycles for real-time demo
                    logger.info(f" REAL-TIME Session summary after {total_cycles} cycles:")
                    logger.info(f"  - Total collected: {total_logs_collected} logs")
                    logger.info(f"  - Total processed: {total_logs_processed} logs")
                    logger.info(f"  - Total alerts: {total_alerts_generated}")
                    logger.info(f"  - Current queues: conn={len(self.fifo_queues['conn'])}, DNS={len(self.fifo_queues['dns'])}")
                    logger.info(f"  - Average cycle time: {cycle_duration:.2f}s")
                    logger.info(f"  - Dashboard updates: CONTINUOUS (no blocking!)")
                    
                    # Backpressure status logging disabled for project scope
                
                #  REAL-TIME: Shorter cycles for continuous dashboard updates
                if collection_result.get('total_collected', 0) == 0:
                    time.sleep(0.001)  # Minimal pause for real-time updates
                else:
                    # If logs were collected, process immediately for real-time dashboard
                    time.sleep(0.005)  #  OPTIMIZED: Even faster for demo
                
        except KeyboardInterrupt:
            logger.info(f" REAL-TIME FIFO Redis monitoring stopped by user after {total_cycles} cycles")
            logger.info(f" Final session stats:")
            logger.info(f"  - Cycles completed: {total_cycles}")
            logger.info(f"  - Total logs collected: {total_logs_collected}")
            logger.info(f"  - Total logs processed: {total_logs_processed}")
            logger.info(f"  - Total alerts generated: {total_alerts_generated}")
            logger.info(f"  - Final queue status: conn={len(self.fifo_queues['conn'])}, DNS={len(self.fifo_queues['dns'])}")
            
        except Exception as e:
            logger.error(f" Fatal error in REAL-TIME FIFO monitoring: {str(e)}")
            raise
    
    def stop_monitoring(self) -> bool:
        """
         NEW: Stop monitoring and clean up resources.
        
        Returns:
            bool: True if monitoring was successfully stopped
        """
        try:
            if not self.monitoring_active:
                logger.info("ℹ️ Monitoring already stopped")
                return True
            
            logger.info(" Stopping monitoring...")
            self.monitoring_active = False
            
            #  FIX: Wait for monitoring thread to finish with proper timeout and force stop
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                logger.info("⏳ Waiting for monitoring thread to finish...")
                #  FIX: Increase timeout to 10 seconds for safer stopping
                self.monitoring_thread.join(timeout=10.0)
                
                if self.monitoring_thread.is_alive():
                    logger.warning(" Monitoring thread did not stop within 10s timeout, forcing stop...")
                    #  FIX: Force stop by setting flag and waiting again
                    self.monitoring_active = False
                    logger.info("⏳ Waiting additional 5 seconds for forced stop...")
                    self.monitoring_thread.join(timeout=5.0)
                    
                    if self.monitoring_thread.is_alive():
                        logger.error(" Thread still alive after force stop - potential resource leak!")
                        #  FIX: Log thread status for debugging
                        logger.error(f"Thread ID: {self.monitoring_thread.ident}, Name: {self.monitoring_thread.name}")
                    else:
                        logger.info(" Monitoring thread stopped successfully after force stop")
                else:
                    logger.info(" Monitoring thread stopped successfully within timeout")
            
            # Clean up thread reference
            self.monitoring_thread = None
            
            # Clear queues and reset stats
            self.fifo_queues['conn'].clear()
            self.fifo_queues['dns'].clear()
            self.queue_timestamps['conn'].clear()
            self.queue_timestamps['dns'].clear()
            
            logger.info(" Monitoring stopped and resources cleaned up")
            return True
            
        except Exception as e:
            logger.error(f" Error stopping monitoring: {str(e)}")
            return False
    
    def start_dual_log_monitoring(self, config: Dict[str, Any] = None):
        """
          FIX: Start monitoring both conn and DNS logs simultaneously with FIFO processing in BACKGROUND THREAD.
        
        Args:
            config: Configuration dictionary with keys:
                - collection_window_seconds: Time window for collection (default: 0.5)
                - processing_cycle_size: Logs per processing cycle (default: 1000)
                - enable_priority_processing: Enable conn log priority (default: True)
                - process_backlog_first: Process existing backlog before starting (default: True)
                - max_backlog_threshold: Threshold for backlog processing (default: 2000)
        """
        if config is None:
            config = {}
        
        collection_window = config.get('collection_window_seconds', 0.5)  #  OPTIMIZED: Default 0.5s
        processing_cycle = config.get('processing_cycle_size', 1000)    #  OPTIMIZED: Default 1000
        enable_priority = config.get('enable_priority_processing', True)
        process_backlog = config.get('process_backlog_first', True)
        max_backlog = config.get('max_backlog_threshold', 2000)
        
        # Update FIFO configuration
        FIFO_CONFIG['priority_processing'] = enable_priority
        
        #  FIX: Set monitoring active and store thread reference
        self.monitoring_active = True
        
        logger.info(f" Starting DUAL LOG monitoring (conn + DNS) in BACKGROUND THREAD")
        logger.info(f" Configuration:")
        logger.info(f"  - Collection window: {collection_window}s")
        logger.info(f"  - Processing cycle: {processing_cycle} logs")
        logger.info(f"  - Priority processing: {'Enabled' if enable_priority else 'Disabled'}")
        logger.info(f"  - Process backlog first: {'Yes' if process_backlog else 'No'}")
        logger.info(f"  - Redis keys: {REDIS_KEYS}")
        
        # STEP 1: Process existing backlog if requested
        if process_backlog:
            logger.info(f" Step 1: Processing existing backlog from both Redis keys...")
            backlog_result = self.process_fifo_backlog_on_startup(max_backlog, processing_cycle)
            
            if backlog_result['success'] and backlog_result['lines_processed'] > 0:
                logger.info(f" Backlog processing completed: {backlog_result['lines_processed']} logs, {backlog_result['alerts_generated']} alerts")
                logger.info(f" Backlog stats: {backlog_result['backlog_stats']}")
            else:
                logger.info(f"ℹ️ {backlog_result.get('message', 'No backlog processing needed')}")
        else:
            logger.info(f"⏭️ Skipping backlog processing as requested")
        
        #  FIX: STEP 2: Start FIFO monitoring in BACKGROUND THREAD
        logger.info(f" Step 2: Starting FIFO Redis monitoring in BACKGROUND THREAD...")
        
        #  FIX: Create and start monitoring thread
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_worker,
            args=(collection_window, processing_cycle),
            name="RedisMonitoringThread",
            daemon=True  # Daemon thread so it doesn't block app shutdown
        )
        
        self.monitoring_thread.start()
        logger.info(f" Background monitoring thread started: {self.monitoring_thread.name} (ID: {self.monitoring_thread.ident})")
        logger.info(f" Background monitoring is now ACTIVE - UI will remain responsive!")
        
        return {
            'success': True,
            'thread_name': self.monitoring_thread.name,
            'thread_id': self.monitoring_thread.ident,
            'message': 'Background monitoring started successfully'
        }
    
    def _monitoring_worker(self, collection_window_seconds: int, processing_cycle_size: int):
        """
         FIX: Background worker method that runs in separate thread.
        This method contains the actual monitoring logic that was previously in start_fifo_redis_monitoring.
        """
        logger.info(f" Background monitoring worker started: collection_window={collection_window_seconds}s, processing_cycle={processing_cycle_size}")
        
        total_cycles = 0
        total_logs_collected = 0
        total_logs_processed = 0
        total_alerts_generated = 0
        
        try:
            while self.monitoring_active:  # Check monitoring_active flag to allow stopping
                cycle_start = time.time()
                total_cycles += 1
                
                # Double-check flag after each cycle for immediate response
                if not self.monitoring_active:
                    logger.info(f" Background monitoring stopped by user after {total_cycles} cycles")
                    break
                
                # Process balanced batches for optimal real-time performance
                batch_size = min(processing_cycle_size, 200)  # Balanced batches for optimal performance
                
                # STEP 1: Collect logs from Redis into FIFO queues
                logger.debug(f" Cycle {total_cycles}: Collecting logs from Redis...")
                collection_result = self._collect_logs_from_redis_fifo(collection_window_seconds)
                
                if collection_result['success']:
                    logs_collected = collection_result['total_collected']
                    total_logs_collected += logs_collected
                    
                    if logs_collected > 0:
                        logger.info(f" Cycle {total_cycles}: Collected {logs_collected} logs")
                        logger.info(f" Queue status: conn={collection_result['conn_queue_size']}, DNS={collection_result['dns_queue_size']}")
                    
                    # STEP 2: Process logs from FIFO queues in priority order (NON-BLOCKING)
                    if collection_result['total_queued'] > 0:
                        logger.debug(f" Cycle {total_cycles}: Processing queued logs...")
                        processing_result = self._process_fifo_queues(batch_size)  # Use smaller batch size
                        
                        if processing_result['success']:
                            logs_processed = processing_result['logs_processed']
                            alerts_generated = processing_result['alerts_generated']
                            
                            total_logs_processed += logs_processed
                            total_alerts_generated += alerts_generated
                            
                            logger.info(f" Cycle {total_cycles}: Processed {logs_processed} logs, {alerts_generated} alerts")
                            logger.info(f" Processing rate: {processing_result.get('processing_rate', 0):.1f} logs/sec")
                        else:
                            logger.error(f" Cycle {total_cycles} processing failed: {processing_result.get('error', 'Unknown error')}")
                    else:
                        logger.debug(f"⏭️ Cycle {total_cycles}: No logs to process")
                
                else:
                    logger.warning(f" Cycle {total_cycles} collection failed: {collection_result.get('error', 'Unknown error')}")
                
                # Log cycle statistics more frequently for real-time monitoring
                cycle_duration = time.time() - cycle_start
                if total_cycles % 5 == 0:  # Log every 5 cycles
                    logger.info(f" Background monitoring summary after {total_cycles} cycles:")
                    logger.info(f"  - Total collected: {total_logs_collected} logs")
                    logger.info(f"  - Total processed: {total_logs_processed} logs")
                    logger.info(f"  - Total alerts: {total_alerts_generated}")
                    logger.info(f"  - Current queues: conn={len(self.fifo_queues['conn'])}, DNS={len(self.fifo_queues['dns'])}")
                    logger.info(f"  - Average cycle time: {cycle_duration:.2f}s")
                    logger.info(f"  - Background monitoring: ACTIVE (UI remains responsive!)")
                
                # Balanced cycles for optimal resource usage
                if collection_result.get('total_collected', 0) == 0:
                    time.sleep(0.01)   # Balanced pause to reduce CPU usage
                else:
                    # If logs were collected, process immediately for real-time dashboard
                    time.sleep(0.02)   # Balanced processing for optimal performance
                
        except Exception as e:
            logger.error(f" Fatal error in background monitoring worker: {str(e)}")
            # Don't raise here - just log the error and let the thread end gracefully
            logger.error(f"Background monitoring worker thread will stop due to error")
        finally:
            logger.info(f" Background monitoring worker thread ended after {total_cycles} cycles")
            logger.info(f" Final worker stats:")
            logger.info(f"  - Cycles completed: {total_cycles}")
            logger.info(f"  - Total logs collected: {total_logs_collected}")
            logger.info(f"  - Total logs processed: {total_logs_processed}")
            logger.info(f"  - Total alerts generated: {total_alerts_generated}")
            logger.info(f"  - Final queue status: conn={len(self.fifo_queues['conn'])}, DNS={len(self.fifo_queues['dns'])}")



    def get_dns_model_status(self) -> Dict[str, Any]:
        """Get comprehensive status of DNS detection capabilities."""
        try:
            dns_status = self.detection_engine.get_dns_model_status()
            return {
                'dns_detection_available': dns_status.get('dns_models_loaded', False),
                'components': dns_status,
                'ready_for_analysis': all(dns_status.values())
            }
        except Exception as e:
            logger.error(f"Error getting DNS model status: {str(e)}")
            return {
                'dns_detection_available': False,
                'error': str(e),
                'ready_for_analysis': False
            }

    def get_redis_log_stats(self) -> Dict[str, Any]:
        """Get current Redis log statistics."""
        try:
            total_logs = self.redis_log_stats['total_logs_received']
            accepted_logs = self.redis_log_stats['accepted_logs']
            filtered_logs = self.redis_log_stats['filtered_logs']
            
            acceptance_rate = (accepted_logs / total_logs * 100) if total_logs > 0 else 0
            filter_rate = (filtered_logs / total_logs * 100) if total_logs > 0 else 0
            
            return {
                'total_logs_received': total_logs,
                'accepted_logs': accepted_logs,
                'filtered_logs': filtered_logs,
                'acceptance_rate_percent': round(acceptance_rate, 2),
                'filter_rate_percent': round(filter_rate, 2),
                'logs_by_type': dict(sorted(self.redis_log_stats['logs_by_type'].items(), key=lambda x: x[1], reverse=True)),
                'logs_by_pipeline': dict(sorted(self.redis_log_stats['logs_by_pipeline'].items(), key=lambda x: x[1], reverse=True)),
                'last_reset_time': self.redis_log_stats['last_reset_time']
            }
        except Exception as e:
            logger.error(f"Error getting Redis log stats: {str(e)}")
            return {'error': str(e)}
    
    def get_fifo_stats(self) -> Dict[str, Any]:
        """
         NEW: Get comprehensive FIFO queue and processing statistics.
        
        Returns:
            Dictionary with FIFO statistics
        """
        try:
            # Calculate queue utilization
            conn_queue_size = len(self.fifo_queues['conn'])
            dns_queue_size = len(self.fifo_queues['dns'])
            total_queued = conn_queue_size + dns_queue_size
            
            # Calculate processing efficiency
            conn_priority = self.processing_priorities['conn']
            dns_priority = self.processing_priorities['dns']
            
            # Get FIFO processing statistics
            fifo_stats = self.redis_log_stats.get('fifo_processing_stats', {})
            
            # Calculate average processing time per log type
            avg_processing_time = {
                'conn': self.processing_stats.get('fifo_queue_stats', {}).get('conn_avg_time', 0),
                'dns': self.processing_stats.get('fifo_queue_stats', {}).get('dns_avg_time', 0)
            }
            
            return {
                'queue_status': {
                    'conn_queue_size': conn_queue_size,
                    'dns_queue_size': dns_queue_size,
                    'total_queued_logs': total_queued,
                    'queue_utilization_percent': round((total_queued / FIFO_CONFIG['max_queue_size']) * 100, 2)
                },
                'processing_priorities': {
                    'conn_weight': conn_priority,
                    'dns_weight': dns_priority,
                    'priority_ratio': f"{conn_priority}:{dns_priority}"
                },
                'fifo_processing_stats': {
                    'conn_processed_first': fifo_stats.get('conn_processed_first', 0),
                    'dns_processed_first': fifo_stats.get('dns_processed_first', 0),
                    'mixed_processing': fifo_stats.get('mixed_processing', 0),
                    'queue_overflow_events': fifo_stats.get('queue_overflow_events', 0)
                },
                'performance_metrics': {
                    'conn_avg_processing_time': avg_processing_time['conn'],
                    'dns_avg_processing_time': avg_processing_time['dns'],
                    'total_processing_cycles': self.processing_stats.get('fifo_queue_stats', {}).get('total_cycles', 0)
                },
                'configuration': {
                    'max_queue_size': FIFO_CONFIG['max_queue_size'],
                    'processing_batch_size': FIFO_CONFIG['processing_batch_size'],
                    'priority_processing_enabled': FIFO_CONFIG['priority_processing']
                }
            }
            
        except Exception as e:
            logger.error(f" Error getting FIFO stats: {str(e)}")
            return {'error': str(e)}
    
    def reset_fifo_stats(self):
        """ NEW: Reset FIFO processing statistics."""
        try:
            # Reset FIFO processing stats
            self.redis_log_stats['fifo_processing_stats'] = {
                'conn_processed_first': 0,
                'dns_processed_first': 0,
                'mixed_processing': 0,
                'queue_overflow_events': 0
            }
            
            # Reset queue stats
            self.processing_stats['fifo_queue_stats'] = {
                'conn_queue_size': 0,
                'dns_queue_size': 0,
                'total_queued_logs': 0,
                'processing_order_violations': 0,
                'total_cycles': 0,
                'conn_avg_time': 0,
                'dns_avg_time': 0
            }
            

            
            logger.info(" FIFO statistics reset successfully")
            
        except Exception as e:
            logger.error(f" Error resetting FIFO stats: {str(e)}")
    
    def reset_redis_log_stats(self):
        """Reset Redis log statistics."""
        self.redis_log_stats = {
            'total_logs_received': 0,
            'logs_by_type': {},
            'logs_by_pipeline': {},
            'filtered_logs': 0,
            'accepted_logs': 0,
            'last_reset_time': time.time()
        }
        logger.info(" Redis log statistics reset")



    def get_model_status(self) -> Dict[str, Any]:
        """Get the status of all ML models and detection components."""
        try:
            detection_status = self.detection_engine.get_model_status()
            ml_status = detection_status.get('ml_handler', {})
            
            # Get DNS model status separately
            dns_status = self.detection_engine.get_dns_model_status()
            
            return {
                'models_loaded': any([
                    ml_status.get('isolation_forest', False),
                    ml_status.get('autoencoder', False),
                    ml_status.get('preprocessor', False)
                ]),
                'isolation_forest': ml_status.get('isolation_forest', False),
                'autoencoder': ml_status.get('autoencoder', False),
                'preprocessor': ml_status.get('preprocessor', False),
                'shap_available': ml_status.get('shap_available', False),
                'tensorflow_available': ml_status.get('tensorflow_available', False),
                'dns_models': dns_status.get('dns_models_loaded', False),
                'detection_engine': detection_status
            }
        except Exception as e:
            logger.error(f"Error getting model status: {str(e)}")
            return {
                'models_loaded': False,
                'isolation_forest': False,
                'autoencoder': False,
                'preprocessor': False,
                'error': str(e)
            }

    

    def run_cognitive_soc_analysis(self, finding_id: str, session_state):
        """Triggers CognitiveSOC analysis for a single finding on-demand."""
        if not self.llm_client:
            self._show_ui_message('error', "LLM client not initialized. Please check if the LLM server is running on localhost:8080")
            return
        
        findings = session_state.get('findings', {}) if hasattr(session_state, 'get') else getattr(session_state, 'findings', {})
        if finding_id in findings:
            finding = findings[finding_id]
            
            try:
                # Đánh dấu là đang xử lý để UI có thể hiển thị spinner
                finding['ai_analysis_status'] = 'running' 
                
                pre_report = self.correlation_engine.summarize_finding_for_llm(finding)
                analysis_result = get_hypothesis_from_llm(pre_report, self.llm_client)
                
                # THÊM DÒNG NÀY: Lưu lại "ngữ cảnh" của lần phân tích này
                if analysis_result and analysis_result.get('status') == 'success':
                    analysis_result['analyzed_evidence_count'] = finding.get('evidence_count', 0)
                
                # Cập nhật kết quả và trạng thái
                finding['ai_analysis'] = analysis_result
                finding['ai_analysis_status'] = 'complete'
                
                # CRITICAL: Log the analysis result to verify it's being saved
                logger.info(f"AI Analysis completed for finding {finding_id}")
                logger.info(f"Analysis status: {analysis_result.get('status')}")
                logger.info(f"Has intelligence_analysis: {'intelligence_analysis' in analysis_result}")
                
                if analysis_result.get('status') == 'success':
                    self._show_ui_message('success', " CognitiveSOC analysis completed successfully!")
                else:
                    self._show_ui_message('warning', f" CognitiveSOC analysis completed with issues: {analysis_result.get('error_message', 'Unknown error')}")
                    
            except Exception as e:
                finding['ai_analysis_status'] = 'error'
                finding['ai_analysis'] = {
                    'status': 'error',
                    'error_message': str(e),
                    'analysis_timestamp': datetime.now().isoformat()
                }
                self._show_ui_message('error', f" Error during CognitiveSOC analysis: {str(e)}")
                logger.error(f"CognitiveSOC analysis error: {str(e)}")
        else:
            self._show_ui_message('error', f"Finding ID {finding_id} not found.")

    def _debug_log_features(self, log_lines: List[str], alerts: List[Dict[str, Any]], log_type: str) -> None:
        """
        Debug function to log raw features and z-score features to debug.json file.
        This helps trace whether raw features are still 0 or correctly calculated.
        
        Args:
            log_lines: Original log lines processed
            alerts: Alerts generated from processing
            log_type: Type of log ('conn' or 'dns')
        """
        try:
            debug_file_path = 'output/debug.json'
            
            # Read existing debug data
            debug_data = {}
            if os.path.exists(debug_file_path):
                try:
                    with open(debug_file_path, 'r', encoding='utf-8') as f:
                        debug_data = json.load(f)
                except Exception:
                    debug_data = {}
            
            # Initialize structure if needed
            if 'debug_info' not in debug_data:
                debug_data['debug_info'] = {
                    'created_at': datetime.now().isoformat(),
                    'description': 'Debug file to track batch processing and raw features',
                    'purpose': 'Monitor whether raw features are still 0 or correctly calculated'
                }
            
            if 'batch_processing_logs' not in debug_data:
                debug_data['batch_processing_logs'] = []
            
            if 'feature_transformation_debug' not in debug_data:
                debug_data['feature_transformation_debug'] = []
            
            # Create debug entry for this batch
            batch_entry = {
                'timestamp': datetime.now().isoformat(),
                'log_type': log_type,
                'batch_size': len(log_lines),
                'alerts_generated': len(alerts),
                'sample_log_line': log_lines[0][:200] if log_lines else '',  # First 200 chars
                'sample_alert_features': {}
            }
            
            # Extract features from first alert (if any)
            if alerts and len(alerts) > 0:
                sample_alert = alerts[0]
                
                # Extract raw features
                raw_features = {
                    'horizontal_scan_unique_dst_ip_count': sample_alert.get('horizontal_scan_unique_dst_ip_count', 'MISSING'),
                    'horizontal_scan_problematic_ratio': sample_alert.get('horizontal_scan_problematic_ratio', 'MISSING'),
                    'vertical_scan_unique_dst_port_count': sample_alert.get('vertical_scan_unique_dst_port_count', 'MISSING'),
                    'vertical_scan_problematic_ratio': sample_alert.get('vertical_scan_problematic_ratio', 'MISSING'),
                    'beacon_group_count': sample_alert.get('beacon_group_count', 'MISSING'),
                    'beacon_group_cv': sample_alert.get('beacon_group_cv', 'MISSING'),
                    'beacon_channel_timediff_std': sample_alert.get('beacon_channel_timediff_std', 'MISSING'),
                    'beacon_channel_duration_std': sample_alert.get('beacon_channel_duration_std', 'MISSING'),
                    'beacon_channel_orig_bytes_std': sample_alert.get('beacon_channel_orig_bytes_std', 'MISSING'),
                    'ddos_group_unique_src_ip_count': sample_alert.get('ddos_group_unique_src_ip_count', 'MISSING')
                }
                
                # Extract z-score features
                z_features = {
                    'z_horizontal_unique_dst_ip_count': sample_alert.get('z_horizontal_unique_dst_ip_count', 'MISSING'),
                    'z_horizontal_problematic_ratio': sample_alert.get('z_horizontal_problematic_ratio', 'MISSING'),
                    'z_vertical_unique_dst_port_count': sample_alert.get('z_vertical_unique_dst_port_count', 'MISSING'),
                    'z_vertical_problematic_ratio': sample_alert.get('z_vertical_problematic_ratio', 'MISSING'),
                    'z_beacon_group_count': sample_alert.get('z_beacon_group_count', 'MISSING'),
                    'z_ddos_group_unique_src_ip_count': sample_alert.get('z_ddos_group_unique_src_ip_count', 'MISSING'),
                    'z_beacon_channel_timediff_std': sample_alert.get('z_beacon_channel_timediff_std', 'MISSING'),
                    'z_beacon_channel_duration_std': sample_alert.get('z_beacon_channel_duration_std', 'MISSING'),
                    'z_beacon_channel_orig_bytes_std': sample_alert.get('z_beacon_channel_orig_bytes_std', 'MISSING')
                }
                
                batch_entry['sample_alert_features'] = {
                    'raw_features': raw_features,
                    'z_score_features': z_features,
                    'alert_id': sample_alert.get('alert_id', 'unknown'),
                    'src_ip': sample_alert.get('src_ip', 'unknown'),
                    'dst_ip': sample_alert.get('dst_ip', 'unknown')
                }
                
                # Count non-zero raw features
                non_zero_raw = sum(1 for v in raw_features.values() if v != 0 and v != 'MISSING')
                present_z_features = sum(1 for v in z_features.values() if v != 'MISSING')
                
                batch_entry['feature_analysis'] = {
                    'non_zero_raw_features': non_zero_raw,
                    'total_raw_features': len(raw_features),
                    'present_z_features': present_z_features,
                    'total_z_features': len(z_features),
                    'raw_features_percentage': round((non_zero_raw / len(raw_features)) * 100, 1),
                    'z_features_percentage': round((present_z_features / len(z_features)) * 100, 1)
                }
            
            # Add to debug data
            debug_data['batch_processing_logs'].append(batch_entry)
            debug_data['last_updated'] = datetime.now().isoformat()
            
            # Keep only last 50 entries to prevent file from growing too large
            if len(debug_data['batch_processing_logs']) > 50:
                debug_data['batch_processing_logs'] = debug_data['batch_processing_logs'][-50:]
            
            # Write debug data back to file
            with open(debug_file_path, 'w', encoding='utf-8') as f:
                json.dump(debug_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"📝 Debug features logged to {debug_file_path}")
            if 'feature_analysis' in batch_entry:
                analysis = batch_entry['feature_analysis']
                logger.info(f"🔍 Feature analysis: {analysis['non_zero_raw_features']}/{analysis['total_raw_features']} raw features non-zero ({analysis['raw_features_percentage']}%)")
                logger.info(f"🔍 Z-score analysis: {analysis['present_z_features']}/{analysis['total_z_features']} z-features present ({analysis['z_features_percentage']}%)")
            
        except Exception as e:
            logger.error(f"Error in debug feature logging: {e}")

