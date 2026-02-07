#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Client Logging — Rotating file + console logger with ms timestamps.

RotatingFileHandler (10 MB × 5 backups), UTF-8 encoding.
CustomFormatter adds millisecond-precision timestamps.

Key exports:
  setup_logging()            — configure 'cloud-client' logger
  get_logger()               — retrieve logger instance
  setup_pil_logging_silence() — suppress PIL noise
  LoggingManager             — OOP wrapper: initialize(), get_logger()
"""

import logging
import datetime as dt
from logging.handlers import RotatingFileHandler

from client_constants import (
    LOG_FILE, LOG_MAX_BYTES, LOG_BACKUP_COUNT, LOG_ENCODING,
    LOG_TIME_FORMAT
)

# ===================== LOGGING SETUP ===================== #

class CustomFormatter(logging.Formatter):
    """High-precision timestamp formatter for detailed logging"""
    def formatTime(self, record, datefmt=None):
        return dt.datetime.fromtimestamp(record.created).strftime(
            datefmt or LOG_TIME_FORMAT)[:-3]

def setup_logging() -> bool:
    """Initialize modern rotating file logger with console output"""
    try:
        # Configure root logger to be quiet, use only our logger
        logging.getLogger().setLevel(logging.WARNING)
        
        # Setup application logger
        logger = logging.getLogger('cloud-client')
        logger.setLevel(logging.INFO)
        logger.propagate = False
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # Create handlers with optimized configuration
        handlers = [
            RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding=LOG_ENCODING),
            logging.StreamHandler()
        ]
        
        # Apply formatting to all handlers
        formatter = CustomFormatter('%(asctime)s [%(levelname)s] %(message)s')
        for handler in handlers:
            handler.setLevel(logging.INFO)
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        global LOGGER
        LOGGER = logger
        logger.info("Logging sistemi başlatıldı")
        return True
        
    except Exception as e:
        # Logging başlatma hatası - sessizce devam et
        print(f"Logging setup error: {e}")
        return False

def get_logger():
    """Get the application logger instance"""
    try:
        return logging.getLogger('cloud-client')
    except:
        # Fallback to basic logging if main logger is not available
        return logging.getLogger()

def setup_pil_logging_silence():
    """Suppress PIL logging noise"""
    try:
        logging.getLogger('PIL').setLevel(logging.WARNING)
    except:
        pass

# Initialize global logger
LOGGER = None

class LoggingManager:
    """Central logging manager"""
    
    def __init__(self):
        self.logger = None
        self.setup_complete = False
        
    def initialize(self) -> bool:
        """Initialize the logging system"""
        try:
            self.setup_complete = setup_logging()
            if self.setup_complete:
                self.logger = get_logger()
                setup_pil_logging_silence()
            return self.setup_complete
        except Exception as e:
            print(f"LoggingManager initialization error: {e}")
            return False
    
    def get_logger(self):
        """Get logger instance"""
        if not self.setup_complete:
            self.initialize()
        return self.logger or get_logger()
    
    def log(self, message: str, level: str = "info"):
        """Log a message with specified level"""
        try:
            logger = self.get_logger()
            if logger:
                getattr(logger, level.lower(), logger.info)(message)
        except Exception as e:
            print(f"Logging error: {e}")