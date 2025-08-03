"""
Logging Utilities

This module provides structured logging functionality for the OpenVAS CLI scanner.
"""

import logging
import logging.handlers
import sys
import os
from typing import Optional
from pathlib import Path


class ColoredFormatter(logging.Formatter):
    """Colored log formatter for console output."""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\\033[36m',      # Cyan
        'INFO': '\\033[32m',       # Green
        'WARNING': '\\033[33m',    # Yellow
        'ERROR': '\\033[31m',      # Red
        'CRITICAL': '\\033[35m',   # Magenta
        'RESET': '\\033[0m'        # Reset
    }
    
    def format(self, record):
        """Format log record with colors."""
        # Add color to levelname
        if record.levelname in self.COLORS:
            record.levelname = (
                f"{self.COLORS[record.levelname]}{record.levelname}"
                f"{self.COLORS['RESET']}"
            )
        
        return super().format(record)


class ScannerLogger:
    """Main logger class for the OpenVAS CLI scanner."""
    
    def __init__(self, name: str = "openvas_cli_scanner"):
        """
        Initialize the scanner logger.
        
        Args:
            name: Logger name
        """
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_default_handlers()
    
    def _setup_default_handlers(self):
        """Set up default console handler."""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # Use colored formatter for console
        console_formatter = ColoredFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        
        self.logger.addHandler(console_handler)
    
    def setup_file_logging(self, log_file: Optional[str] = None, 
                          max_size: int = 10 * 1024 * 1024,  # 10MB
                          backup_count: int = 5):
        """
        Set up file logging with rotation.
        
        Args:
            log_file: Path to log file (default: openvas_scanner.log)
            max_size: Maximum log file size in bytes
            backup_count: Number of backup files to keep
        """
        if log_file is None:
            log_file = "openvas_scanner.log"
        
        # Create log directory if it doesn't exist
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Set up rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_size, backupCount=backup_count
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Use plain formatter for file (no colors)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        
        self.logger.addHandler(file_handler)
    
    def set_level(self, level: str):
        """
        Set logging level.
        
        Args:
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        numeric_level = getattr(logging, level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(f'Invalid log level: {level}')
        
        self.logger.setLevel(numeric_level)
        
        # Also update console handler level
        for handler in self.logger.handlers:
            if isinstance(handler, logging.StreamHandler) and handler.stream == sys.stdout:
                handler.setLevel(numeric_level)
    
    def set_verbose(self, verbose: bool):
        """
        Enable or disable verbose logging.
        
        Args:
            verbose: True to enable DEBUG level, False for INFO level
        """
        if verbose:
            self.set_level('DEBUG')
        else:
            self.set_level('INFO')
    
    def get_logger(self) -> logging.Logger:
        """Get the underlying logger instance."""
        return self.logger


# Global logger instance
_scanner_logger = None


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (uses module name if None)
        
    Returns:
        Logger instance
    """
    global _scanner_logger
    
    if _scanner_logger is None:
        _scanner_logger = ScannerLogger()
    
    if name:
        return logging.getLogger(name)
    else:
        return _scanner_logger.get_logger()


def setup_logging(verbose: bool = False, 
                 log_file: Optional[str] = None,
                 quiet: bool = False):
    """
    Set up logging for the scanner application.
    
    Args:
        verbose: Enable verbose (DEBUG) logging
        log_file: Path to log file for file logging
        quiet: Suppress console output (only log to file)
    """
    global _scanner_logger
    
    _scanner_logger = ScannerLogger()
    
    if verbose:
        _scanner_logger.set_verbose(True)
    
    if log_file:
        _scanner_logger.setup_file_logging(log_file)
    
    if quiet:
        # Remove console handlers
        logger = _scanner_logger.get_logger()
        handlers_to_remove = []
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler) and handler.stream == sys.stdout:
                handlers_to_remove.append(handler)
        
        for handler in handlers_to_remove:
            logger.removeHandler(handler)


def log_scan_start(targets: list, ports: str, output_file: str):
    """Log scan start information."""
    logger = get_logger()
    logger.info("=" * 60)
    logger.info("OpenVAS CLI Scanner - Scan Started")
    logger.info("=" * 60)
    logger.info(f"Targets: {len(targets)} target(s)")
    logger.info(f"Ports: {ports}")
    logger.info(f"Output: {output_file}")
    logger.info("-" * 60)


def log_scan_complete(duration: float, results_count: int):
    """Log scan completion information."""
    logger = get_logger()
    logger.info("-" * 60)
    logger.info(f"Scan completed in {duration:.2f} seconds")
    logger.info(f"Found {results_count} vulnerability findings")
    logger.info("=" * 60)


def log_progress(current: int, total: int, message: str = ""):
    """Log progress information."""
    logger = get_logger()
    percentage = (current / total) * 100 if total > 0 else 0
    progress_msg = f"Progress: {current}/{total} ({percentage:.1f}%)"
    if message:
        progress_msg += f" - {message}"
    logger.info(progress_msg)


def log_error_with_context(error: Exception, context: str):
    """Log error with additional context."""
    logger = get_logger()
    logger.error(f"{context}: {type(error).__name__}: {error}")
    logger.debug(f"Error details:", exc_info=True)


class ScanProgressLogger:
    """Context manager for logging scan progress."""
    
    def __init__(self, operation: str, total_items: int = 0):
        """
        Initialize progress logger.
        
        Args:
            operation: Description of the operation
            total_items: Total number of items to process
        """
        self.operation = operation
        self.total_items = total_items
        self.current_item = 0
        self.logger = get_logger()
    
    def __enter__(self):
        """Enter the context manager."""
        self.logger.info(f"Starting {self.operation}...")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context manager."""
        if exc_type is None:
            self.logger.info(f"Completed {self.operation}")
        else:
            self.logger.error(f"Failed {self.operation}: {exc_val}")
    
    def update(self, increment: int = 1, message: str = ""):
        """Update progress."""
        self.current_item += increment
        if self.total_items > 0:
            log_progress(self.current_item, self.total_items, message)
        else:
            progress_msg = f"{self.operation}: {self.current_item} completed"
            if message:
                progress_msg += f" - {message}"
            self.logger.info(progress_msg)
    
    def set_total(self, total: int):
        """Set total number of items."""
        self.total_items = total


if __name__ == "__main__":
    # Test the logging functionality
    setup_logging(verbose=True, log_file="test.log")
    
    logger = get_logger()
    
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")
    
    # Test progress logging
    with ScanProgressLogger("Test Operation", 5) as progress:
        for i in range(5):
            progress.update(message=f"Processing item {i+1}")
    
    print("\\nLogging test completed. Check test.log for file output.")

