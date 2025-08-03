"""
CLI Module

This module provides the command-line interface for the OpenVAS CLI scanner.
"""

from .parser import (
    ScannerArgumentParser,
    create_parser,
    parse_command_line
)

from .main import (
    CLIApplication,
    main,
    console_entry_point
)

__all__ = [
    # Argument parsing
    'ScannerArgumentParser',
    'create_parser',
    'parse_command_line',
    
    # Main application
    'CLIApplication',
    'main',
    'console_entry_point'
]

