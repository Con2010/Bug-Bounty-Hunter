#!/usr/bin/env python3
"""
File Utility Functions

This module provides utility functions for file operations.
"""

import logging
import os
import yaml
from typing import Dict, Any, Optional

logger = logging.getLogger("bug_bounty_hunter.utils.file")

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from a YAML file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Dictionary containing configuration parameters
        
    Raises:
        FileNotFoundError: If the configuration file does not exist
        yaml.YAMLError: If the configuration file is not valid YAML
    """
    logger.debug(f"Loading configuration from {config_path}")
    
    if not os.path.exists(config_path):
        logger.error(f"Configuration file not found: {config_path}")
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        
        logger.debug(f"Successfully loaded configuration from {config_path}")
        return config or {}
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML configuration: {e}")
        raise
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        raise

def save_config(config: Dict[str, Any], config_path: str) -> bool:
    """
    Save configuration to a YAML file.
    
    Args:
        config: Dictionary containing configuration parameters
        config_path: Path to save the configuration file
        
    Returns:
        Boolean indicating success or failure
    """
    logger.debug(f"Saving configuration to {config_path}")
    
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
        
        logger.debug(f"Successfully saved configuration to {config_path}")
        return True
    except Exception as e:
        logger.error(f"Error saving configuration: {e}")
        return False

def ensure_directory(directory_path: str) -> bool:
    """
    Ensure that a directory exists, creating it if necessary.
    
    Args:
        directory_path: Path to the directory
        
    Returns:
        Boolean indicating success or failure
    """
    logger.debug(f"Ensuring directory exists: {directory_path}")
    
    try:
        os.makedirs(directory_path, exist_ok=True)
        logger.debug(f"Directory exists or was created: {directory_path}")
        return True
    except Exception as e:
        logger.error(f"Error creating directory {directory_path}: {e}")
        return False