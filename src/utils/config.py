import os
import yaml
from typing import Dict, Any
from pathlib import Path

def load_config() -> Dict[str, Any]:
    """
    Load and validate the configuration from config.yaml and environment variables.
    
    Returns:
        Dict[str, Any]: The validated configuration dictionary
    """
    config_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found at {config_path}")
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Replace environment variables
    config = _replace_env_vars(config)
    
    # Validate required configurations
    _validate_config(config)
    
    return config

def _replace_env_vars(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively replace environment variable placeholders in the configuration.
    
    Args:
        config: The configuration dictionary
        
    Returns:
        Dict[str, Any]: Configuration with environment variables replaced
    """
    if isinstance(config, dict):
        return {key: _replace_env_vars(value) for key, value in config.items()}
    elif isinstance(config, list):
        return [_replace_env_vars(item) for item in config]
    elif isinstance(config, str) and config.startswith("${") and config.endswith("}"):
        env_var = config[2:-1]
        if env_var not in os.environ:
            raise ValueError(f"Required environment variable {env_var} not set")
        return os.environ[env_var]
    return config

def _validate_config(config: Dict[str, Any]) -> None:
    """
    Validate the configuration structure and required fields.
    
    Args:
        config: The configuration dictionary to validate
        
    Raises:
        ValueError: If required configuration is missing or invalid
    """
    required_sections = [
        "elasticsearch",
        "postgresql",
        "redis",
        "ingestion",
        "analysis",
        "visualization",
        "alerts",
        "logging",
        "security"
    ]
    
    for section in required_sections:
        if section not in config:
            raise ValueError(f"Missing required configuration section: {section}")
    
    # Validate Elasticsearch configuration
    es_config = config["elasticsearch"]
    if not es_config.get("hosts"):
        raise ValueError("Elasticsearch hosts not configured")
    
    # Validate PostgreSQL configuration
    pg_config = config["postgresql"]
    required_pg_fields = ["host", "port", "database", "user", "password"]
    for field in required_pg_fields:
        if not pg_config.get(field):
            raise ValueError(f"Missing required PostgreSQL configuration: {field}")
    
    # Validate Redis configuration
    redis_config = config["redis"]
    required_redis_fields = ["host", "port"]
    for field in required_redis_fields:
        if not redis_config.get(field):
            raise ValueError(f"Missing required Redis configuration: {field}")
    
    # Validate security configuration
    security_config = config["security"]
    if not security_config.get("jwt_secret"):
        raise ValueError("JWT secret not configured")
    
    # Validate alert channels
    alert_config = config["alerts"]
    if not any(channel.get("enabled") for channel in alert_config["channels"].values()):
        raise ValueError("At least one alert channel must be enabled") 