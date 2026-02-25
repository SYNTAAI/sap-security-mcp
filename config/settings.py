"""
MCP Server Configuration
Load all settings from environment variables via .env file.
"""
import os
from dotenv import load_dotenv

# Load .env file from mcp directory
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

# JCo Service (existing Syntasec JCo microservice)
JCO_SERVICE_URL = os.getenv("JCO_SERVICE_URL", "http://localhost:8080")
JCO_SERVICE_API_KEY = os.getenv("JCO_SERVICE_API_KEY", "")

# SAP Communication User (one comm user for all SAP calls)
SAP_HOST = os.getenv("SAP_HOST", "")
SAP_SYSNR = os.getenv("SAP_SYSNR", "00")
SAP_CLIENT = os.getenv("SAP_CLIENT", "100")
SAP_USER = os.getenv("SAP_USER", "")
SAP_PASSWORD = os.getenv("SAP_PASSWORD", "")

# MCP Server Auth (simple username/password table)
MCP_SECRET_KEY = os.getenv("MCP_SECRET_KEY", "syntaai-mcp-secret-2025")

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
