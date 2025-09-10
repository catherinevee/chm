"""
Monitoring package - SNMP, SSH, and API monitoring handlers
"""

# Import handlers conditionally to avoid import errors during development
__all__ = []

try:
    from backend.monitoring.snmp_handler import SNMPHandler
    __all__.append('SNMPHandler')
except ImportError as e:
    import logging
    logging.warning(f"Could not import SNMPHandler: {e}")
    SNMPHandler = None

try:
    from backend.monitoring.ssh_handler import SSHHandler, SSHConnectionException
    __all__.extend(['SSHHandler', 'SSHConnectionException'])
except ImportError as e:
    import logging
    logging.warning(f"Could not import SSHHandler: {e}")
    SSHHandler = None
    SSHConnectionException = None