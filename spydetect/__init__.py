"""spydetect - detect host surveillance indicators."""

from .core import (
    CAMERA_MIC_DEVICES,
    EXPECTED_LISTENERS,
    SUSPICIOUS_NAMES,
    Connection,
    Finding,
    Process,
    analyse,
    score_connection,
    score_process,
    shannon_entropy,
)

__version__ = "0.1.0"
__all__ = [
    "Process", "Connection", "Finding", "analyse", "score_process",
    "score_connection", "shannon_entropy", "SUSPICIOUS_NAMES",
    "CAMERA_MIC_DEVICES", "EXPECTED_LISTENERS",
]
