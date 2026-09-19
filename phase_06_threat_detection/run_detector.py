#!/usr/bin/env python3
"""
NetSleuth AI - Phase 6 Threat Detector Standalone Launcher
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from phase_06_threat_detection.cli import main

if __name__ == "__main__":
    main()
