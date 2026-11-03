#!/usr/bin/env python3
"""Render shared nginx structure with deployment-specific PID and log paths."""
import sys
from pathlib import Path

if len(sys.argv) != 5:
    raise SystemExit("usage: render-nginx-config.py TEMPLATE OUTPUT PID_PATH ERROR_LOG_PATH")

template, output, pid_path, error_log = map(Path, sys.argv[1:])
content = template.read_text()
content = content.replace("{{pid_path}}", str(pid_path))
content = content.replace("{{error_log_path}}", str(error_log))
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(content)
