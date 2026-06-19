from __future__ import annotations

import faulthandler
import logging
import os
import sys
from typing import Any

from colink_ws_debugger.identity_store import data_dir

LOG_LEVEL_ENV = "COLINK_WS_DEBUGGER_LOG_LEVEL"
LOG_FILE_NAME = "debugger.log"
FAULT_LOG_HANDLE: Any = None


def log_path() -> str:
    return str(data_dir() / LOG_FILE_NAME)


def configure_logging() -> None:
    global FAULT_LOG_HANDLE
    path = data_dir() / LOG_FILE_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    FAULT_LOG_HANDLE = path.open("a", encoding="utf-8")
    faulthandler.enable(file=FAULT_LOG_HANDLE, all_threads=True)
    level_name = os.environ.get(LOG_LEVEL_ENV, "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(threadName)s %(message)s")
    file_handler = logging.FileHandler(path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    logging.basicConfig(level=level, handlers=[file_handler, console_handler], force=True)
    sys.excepthook = log_unhandled_exception
    logging.info("CoLink WebSocket Debugger starting")
    logging.info("data_dir=%s", data_dir())
    logging.info("python=%s", sys.version.replace("\n", " "))


def log_unhandled_exception(exc_type: type[BaseException], exc: BaseException, tb: Any) -> None:
    logging.critical("unhandled exception", exc_info=(exc_type, exc, tb))
