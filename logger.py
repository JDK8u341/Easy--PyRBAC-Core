import logging
import json
import threading
from datetime import datetime

# 辅助类，写log的无情机器
class Logger:
    __slots__ = ['_lock', 'logger']

    def __init__(self, logger_name, save_file) -> None:
        # 配置log
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)
        # 创建日志处理器
        file_handler = logging.FileHandler(save_file)
        file_handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(file_handler)

        # 添加控制台日志
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(console_handler)
        self._lock = threading.RLock()

    # 辅助函数，写log的无情机器
    def audit_log(self, event_type, details, level=None):
        with self._lock:  # 加锁
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "event_type": event_type,
                **details
            }
            if level is None:
                self.logger.info(json.dumps(log_entry))
            else:
                self.logger.error(json.dumps(log_entry))

Loggers = Logger('security_audit','./security.json.log')  # 不想改了就直接初始化了。。。