import logging
import os
from datetime import datetime


def setup_logging():
    """Configura el sistema de logging."""
    access_logger = logging.getLogger('access')
    if access_logger.handlers:
        return access_logger

    if not os.path.exists('logs'):
        os.makedirs('logs')

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(
                f'logs/app_{datetime.now().strftime("%Y%m%d")}.log',
                encoding='utf-8'
            ),
            logging.StreamHandler()
        ]
    )

    access_handler = logging.FileHandler('logs/accesos.log', encoding='utf-8')
    access_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    access_logger.addHandler(access_handler)
    access_logger.setLevel(logging.INFO)
    access_logger.propagate = False

    return access_logger
