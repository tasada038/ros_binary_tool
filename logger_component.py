#-----------------------------------------------------------------------------------
# MIT License

# Copyright (c) 2024 Takumi Asada

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#-----------------------------------------------------------------------------------

#-----------------------------------------------------------------------------------#
# ----------------------------------- Import  --------------------------------------#
#-----------------------------------------------------------------------------------#
import os
import logging
import colorlog
from datetime import datetime


#-----------------------------------------------------------------------------------#
# ----------------------------------- Class  -------------------------------------- #
#-----------------------------------------------------------------------------------#
class ColoredLogger:
    def __init__(self, name=__name__, log_level=logging.DEBUG):
        log_dir='logs'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        # Create the log file name with the current date and time
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = os.path.join(log_dir, f"log_{current_time}.log")

        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)

        # Create a color formatter using colorlog
        color_formatter = colorlog.ColoredFormatter(
            "%(log_color)s[%(levelname)s] %(message)s",  # Format with colors
            datefmt=None,
            reset=True,
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'bold_red',
            }
        )

        # Set up console handler with color
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(color_formatter)

        # Set up file handler without color, using the dynamic log file name
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            "[%(levelname)s] %(message)s"
        ))

        # Add handlers to the logger
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    def get_logger(self):
        return self.logger