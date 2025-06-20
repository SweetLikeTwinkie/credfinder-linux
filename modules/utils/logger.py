import sys

class Logger:
    def __init__(self, minimal_logging=False):
        self.minimal_logging = minimal_logging

    def info(self, message):
        if not self.minimal_logging:
            print(f"[INFO] {message}")

    def error(self, message):
        print(f"[ERROR] {message}", file=sys.stderr) 