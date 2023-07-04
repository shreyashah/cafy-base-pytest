"""
Define utils required by plugin.py.
"""
import os, sys

class SuppressOutput:
    def __enter__(self):
        self._original_stdout = sys.stdout
        self._original_stderr = sys.stderr
        self._devnull = open(os.devnull, 'w')
        sys.stdout = self._devnull
        sys.stderr = self._devnull

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._devnull.close()
        sys.stdout = self._original_stdout
        sys.stderr = self._original_stderr