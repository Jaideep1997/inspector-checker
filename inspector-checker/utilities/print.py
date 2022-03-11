#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from config.config import inspector_checker_version

def print_inspector_checker_intro():
  columns = os.get_terminal_size().columns
  text = f'Inspector Checker v{inspector_checker_version}'
  indent = '=' * int(columns / 6)
  whitespace = ' ' * int((columns - len(text) - (len(indent) * 2)) / 2)
  print(f'{"=" * columns}\n{indent}{whitespace}{text}{whitespace}{indent}\n{"=" * columns}')

def empty_carriage_line():
  return f'{" " * 100}\r'
