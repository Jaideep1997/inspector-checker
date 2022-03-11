#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utilities.print import print_inspector_checker_intro
from utilities.input import parse_arguments
from coverage import check_inspector_coverage
from findings import check_inspector_findings

def main():
  try:
    print_inspector_checker_intro()
    args = parse_arguments()
    if args.task == 'coverage':
      check_inspector_coverage(args)
    elif args.task == 'findings':
      check_inspector_findings(args)
  except KeyboardInterrupt:
    print('\n\nGracefully exiting...')

if __name__ == '__main__':
  main()
