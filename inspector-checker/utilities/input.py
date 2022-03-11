#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re

from config.config import inspector_supported_regions, allowed_finding_severities

def parse_arguments():
  parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  subparser = parser.add_subparsers(dest='task', required=True)

  # Coverage
  parser_coverage = subparser.add_parser('coverage', formatter_class=argparse.ArgumentDefaultsHelpFormatter, help='Check the coverage of Inspector scanning')
  parser_coverage.add_argument('-r', '--region', dest='regions', type=check_region_input, default=inspector_supported_regions, help='region to check Inspector')
  parser_coverage.add_argument('-o', '--output', action='store_true', help='save the results in a csv file')
  parser_coverage.add_argument('-d', '--detailed', action='store_true', help='show uncovered instances')

  # Findings
  parser_findings = subparser.add_parser('findings', formatter_class=argparse.ArgumentDefaultsHelpFormatter, help='Check recent Inspector findings')
  parser_findings_mutually_exclusive_group = parser_findings.add_mutually_exclusive_group()

  parser_findings.add_argument('-r', '--region', dest='regions', type=check_region_input, default=inspector_supported_regions, help='region to check Inspector')
  parser_findings.add_argument('-t', '--time', dest='time_period', type=check_time_input, help='analyze findings between now and this many hours ago')
  parser_findings_mutually_exclusive_group.add_argument('-s', '--severities', type=check_severities_input, default='critical,high', help=f'comma-separated list of severities. Options: {[s.lower() for s in allowed_finding_severities]}')
  parser_findings_mutually_exclusive_group.add_argument('-c', '--cve-id', type=check_cve_id, help='CVE to check')
  parser_findings.add_argument('-i', '--instance-id', type=check_instance_id_input, help='specific instance to check')
  parser_findings.add_argument('-o', '--output', action='store_true', help='save the results in a csv file')
  parser_findings.add_argument('--skip-pec', dest='skip_public_exploit_check', action='store_true', help='skip public exploit check')


  args = parser.parse_args()

  if args.task == 'findings':
    # Require region when instance id is specified
    if args.instance_id and len(args.regions) != 1:
      parser_findings.error('Region must be specified when instance id is specified')
    # Set severities to all allowed when searching by CVE
    if args.cve_id:
      args.severities = allowed_finding_severities

  return args

def check_region_input(region):
  if region not in inspector_supported_regions:
    raise argparse.ArgumentTypeError(f'Unsupported Inspector region: {region}')
  return [region]

def check_time_input(time):
  try:
    itime = int(time)
    if itime <= 0:
      raise Exception
    return itime
  except:
    raise argparse.ArgumentTypeError('Time must be a positive integer value')

def check_severities_input(severities):
  severities_list = [s.strip() for s in severities.split(',')]
  for severity in severities_list:
    if severity.upper() not in allowed_finding_severities:
      raise argparse.ArgumentTypeError(f'Invalid severity: {severity}')
  return severities_list

def check_instance_id_input(instance_id):
  try:
    instance_id_pattern = 'i-[\da-f]{12,20}$'
    instance_id_search = re.search(instance_id_pattern, instance_id).group(0)
    return instance_id
  except:
    raise argparse.ArgumentTypeError('Invalid instance id')

def check_cve_id(cve_id):
  try:
    cve_id_pattern = 'CVE-[\d]{4}-[\d]{1,5}$'
    cve_id_search = re.search(cve_id_pattern, cve_id).group(0)
    return cve_id_search
  except:
    raise argparse.ArgumentTypeError('Invalid CVE id')
