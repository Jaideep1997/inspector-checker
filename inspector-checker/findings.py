#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
import re
import requests
import json

from utilities.print import empty_carriage_line
from utilities.output import format_findings_data, output_table, output_report
from utilities.aws import inspector2_list_findings

def check_inspector_findings(args):
  findings = get_inspector_findings(args)
  if not findings:
    return
  processed_findings = process_findings(findings, args)
  data = format_findings_data(processed_findings, args)
  output_table('\U0001F575  Findings', data)
  if args.output:
    output_report(args, data)

def get_inspector_findings(args):
  filter_criteria = get_filter_criteria(args)
  findings = []
  for i, region in enumerate(args.regions):
    print(f'{empty_carriage_line()}\N{earth globe europe-africa} Getting findings in {region} ({i+1}/{len(args.regions)})', end='\r')
    regional_findings = inspector2_list_findings(region, filter_criteria)
    if regional_findings:
      findings.extend(regional_findings)
  print(f'{empty_carriage_line()}\N{earth globe europe-africa} Obtained {len(findings)} finding{"s" if len(findings) != 1 else ""}\n')
  return findings

def get_filter_criteria(args):
  # Default -> active status and severities
  filter_criteria = {
    'findingStatus': [get_filter_criteria_values(comparison='EQUALS', value='ACTIVE')],
    'severity': [get_filter_criteria_values(comparison='EQUALS', value=severity.upper()) for severity in args.severities],
  }
  # Time
  if args.time_period:
    now = datetime.now()
    past = now - timedelta(hours = args.time_period)
    filter_criteria['firstObservedAt'] = [{
      'startInclusive': past.timestamp(),
      'endInclusive': now.timestamp()
    }]
  # Instance ID
  if args.instance_id: filter_criteria['resourceId'] = [get_filter_criteria_values(comparison='EQUALS', value=args.instance_id)]
  # CVE
  if args.cve_id: filter_criteria['title'] = [get_filter_criteria_values(comparison='PREFIX', value=args.cve_id)]
  return filter_criteria

def get_filter_criteria_values(comparison, value):
  return {
    'comparison': comparison,
    'value': value
  }

def process_findings(findings, args):
  if not args.instance_id and not args.cve_id:
    print(f'{empty_carriage_line()}\N{factory} Processing unique finding{"s" if len(findings) != 1 else ""}', end='\r')
  processed_findings = {}
  for finding in findings:
    if finding['title'] not in processed_findings:
      processed_findings[finding['title']] = {
        'resources': [],
        'severity': finding['severity'],
        'public_exploits': 'n/a'
      }
    processed_findings[finding['title']]['resources'].append({
      'id': finding['resources'][0]['id'],
      'region': finding['resources'][0]['region'],
      'first_observed': finding['firstObservedAt'].strftime('%Y-%m-%d')
    })
  if not args.instance_id and not args.cve_id:
    print(f'{empty_carriage_line()}\N{factory} Processed {len(processed_findings)} unique finding{"s" if len(processed_findings) != 1 else ""}\n')
  
  if not args.skip_public_exploit_check:
    processed_findings = check_findings_for_public_exploits(processed_findings)
  return processed_findings

def check_findings_for_public_exploits(findings):
  request_parameters = {
    'url': 'https://sploitus.com/search',
    'headers': {'content-type': 'application/json'},
    'payload': {
      'type': 'exploits',
      'sort': 'default',
      'title': False,
      'offset': 0
    }
  }
  for i, finding_title in enumerate(findings):
    findings[finding_title]['public_exploits'] = check_finding_for_public_exploits(request_parameters, finding_title, finding_number=i+1, number_of_findings=len(findings))
  print(f'{empty_carriage_line()}\U0001F50D Checked {len(findings)} CVE{"s" if len(findings) != 1 else ""} for public exploits\n')
  return findings

def check_finding_for_public_exploits(request_parameters, finding, finding_number, number_of_findings):
  try:
    cve_pattern = 'CVE-\d{4}-\d{1,5}'
    cve_id = re.search(cve_pattern, finding).group(0)
    request_parameters['payload']['query'] = cve_id
    print(f'{empty_carriage_line()}\U0001F50D Checking {cve_id} for public exploits ({finding_number}/{number_of_findings})', end='\r')
    response = requests.post(url=request_parameters['url'], data=json.dumps(request_parameters['payload']), headers=request_parameters['headers']).text
    number_of_exploits = json.loads(response)['exploits_total']
    return number_of_exploits
  except (AttributeError, json.decoder.JSONDecodeError):
    return 'n/a'
