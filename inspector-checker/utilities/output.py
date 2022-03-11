#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import csv
from datetime import datetime
from beautifultable import BeautifulTable

def get_project_path():
  return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def get_output_path():
  return f'{get_project_path()}/output'

def create_output_directory(output_path):
  if not os.path.isdir(output_path):
    os.mkdir(output_path)

def get_report_path(output_path, args):
  return f'{output_path}/{get_report_name(args)}'

def get_report_name(args):
  report_name = f'ic-{args.task}'
  # Add region
  if type(args.regions) == str or len(args.regions) == 1:
    report_name += f'-{"".join(args.regions)}'
  # Add detailed
  if args.task == 'coverage' and args.detailed:
    report_name += f'-detailed'
  # Add instance id
  if args.task == 'findings' and args.instance_id:
    report_name += f'-{args.instance_id}'
  # Add CVE
  if args.task == 'findings' and args.cve_id:
    report_name += f'-{args.cve_id}'
  # Add date
  report_name += f'-{datetime.now().strftime("%m-%d-%Y")}.csv'
  return report_name

def output_report(args, data):
  output_path = get_output_path()
  create_output_directory(output_path)
  report_path = get_report_path(output_path, args)

  with open(report_path, 'w') as report_file:
    csv_writer = csv.writer(report_file, delimiter=',')
    for line in data:
      csv_writer.writerow(line)

def output_table(name, data, style='STYLE_BOX_DOUBLED'):
  print(f'{name}\n')
  # Populate
  table = BeautifulTable(maxwidth=os.get_terminal_size().columns)
  table.columns.header = data[0]
  for row in data[1:]:
    table.rows.append(row)
  # Alignment
  table.columns.alignment = BeautifulTable.ALIGN_LEFT
  # Style
  table.set_style(getattr(BeautifulTable, style))
  print(f'{table}\n')

def format_coverage_data(body):
  headers = [
    'Region',
    'Active Instances',
    'Inactive Instances',
    'Total Instances',
    'Coverage'
  ]
  data = [headers]
  for region in body:
    data.append([
      region,
      body[region]['active'],
      body[region]['inactive'],
      body[region]['total'],
      body[region]['percentage']
    ])
  return data

def format_detailed_coverage_data(body):
  headers = [
    'Uncovered Instances'
  ]
  data =  [headers]
  for instance in body:
    data.append([
      instance
    ])
  return data

def format_findings_data(body, args):
  # Default
  if not args.instance_id and not args.cve_id:
    headers = [
      'Finding',
      'Severity',
      'Occurrences',
      'Public Exploits'
    ]
    data = [headers]
    for finding_title in body:
      data.append([
        finding_title,
        body[finding_title]['severity'],
        len(body[finding_title]['resources']),
        body[finding_title]['public_exploits']
      ])
  # Instance specified
  elif args.instance_id and not args.cve_id:
    headers = [
      'Finding',
      'Severity',
      'Public Exploits',
      'First Observed'
    ]
    data = [headers]
    for finding_title in body:
      for resource in body[finding_title]['resources']:
        data.append([
          finding_title,
          body[finding_title]['severity'],
          body[finding_title]['public_exploits'],
          resource['first_observed'],
        ])

  # CVE specified
  elif args.cve_id:
    headers = [
      'Finding',
      'Severity',
      'Public Exploits',
      'Resource',
      'Region',
      'First Observed'
    ]
    data = [headers]
    for finding_title in body:
      for resource in body[finding_title]['resources']:
        data.append([
          finding_title,
          body[finding_title]['severity'],
          body[finding_title]['public_exploits'],
          resource['id'],
          resource['region'],
          resource['first_observed']
        ])
  return data
