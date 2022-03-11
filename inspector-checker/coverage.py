#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utilities.output import format_coverage_data, output_table, format_detailed_coverage_data, output_report
from utilities.print import empty_carriage_line
from utilities.aws import inspector2_list_coverage

def check_inspector_coverage(args):
  coverage = get_inspector_coverage(args.regions, args.detailed)
  if coverage:
    data = format_coverage_data(coverage)
    output_table('\U0001F916 Coverage', data)
    if args.detailed:
      for region in coverage:
        detailed_data = format_detailed_coverage_data(coverage[region]['uncovered_instances'])
        output_table(f'\N{world map}  {region}', detailed_data, style='STYLE_COMPACT')
        if args.output:
          output_report(args, detailed_data)
    if args.output:
      output_report(args, data)

def get_inspector_coverage(regions, detailed):
  coverage = {}
  for i, region in enumerate(regions):
    print(f'{empty_carriage_line()}\N{earth globe europe-africa} Getting Inspector coverage in {region} ({i+1}/{len(regions)})', end='\r')
    regional_coverage = inspector2_list_coverage(region)
    if not regional_coverage: continue
    coverage[region] = {
      'active': 0,
      'inactive': 0
    }
    for instance in regional_coverage:
      if instance['scanStatus']['statusCode'] == 'ACTIVE':
        coverage[region]['active'] += 1
      else:
        coverage[region]['inactive'] += 1
        if detailed:
          if 'uncovered_instances' not in coverage[region]:
            coverage[region]['uncovered_instances'] = []
          coverage[region]['uncovered_instances'].append(instance['resourceId'])

    coverage[region]['total'] = coverage[region]['active'] + coverage[region]['inactive']
    coverage[region]['percentage'] = calculate_coverage_percentage(coverage[region]['active'], coverage[region]['inactive'])
  if coverage: print(f'{empty_carriage_line()}\N{earth globe europe-africa} Obtained Inspector coverage ({len(regions)}/{len(regions)})\n')
  return coverage

def calculate_coverage_percentage(active_instances, inactive_instances):
  try:
    return f'{round(active_instances / (active_instances + inactive_instances) * 100, 2)}%'
  except ZeroDivisionError:
    return '0.0%'
  