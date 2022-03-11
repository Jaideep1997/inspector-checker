# inspector-checker

`inspector-checker` is a programmatic companion to the AWS Inspector2 service. It tries to make up for some of the inherent weaknesses of the Inspector2 dashboard by making it quick and easy to check and visualize findings across your AWS environment.

# Setup

```
git clone git@github.com:nicolaurech/inspector-checker.git
cd inspector-checker

pip install -r requirements.txt

ln -s $(pwd)/inspector-checker/inspector-checker.py /usr/local/bin/inspector-checker
```

# Usage

`inspector-checker` can perform two main functions:
- Check coverage
- Check findings

## Coverage
The check coverage function provides insight into how many of your instances are covered (i.e. being scanned). It can also highlight the instances that are not covered.

By default, it shows you:
- Active instances
- Inactive instances
- Total instances
- The percentage of instances covered

### Options
- Region
- Detailed
- Save output

Help
```
inspector-checker coverage -h
```

Check coverage in all regions
```
inspector-checker coverage
```

Check coverage in a specific region
```
inspector-checker coverage -r us-east-1
```

Check the uncovered instances in all regions
```
inspector-checker coverage --detailed
```

Check the uncovered instances in a specific region
```
inspector-checker coverage -r us-east-1 --detailed
```

Save the output in a csv file
```
inspector-checker coverage -o
inspector-checker coverage -r us-east-1 --detailed -o
```

## Findings
The check findings function provides insight into the Inspector2 findings across your AWS environment. It can highlight all findings, only show recent findings, search for findings with a specified severity, search for CVEs, check specified instances, etc.

By default, it shows you:
- All active CVEs across your AWS environment
- The frequency of each CVE across your AWS environment
- Public exploits associated with CVEs
- The severity of each CVE across your AWS environment

Additionally, it can show you:
- The most recent findings across your AWS environment
- Findings with specified severities
- If a specified CVE has been found in your AWS environment
- What findings a specified EC2 instance has

### Options
- Region
- Time period
- Severities
- CVE
- Instance
- Save output
- Skip public exploit check

Help
```
inspector-checker findings -h
```

Check active findings in all regions
```
inspector-checker findings
```

Check active findings in a specified region
```
inspector-checker findings -r us-east-1
```

Check recent findings (e.g. 24 hours, 1 week)
```
inspector-checker findings -t 24
inspector-checker findings -t 168
```

Check findings with specified severities (default is critical and high)
```
inspector-checker findings -s medium
inspector-checker findings -s high,medium
inspector-checker findings -s informational
```

Check the findings for a specified instance in a region
```
inspector-checker findings -i i-0aa55b666c7dd8e99 -r us-east-1
```

Check if a CVE has been found in your AWS environment
```
inspector-checker findings -c CVE-2010-1122
inspector-checker findings -c CVE-2010-1122 -r us-east-1
inspector-checker findings -c CVE-2010-1122 -r us-east-1 -t 24
inspector-checker findings -c CVE-2010-1122 -r us-east-1 -i i-0aa55b666c7dd8e99
```

Skip public exploit check (enabled by default)
```
inspector-checker findings --skip-pec
```

Save the output to a csv file
```
inspector-checker findings -o
inspector-checker findings -t 168 -o
inspector-checker findings -c CVE-2010-1122 -r us-east-1 -o
inspector-checker findings -i i-0aa55b666c7dd8e99 -r us-east-1 -o
```

# Future Improvements
- Add custom, comprehensive long-term report feature (i.e. functionality for monthly reporting)
- Add other report formats (e.g. json)
- Better reporting in general
- Add support for container scanning and findings
- Allow searching of non-CVE findings (e.g. "port range")
- Add colors to highlight (more) important information
- Add support for suppressed, closed and all findings
