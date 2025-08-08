#!/bin/bash

# Script to verify that schema.yml contains all parameters from the latest phone report
# This ensures we don't miss any Cisco MPP parameters

set -e

echo "🔍 Verifying schema completeness against phone reports..."

# Find the latest phone config report
REPORTS_DIR="./reports"
LATEST_REPORT=""

if [ -d "$REPORTS_DIR" ]; then
    LATEST_REPORT=$(find "$REPORTS_DIR" -name "*_config_*.json" -type f -exec ls -t {} + | head -n1)
fi

if [ -z "$LATEST_REPORT" ]; then
    echo "❌ No phone config reports found in $REPORTS_DIR"
    echo "   Please ensure a phone has reported its configuration first"
    exit 1
fi

echo "📄 Using latest report: $(basename "$LATEST_REPORT")"

# Extract all parameter names from the phone report
echo "📋 Extracting parameters from phone report..."
REPORT_PARAMS=$(python3 -c "
import json
import sys

with open('$LATEST_REPORT', 'r') as f:
    report = json.load(f)

# Get all parameter names from the report data
params = set()
for key, value in report['data'].items():
    if key != 'raw_xml' and not key.startswith('<'):
        params.add(key)

# Sort and print
for param in sorted(params):
    print(param)
")

# Extract all parameter names from schema.yml
echo "📋 Extracting parameters from schema.yml..."
SCHEMA_PARAMS=$(python3 -c "
import yaml
import sys

try:
    with open('config/schema.yml', 'r') as f:
        schema = yaml.safe_load(f)
    
    # Get all parameter names from flat_profile_params
    params = set()
    flat_profile = schema.get('schema', {}).get('flat_profile_params', {})
    for key in flat_profile.keys():
        params.add(key)
    
    # Sort and print
    for param in sorted(params):
        print(param)
        
except Exception as e:
    print(f'Error reading schema: {e}', file=sys.stderr)
    sys.exit(1)
")

if [ $? -ne 0 ]; then
    echo "❌ Failed to read schema.yml"
    exit 1
fi

# Compare parameters
echo "🔍 Comparing parameters..."
echo "$REPORT_PARAMS" > /tmp/report_params.txt
echo "$SCHEMA_PARAMS" > /tmp/schema_params.txt

# Find parameters in report but not in schema
MISSING_IN_SCHEMA=$(comm -23 <(sort /tmp/report_params.txt) <(sort /tmp/schema_params.txt))

# Find parameters in schema but not in report (this is okay, they might be defaults)
EXTRA_IN_SCHEMA=$(comm -13 <(sort /tmp/report_params.txt) <(sort /tmp/schema_params.txt))

# Report results
REPORT_COUNT=$(echo "$REPORT_PARAMS" | wc -l)
SCHEMA_COUNT=$(echo "$SCHEMA_PARAMS" | wc -l)
if [ -z "$MISSING_IN_SCHEMA" ]; then
    MISSING_COUNT=0
else
    MISSING_COUNT=$(echo "$MISSING_IN_SCHEMA" | grep -c .)
fi

echo ""
echo "📊 Summary:"
echo "   Parameters in phone report: $REPORT_COUNT"
echo "   Parameters in schema.yml:   $SCHEMA_COUNT"
echo "   Missing from schema:        $MISSING_COUNT"

if [ "$MISSING_COUNT" -gt 0 ]; then
    echo ""
    echo "❌ MISSING PARAMETERS in schema.yml:"
    echo "   The following parameters are reported by the phone but not defined in schema.yml:"
    echo ""
    echo "$MISSING_IN_SCHEMA" | while read -r param; do
        if [ -n "$param" ]; then
            # Get the value from the report for reference
            VALUE=$(python3 -c "
import json
with open('$LATEST_REPORT', 'r') as f:
    report = json.load(f)
value = report['data'].get('$param', '')
# Truncate long values
if len(str(value)) > 50:
    print(f'$param: \"{str(value)[:47]}...\"')
else:
    print(f'$param: \"{value}\"')
")
            echo "   $VALUE"
        fi
    done
    echo ""
    echo "💡 To fix this, add these parameters to config/schema.yml under flat_profile_params:"
    echo ""
    echo "$MISSING_IN_SCHEMA" | while read -r param; do
        if [ -n "$param" ]; then
            VALUE=$(python3 -c "
import json
with open('$LATEST_REPORT', 'r') as f:
    report = json.load(f)
value = report['data'].get('$param', '')
if isinstance(value, str) and len(value) > 50:
    print(f'    $param: \"\"  # Default empty, reported: \"{value[:30]}...\"')
else:
    print(f'    $param: \"$value\"')
")
            echo "$VALUE"
        fi
    done
    echo ""
    exit 1
else
    echo ""
    echo "✅ SUCCESS: All phone-reported parameters are included in schema.yml!"
    
    if [ -n "$EXTRA_IN_SCHEMA" ] && [ "$(echo "$EXTRA_IN_SCHEMA" | grep -c .)" -gt 0 ]; then
        EXTRA_COUNT=$(echo "$EXTRA_IN_SCHEMA" | grep -c .)
        echo ""
        echo "ℹ️  Note: $EXTRA_COUNT parameters in schema.yml are not currently reported by the phone."
        echo "   This is normal - they may be defaults or optional parameters."
    fi
fi

# Cleanup
rm -f /tmp/report_params.txt /tmp/schema_params.txt

echo ""
echo "🎯 Schema verification complete!"
