#!/bin/bash

# Script to auto-generate complete schema.yml from phone reports
# This ensures we capture ALL parameters reported by Cisco MPP phones

set -e

echo "🔄 Auto-generating complete schema.yml from phone reports..."

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

# Generate complete schema.yml
echo "🏗️ Generating complete schema.yml..."
python3 -c "
import json
import yaml
import sys

# Load the phone report
with open('$LATEST_REPORT', 'r') as f:
    report = json.load(f)

# Extract all parameters and their values
params = {}
for key, value in report['data'].items():
    if key != 'raw_xml' and not key.startswith('<'):
        # Use the actual reported value as default, or empty string for passwords
        if 'password' in key.lower() or 'passwd' in key.lower():
            params[key] = ''  # Don't store actual passwords
        elif isinstance(value, str) and len(value) > 100:
            params[key] = ''  # Don't store overly long values as defaults
        else:
            # Ensure all values are strings and properly formatted for YAML
            if value is None:
                params[key] = ''
            elif isinstance(value, bool):
                params[key] = 'Yes' if value else 'No'
            elif isinstance(value, (int, float)):
                params[key] = str(value)
            else:
                params[key] = str(value)

# Create the complete schema structure
schema = {
    'schema': {
        'xml_structure': {
            'device': {
                'flat-profile': 'DYNAMIC_PARAMS'
            }
        },
        'flat_profile_params': params
    }
}

# Write the complete schema
with open('config/schema.yml', 'w') as f:
    f.write('# Auto-generated XML Schema Configuration for Cisco MPP Phones\n')
    f.write('# Generated from phone report: $(basename \"$LATEST_REPORT\")\n')
    f.write('# Contains ALL parameters reported by actual Cisco phones\n')
    f.write('# Edit parameter values as needed for your environment\n\n')
    
    # Custom YAML dumper to ensure only values are quoted, not keys
    class QuotedDumper(yaml.SafeDumper):
        def represent_str(self, data):
            # Always quote string values
            return self.represent_scalar('tag:yaml.org,2002:str', data, style=\"'\")
        
        def represent_mapping(self, tag, mapping, flow_style=None):
            # Override mapping representation to ensure keys are not quoted
            node = super().represent_mapping(tag, mapping, flow_style)
            # Ensure keys use plain style (no quotes)
            for key_node, value_node in node.value:
                if key_node.tag == 'tag:yaml.org,2002:str':
                    key_node.style = None  # Plain style for keys
            return node
    
    QuotedDumper.add_representer(str, QuotedDumper.represent_str)
    
    yaml.dump(schema, f, Dumper=QuotedDumper, default_flow_style=False, sort_keys=True, width=120, allow_unicode=True)

print(f'✅ Generated complete schema.yml with {len(params)} parameters')
"

if [ $? -eq 0 ]; then
    echo ""
    echo "🎯 Schema generation complete!"
    echo "📝 The new schema.yml contains ALL parameters from the phone report"
    echo "💡 You can now edit the default values in config/schema.yml as needed"
    echo ""
    echo "🔍 Running verification to confirm completeness..."
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    "$SCRIPT_DIR/verify_schema_completeness.sh"
else
    echo "❌ Failed to generate schema"
    exit 1
fi
