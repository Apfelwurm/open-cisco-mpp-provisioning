#!/usr/bin/env python3
"""
Cisco MPP Phone Provisioning Service
Serves XML configuration dynamically for Cisco CP-6841-3CPP phones
"""

import os
import yaml
import logging
import json
import re
from datetime import datetime, timedelta
from flask import Flask, request, Response, render_template_string, jsonify
from jinja2 import Template
import xml.etree.ElementTree as ET
from xml.dom import minidom
from functools import wraps
import base64
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
import time

# Configure logging
try:
    os.makedirs('/app/logs', exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/app/logs/provisioning.log'),
            logging.StreamHandler()
        ]
    )
except Exception as e:
    # Fallback to console logging only
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    print(f"Warning: Could not set up file logging: {e}")

logger = logging.getLogger(__name__)

# Prometheus metrics
phone_config_requests = Counter('phone_config_requests_total', 'Total phone configuration requests', ['ip', 'phone_mac'])
phone_reports_received = Counter('phone_reports_received_total', 'Total phone reports received', ['phone_mac', 'report_type'])
phone_config_differences = Gauge('phone_config_differences', 'Number of phones with configuration differences')
phone_unexpected_params = Gauge('phone_unexpected_params', 'Number of phones with unexpected parameters')
phone_activity_recent = Gauge('phone_activity_recent', 'Number of phones active in recent time window')
reports_recent = Gauge('reports_recent', 'Number of reports received in recent time window')
phone_config_request_duration = Histogram('phone_config_request_duration_seconds', 'Time spent processing config requests')
phone_firmware_updates = Counter('phone_firmware_updates_total', 'Total firmware update requests served', ['current_version', 'expected_version', 'phone_model'])

app = Flask(__name__)

# Ensure reports directory exists
REPORTS_DIR = '/app/reports'
os.makedirs(REPORTS_DIR, exist_ok=True)

# Load phone configurations
def load_phone_config():
    """Load phone configuration from YAML file"""
    try:
        with open('/app/config/phones.yml', 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.error("Phone configuration file not found")
        return None
    except Exception as e:
        logger.error(f"Error loading phone config: {e}")
        return None

def load_common_config():
    """Load common configuration settings"""
    try:
        with open('/app/config/common.yml', 'r') as f:
            data = yaml.safe_load(f)
            return data.get('common', {}) if data else {}
    except FileNotFoundError:
        logger.error("Common configuration file not found")
        return {}
    except Exception as e:
        logger.error(f"Error loading common config: {e}")
        return {}

def load_comparison_config():
    """Load comparison configuration settings"""
    try:
        with open('/app/config/comparison.yml', 'r') as f:
            data = yaml.safe_load(f)
            return data.get('comparison', {}) if data else {}
    except FileNotFoundError:
        logger.warning("Comparison configuration file not found, using defaults")
        return {
            'blacklist': ['mac', 'ip_address', 'serial_number', 'raw_xml']
        }
    except Exception as e:
        logger.error(f"Error loading comparison config: {e}")
        return {
            'blacklist': ['mac', 'ip_address', 'serial_number', 'raw_xml']
        }

def load_schema_config():
    """Load XML schema configuration"""
    try:
        with open('/app/config/schema.yml', 'r') as f:
            data = yaml.safe_load(f)
            return data.get('schema', {}) if data else {}
    except FileNotFoundError:
        logger.warning("Schema configuration file not found, using minimal defaults")
        return {
            'xml_structure': {
                'device': {
                    'flat-profile': 'DYNAMIC_PARAMS'
                }
            },
            'flat_profile_params': {},
            'special_rules': {}
        }
    except Exception as e:
        logger.error(f"Error loading schema config: {e}")
        return {
            'xml_structure': {
                'device': {
                    'flat-profile': 'DYNAMIC_PARAMS'
                }
            },
            'flat_profile_params': {},
            'special_rules': {}
        }

def load_service_config():
    """Load service configuration (monitoring and authentication)"""
    try:
        with open('/app/config/serviceconfig.yml', 'r') as f:
            data = yaml.safe_load(f)
            return data if data else {}
    except FileNotFoundError:
        logger.warning("Service configuration file not found, using defaults")
        return {
            'monitoring': {
                'metrics_enabled': True,
                'phone_activity_window': 3600,
                'report_activity_window': 1800
            },
            'auth': {
                'enabled': False,
                'users': {}
            }
        }
    except Exception as e:
        logger.error(f"Error loading service config: {e}")
        return {
            'monitoring': {
                'metrics_enabled': True,
                'phone_activity_window': 3600,
                'report_activity_window': 1800
            },
            'auth': {
                'enabled': False,
                'users': {}
            }
        }

def load_firmware_config():
    """Load firmware update configuration"""
    try:
        with open('/app/config/firmware.yml', 'r') as f:
            data = yaml.safe_load(f)
            return data.get('firmware', {}) if data else {}
    except FileNotFoundError:
        logger.warning("Firmware configuration file not found, firmware updates disabled")
        return {
            'update_enabled': False,
            'expected_version': '12.0.1',
            'upgrade_url': '',
            'retry_delay': 3600,
            'log_messages': {
                'upgrade_request': '$PN $MAC -- Requesting upgrade $SCHEME://$SERVIP:$PORT$PATH',
                'upgrade_success': '$PN $MAC -- Successful upgrade $SCHEME://$SERVIP:$PORT$PATH -- $ERR',
                'upgrade_failure': '$PN $MAC -- Upgrade failed: $ERR'
            },
            'model_specific': {
                'enabled': False,
                'versions': {}
            }
        }
    except Exception as e:
        logger.error(f"Error loading firmware config: {e}")
        return {
            'update_enabled': False,
            'expected_version': '12.0.1',
            'upgrade_url': '',
            'retry_delay': 3600,
            'log_messages': {
                'upgrade_request': '$PN $MAC -- Requesting upgrade $SCHEME://$SERVIP:$PORT$PATH',
                'upgrade_success': '$PN $MAC -- Successful upgrade $SCHEME://$SERVIP:$PORT$PATH -- $ERR',
                'upgrade_failure': '$PN $MAC -- Upgrade failed: $ERR'
            },
            'model_specific': {
                'enabled': False,
                'versions': {}
            }
        }

def get_phone_by_mac(mac_address):
    """Get phone configuration by MAC address"""
    config = load_phone_config()
    if not config:
        return None
    
    # Normalize MAC address (remove colons, convert to lowercase)
    mac_normalized = mac_address.replace(':', '').replace('-', '').lower()
    
    for phone_id, phone_data in config.get('phones', {}).items():
        phone_mac = phone_data.get('mac', '').replace(':', '').replace('-', '').lower()
        if phone_mac == mac_normalized:
            return phone_data
    
    return None

def get_phone_by_identifier(identifier):
    """Get phone configuration by any identifier (MAC, serial number, etc.)"""
    config = load_phone_config()
    if not config:
        return None
    
    # Normalize identifier (remove colons, dashes, convert to lowercase)
    identifier_normalized = identifier.replace(':', '').replace('-', '').lower()
    
    for phone_id, phone_data in config.get('phones', {}).items():
        # Check MAC address
        phone_mac = phone_data.get('mac', '').replace(':', '').replace('-', '').lower()
        if phone_mac == identifier_normalized:
            return phone_data
        
        # Check serial number if present
        phone_serial = str(phone_data.get('serial_number', '')).replace(':', '').replace('-', '').lower()
        if phone_serial and phone_serial == identifier_normalized:
            return phone_data
        
        # Check if identifier matches phone_id itself
        if phone_id.lower() == identifier_normalized:
            return phone_data
    
    return None

def build_merged_config(phone_config, common_config, schema_config):
    """Build merged configuration using same logic as comparison"""
    merged_config = {}
    
    # Start with common config (actual values we want to set)
    if common_config:
        for key, value in common_config.items():
            merged_config[key] = value
    
    # Apply phone-specific config (overrides common)
    if phone_config:
        for key, value in phone_config.items():
            if key not in ['mac', 'ip_address', 'serial_number']:  # Skip non-Cisco parameters
                merged_config[key] = value
    
    # Add any missing schema parameters with empty values (no defaults)
    # This ensures all schema parameters are present in XML but without unwanted default values
    flat_profile_params = schema_config.get('flat_profile_params', {})
    for param in flat_profile_params.keys():
        if param not in merged_config:
            merged_config[param] = ""  # Empty value, not the schema default
    
    return merged_config

def generate_xml_element(element_name, element_config, merged_config, indent_level=0):
    """Recursively generate XML elements based on schema structure"""
    indent = "  " * indent_level
    xml_parts = []
    
    if isinstance(element_config, dict):
        # This is a container element with child elements
        xml_parts.append(f"{indent}<{element_name}>")
        
        for child_name, child_config in element_config.items():
            if child_config == "DYNAMIC_PARAMS":
                # Special case: insert all flat-profile parameters dynamically
                xml_parts.append(f"{indent}  <{child_name}>")
                for param, value in merged_config.items():
                    # Include all parameters from merged config (common + phone + empty schema params)
                    # Cisco phones expect the complete XML structure with all known parameters
                    escaped_value = str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    xml_parts.append(f"{indent}    <{param} ua=\"na\">{escaped_value}</{param}>")
                xml_parts.append(f"{indent}  </{child_name}>")
            else:
                # Recursively generate child elements
                child_xml = generate_xml_element(child_name, child_config, merged_config, indent_level + 1)
                xml_parts.extend(child_xml)
        
        xml_parts.append(f"{indent}</{element_name}>")
    
    elif isinstance(element_config, str):
        # This is a leaf element with either static text or parameter reference
        if element_config in merged_config:
            # This is a parameter reference - use the value from config
            value = merged_config.get(element_config, "")
            escaped_value = str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            xml_parts.append(f"{indent}<{element_name}>{escaped_value}</{element_name}>")
        else:
            # This is static text
            escaped_value = element_config.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            xml_parts.append(f"{indent}<{element_name}>{escaped_value}</{element_name}>")
    
    return xml_parts

def generate_xml_config(phone_config, common_config):
    """Generate XML configuration dynamically using schema structure"""
    schema_config = load_schema_config()
    
    # Build merged config using same logic as comparison
    merged_config = build_merged_config(phone_config, common_config, schema_config)
    
    # Note: Profile_Rule and Report_Rule are now set in common.yml
    # If they need to be dynamic, they can be overridden in phone-specific configs
    
    # Get XML structure from schema
    xml_structure = schema_config.get('xml_structure', {})
    
    if not xml_structure:
        # Fallback to minimal XML if no structure defined
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<device>
  <flat-profile>
    {chr(10).join(f'<{param} ua="na">{value}</{param}>' for param, value in merged_config.items() if value)}
  </flat-profile>
</device>"""
    
    # Generate XML from structure
    xml_parts = ['<?xml version="1.0" encoding="UTF-8"?>']
    
    # Process the root structure
    for root_element, root_config in xml_structure.items():
        element_xml = generate_xml_element(root_element, root_config, merged_config)
        xml_parts.extend(element_xml)
    
    return '\n'.join(xml_parts)

def prettify_xml(xml_string):
    """Pretty print XML with proper indentation"""
    try:
        root = ET.fromstring(xml_string)
        rough_string = ET.tostring(root, 'utf-8')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ", encoding="UTF-8").decode('utf-8')
    except Exception as e:
        logger.error(f"Error prettifying XML: {e}")
        return xml_string

def save_phone_report(mac_address, report_data, report_type='config'):
    """Save phone configuration report to file"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{mac_address}_{report_type}_{timestamp}.json"
        filepath = os.path.join(REPORTS_DIR, filename)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'mac_address': mac_address,
            'report_type': report_type,
            'client_ip': request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR')),
            'user_agent': request.headers.get('User-Agent', ''),
            'data': report_data
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Saved {report_type} report for MAC {mac_address}: {filename}")
        return filename
    except Exception as e:
        logger.error(f"Error saving phone report: {e}")
        return None

def parse_phone_xml_config(xml_content):
    """Parse XML configuration from phone and extract key parameters"""
    try:
        # Handle the case where XML content might be in a form field key
        if isinstance(xml_content, dict):
            # If it's a dict, look for XML content in the keys
            for key, value in xml_content.items():
                if key.strip().startswith('<'):
                    # The XML content is in the key, value might contain additional data
                    xml_content = key + str(value) if value else key
                    break
            
            # If still a dict, convert to string representation
            if isinstance(xml_content, dict):
                xml_content = str(xml_content)
        
        # Clean up the XML content
        if isinstance(xml_content, str):
            # Remove any JSON escaping
            xml_content = xml_content.replace('\\n', '\n').replace('\\"', '"').replace('\\/', '/')
            
            # Find the actual XML content between <env> tags or <flat-profile> tags
            if '<flat-profile>' in xml_content:
                start = xml_content.find('<env>')
                if start == -1:
                    start = xml_content.find('<flat-profile>')
                    end = xml_content.find('</flat-profile>') + len('</flat-profile>')
                else:
                    end = xml_content.find('</env>') + len('</env>')
                
                if start != -1 and end != -1:
                    xml_content = xml_content[start:end]
        
        # Try to parse as proper XML first
        try:
            root = ET.fromstring(xml_content)
            config = {}
            
            # Extract flat-profile parameters
            flat_profile = root.find('.//flat-profile')
            if flat_profile is not None:
                for child in flat_profile:
                    # Clean up tag name and get text value
                    tag_name = child.tag
                    value = child.text or ''
                    # Remove ua attributes info for cleaner comparison
                    config[tag_name] = value
            
            return config
            
        except ET.ParseError as parse_error:
            logger.debug(f"XML parsing failed, trying manual parsing: {parse_error}")
            # If XML parsing fails, try manual parsing for phone config data
            return parse_phone_config_manually(xml_content)
        
    except Exception as e:
        logger.error(f"Error parsing phone XML config: {e}")
        logger.debug(f"XML content type: {type(xml_content)}")
        logger.debug(f"XML content preview: {str(xml_content)[:200]}...")
        return {}

def parse_phone_config_manually(xml_content):
    """Manually parse phone config when XML is malformed"""
    try:
        config = {}
        
        # Convert to string if not already
        if not isinstance(xml_content, str):
            xml_content = str(xml_content)
        
        # Look for parameter patterns like <Parameter-Name ua="na">Value</Parameter-Name>
        import re
        
        # Pattern to match XML-like tags with values (supporting hyphens and dots in tag names)
        # Handles cases like: <Admin_Passwd ua="na">admin123</Admin_Passwd>
        # and tags with hyphens: <ACD_Logged-off_LED ua="na">Yes</ACD_Logged-off_LED>
        pattern = r'<([A-Za-z_][A-Za-z0-9_\-\.]*)(?:\s[^>]*)?>(.*?)</\1>'
        matches = re.findall(pattern, xml_content, flags=re.DOTALL)
        
        for tag_name, value in matches:
            # Include parameters even if the value is empty to ensure completeness
            config[tag_name] = (value or '').strip()
        
        # Also look for self-closing tags or tags with just attributes
        # Pattern like: <Parameter-Name ua="na"/>
        pattern_self_closing = r'<([A-Za-z_][A-Za-z0-9_\-\.]*)[^>]*/>'
        self_closing_matches = re.findall(pattern_self_closing, xml_content)
        
        for tag_name in self_closing_matches:
            if tag_name not in config:  # Don't overwrite existing values
                config[tag_name] = ''  # Empty value for self-closing tags
        
        logger.info(f"Manual parsing extracted {len(config)} parameters")
        return config
        
    except Exception as e:
        logger.error(f"Manual parsing also failed: {e}")
        return {}

def generate_comparison_report(mac_address):
    """Generate comparison between expected config and phone reported config"""
    try:
        phone_config = get_phone_by_mac(mac_address)
        if not phone_config:
            return None
        
        common_config = load_common_config()
        comparison_config = load_comparison_config()
        
        # Get blacklist from config
        blacklist = comparison_config.get('blacklist', [])
        
        # Get latest phone report
        reports = []
        for filename in os.listdir(REPORTS_DIR):
            if filename.startswith(f"{mac_address}_config_"):
                filepath = os.path.join(REPORTS_DIR, filename)
                with open(filepath, 'r') as f:
                    reports.append(json.load(f))
        
        if not reports:
            return None
        
        # Get most recent report
        latest_report = max(reports, key=lambda x: x['timestamp'])
        
        # Build expected configuration using actual Cisco parameter names
        expected_config = {}
        
        # Start with common parameters  
        if common_config:
            for key, value in common_config.items():
                if key not in blacklist:  # Skip blacklisted parameters
                    expected_config[key] = value
        
        # Add phone-specific parameters (these override common parameters with same name)
        if phone_config:
            for key, value in phone_config.items():
                if key not in blacklist:  # Skip blacklisted parameters
                    expected_config[key] = value
        
        # Compare configurations
        comparison = {
            'mac_address': mac_address,
            'timestamp': datetime.now().isoformat(),
            'expected_config': expected_config,
            'reported_config': latest_report['data'],
            'differences': []
        };
        
        # Find differences - comprehensive parameter comparison
        reported = latest_report['data']
        
        # Add a count that excludes raw_xml for correct UI display
        try:
            reported_count = len(reported) - (1 if isinstance(reported, dict) and 'raw_xml' in reported else 0)
        except Exception:
            reported_count = 0
        comparison['reported_config_count'] = reported_count
        
        # Compare ALL parameters from expected config
        for param, expected_value in expected_config.items():
            if param in blacklist:
                continue  # Skip blacklisted parameters
                
            reported_value = reported.get(param)
            
            # For regular parameters, compare actual values
            if expected_value is not None:
                if str(reported_value) != str(expected_value):
                    comparison['differences'].append({
                        'parameter': param,
                        'expected': expected_value,
                        'reported': reported_value,
                        'type': 'value_mismatch'
                    })
        
        # Also check for reported parameters that aren't in our expected config
        # (this helps identify new parameters or configuration drift)
        unexpected_params = []
        for param, reported_value in reported.items():
            if param not in expected_config and param not in blacklist:
                unexpected_params.append({
                    'parameter': param,
                    'reported_value': reported_value
                })
        
        if unexpected_params:
            comparison['unexpected_parameters'] = unexpected_params
        
        return comparison
        
    except Exception as e:
        logger.error(f"Error generating comparison report: {e}")
        return None

def is_client_ip_authorized(client_ip):
    """Check if client IP is authorized (listed in phone configurations)"""
    if not client_ip:
        return False
    
    config = load_phone_config()
    service_config = load_service_config()
    ip_whitelist = service_config.get('ip_whitelist', {})

    if not config and not service_config:
        logger.warning("Cannot verify IP authorization: phone config and whitelist not loaded")
        return False
    
    # Get all authorized IPs from phone configurations
    authorized_ips = []
    for phone_id, phone_data in config.get('phones', {}).items():
        phone_ip = phone_data.get('ip_address')
        if phone_ip:
            authorized_ips.append(phone_ip)

    # Merge IPs from ip_whitelist (if any)
    if isinstance(ip_whitelist, list):
        authorized_ips.extend(ip_whitelist)
    elif isinstance(ip_whitelist, dict):
        authorized_ips.extend(ip_whitelist.values())
    elif isinstance(ip_whitelist, str):
        authorized_ips.append(ip_whitelist)
    # Remove duplicates
    authorized_ips = list(set(authorized_ips))
    # Check if client IP is in the authorized list
    is_authorized = client_ip in authorized_ips
    
    if not is_authorized:
        logger.warning(f"Unauthorized IP access attempt: {client_ip}. Authorized IPs: {authorized_ips}")
    else:
        logger.info(f"Authorized IP access: {client_ip}")
    
    return is_authorized

def get_authenticated_user(auth_header, service_config):
    """Extract and validate user from auth header, return user info or None"""
    if not auth_header:
        return None
    
    try:
        # Parse basic auth
        auth_type, auth_string = auth_header.split(' ', 1)
        if auth_type.lower() != 'basic':
            return None
        
        username, password = base64.b64decode(auth_string).decode('utf-8').split(':', 1)
        
        # Check credentials
        users = service_config.get('auth', {}).get('users', {})
        for user_id, user_data in users.items():
            if (user_data.get('username') == username and 
                user_data.get('password') == password):
                return {
                    'id': user_id,
                    'username': username,
                    'role': user_data.get('role', 'admin'),
                    'description': user_data.get('description', '')
                }
        
        return None
        
    except (ValueError, UnicodeDecodeError):
        return None

def requires_auth(allowed_roles=None):
    """Decorator that requires basic authentication with optional role restriction"""
    if allowed_roles is None:
        allowed_roles = ['admin']  # Default to admin only
    
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            service_config = load_service_config()
            auth_config = service_config.get('auth', {})
            
            if not auth_config.get('enabled', False):
                # Authentication disabled, allow access
                return f(*args, **kwargs)
            
            auth_header = request.headers.get('Authorization')
            user = get_authenticated_user(auth_header, service_config)
            
            if not user:
                return Response(
                    'Authentication required',
                    401,
                    {'WWW-Authenticate': 'Basic realm="Cisco MPP Provisioning Service"'}
                )
            
            # Check role authorization
            if user['role'] not in allowed_roles:
                logger.warning(f"Access denied for user {user['username']} with role {user['role']} - requires one of: {allowed_roles}")
                return Response(
                    'Access forbidden - insufficient privileges',
                    403
                )
            
            # Valid credentials and role
            return f(*args, **kwargs)
            
        return decorated
    return decorator

@app.route('/')
@requires_auth(['admin'])
def index():
    """Status page showing configured phones"""
    config = load_phone_config()
    if not config:
        return "Configuration not loaded", 500
    
    # Get service configuration for discovery mode status
    service_config = load_service_config()
    discovery_config = service_config.get('discovery', {})
    discovery_enabled = discovery_config.get('enabled', False)
    exclude_macs = discovery_config.get('exclude_macs', [])
    
    phones = config.get('phones', {})
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Cisco MPP Provisioning Service</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .status-active { color: green; }
        .status-inactive { color: red; }
        .status-discovery { color: orange; }
        .discovery-notice { 
            background: #fff3cd; 
            border: 1px solid #ffeaa7; 
            padding: 15px; 
            border-radius: 5px; 
            margin: 20px 0;
            border-left: 4px solid #f39c12;
        }
        .discovery-notice h3 { margin-top: 0; color: #e67e22; }
    </style>
</head>
<body>
    <h1>Cisco MPP Provisioning Service</h1>
    {% if discovery_enabled %}
    <div class="discovery-notice">
        <h3>🔍 Discovery Mode Active</h3>
        <p><strong>Status:</strong> Configuration serving disabled, reporting enabled for default config collection.</p>
        <p><strong>Effect:</strong> Phones will receive 404 responses for .xml configuration requests, allowing collection of factory default configurations via reporting.</p>
        {% if exclude_macs %}
        <p><strong>Excluded MACs:</strong> {{ exclude_macs|join(', ') }} (these phones still receive configuration)</p>
        {% endif %}
    </div>
    <p>Service Status: <span class="status-discovery">Discovery Mode</span></p>
    {% else %}
    <p>Service Status: <span class="status-active">Active</span></p>
    {% endif %}
    <p>Last Updated: {{ timestamp }}</p>
    
    <h2>Configured Phones</h2>
    <table>
        <tr>
            <th>Phone ID</th>
            <th>MAC Address</th>
            <th>Display Name</th>
            <th>User ID</th>
            <th>Station Name</th>
            <th>Config URL</th>
        </tr>
        {% for phone_id, phone in phones.items() %}
        <tr>
            <td>{{ phone_id }}</td>
            <td>{{ phone.mac }}</td>
            <td>{{ phone.display_name }}</td>
            <td>{{ phone.user_id }}</td>
            <td>{{ phone.station_name }}</td>
            <td><a href="/{{ phone.mac.replace(':', '') }}.xml">{{ phone.mac.replace(':', '') }}.xml</a></td>
        </tr>
        {% endfor %}
    </table>
    
    <h2>API Endpoints</h2>
    <ul>
        <li><code>/&lt;filename&gt;.xml</code> - Universal XML configuration endpoint (handles MAC, serial number, or any identifier) <em>- IP restricted, firmware update aware</em></li>
        <li><code>/status</code> - Service status with metrics (JSON)</li>
        <li><code>/health</code> - Health check endpoint</li>
        <li><code>/metrics</code> - Prometheus metrics endpoint</li>
        <li><code>/report</code> - Receive phone configuration reports (POST) <em>- IP restricted</em></li>
        <li><code>/reports</code> - View all received reports <em>- Authentication required</em></li>
        <li><code>/compare/&lt;mac_address&gt;</code> - Compare expected vs reported config <em>- Authentication required</em></li>
    </ul>
    
    <h2>Features</h2>
    <ul>
        <li><strong>IP Authorization:</strong> Configuration and report endpoints restricted to configured phone IPs</li>
        <li><strong>Web Authentication:</strong> Admin interface protected with basic authentication</li>
        <li><strong>Firmware Updates:</strong> Automatic firmware version checking and update XML generation</li>
        <li><strong>Monitoring:</strong> Prometheus metrics available at <a href="/metrics">/metrics</a></li>
        <li><strong>Configuration Comparison:</strong> Real-time comparison between expected and reported configurations</li>
        {% if discovery_enabled %}
        <li><strong>Discovery Mode:</strong> Default configuration collection mode - phones receive 404 responses for config requests</li>
        {% endif %}
    </ul>
    
    <h2>Configuration Reporting</h2>
    <p>Phones will automatically report their configuration to <code>{{ request.url_root }}report</code></p>
    <p><a href="/reports">View Configuration Reports →</a></p>
</body>
</html>
    """, phones=phones, 
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        discovery_enabled=discovery_enabled,
        exclude_macs=exclude_macs)

@app.route('/<filename>.xml')
def get_phone_config_universal(filename):
    """Universal XML configuration endpoint - handles any .xml request"""
    start_time = time.time()
    logger.info(f"XML configuration requested: {filename}.xml")
    
    # Step 0: Check discovery mode
    service_config = load_service_config()
    discovery_config = service_config.get('discovery', {})
    discovery_enabled = discovery_config.get('enabled', False)
    
    if discovery_enabled:
        # In discovery mode, check if this phone is excluded from discovery
        user_agent = request.headers.get('User-Agent', '')
        current_mac = None
        
        # Try to extract MAC from User-Agent for exclusion check
        if 'Cisco-' in user_agent and '(' in user_agent and ')' in user_agent:
            start_idx = user_agent.find('(') + 1
            end_idx = user_agent.find(')')
            potential_mac = user_agent[start_idx:end_idx]
            if len(potential_mac) == 12:
                current_mac = potential_mac.lower()
        
        # Also try filename as MAC
        if not current_mac:
            filename_clean = filename.replace(':', '').replace('-', '').lower()
            if len(filename_clean) == 12:
                current_mac = filename_clean
        
        # Check if this MAC is excluded from discovery mode
        exclude_macs = [mac.lower().replace(':', '').replace('-', '') for mac in discovery_config.get('exclude_macs', [])]
        
        if current_mac and current_mac in exclude_macs:
            logger.info(f"Phone {current_mac} excluded from discovery mode, serving configuration normally")
        else:
            logger.info(f"Discovery mode enabled - returning 404 for {filename}.xml to allow default config collection")
            return "Phone not found - discovery mode enabled", 404
    
    # Step 1: Check if client IP is authorized (only in normal mode)
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
    if not is_client_ip_authorized(client_ip):
        logger.warning(f"Access denied for IP {client_ip} requesting {filename}.xml")
        return "Access denied - IP not authorized", 403
    
    # Step 2: Check firmware version and potentially return firmware update XML
    user_agent = request.headers.get('User-Agent', '')
    firmware_config = load_firmware_config()
    
    # Skip firmware updates in discovery mode (unless phone is excluded)
    if not discovery_enabled or (current_mac and current_mac in exclude_macs):
        if needs_firmware_update(user_agent, firmware_config):
            logger.info(f"Firmware update required for User-Agent: {user_agent}")
            
            # Track metrics for firmware update response
            current_version, phone_model = extract_firmware_version_from_user_agent(user_agent)
            
            # Generate firmware update XML with model-specific support
            firmware_xml = generate_firmware_update_xml(firmware_config, phone_model)
            firmware_xml = prettify_xml(firmware_xml)
            
            # Get expected version (with model-specific support)
            expected_version = firmware_config.get('expected_version', '12.0.1')
            if firmware_config.get('model_specific', {}).get('enabled', False):
                model_versions = firmware_config.get('model_specific', {}).get('versions', {})
                if phone_model and phone_model in model_versions:
                    expected_version = model_versions[phone_model]
            
            # Track firmware update metrics
            phone_firmware_updates.labels(
                current_version=current_version or 'unknown',
                expected_version=expected_version,
                phone_model=phone_model or 'unknown'
            ).inc()
            
            phone_config_requests.labels(ip=client_ip, phone_mac='firmware-update').inc()
            phone_config_request_duration.observe(time.time() - start_time)
            
            logger.info(f"Firmware update XML served for {phone_model} version {current_version}")
            logger.info(f"Firmware update XML served for {phone_model} version {current_version}")
            return Response(firmware_xml, mimetype='application/xml')
    
    # Step 3: Try to find phone by the filename (could be MAC, serial number, etc.)
    phone_config = None
    mac_address = None
    
    # First, try to find phone by filename (could be MAC, serial number, phone ID, etc.)
    phone_config = get_phone_by_identifier(filename)
    if phone_config:
        # Get the actual MAC address for logging/tracking
        mac_address = phone_config.get('mac', '').replace(':', '').replace('-', '').lower()
        logger.info(f"Phone found by identifier '{filename}' -> MAC: {mac_address}")
    
    # Step 2: If not found by filename, try User-Agent parsing
    if not phone_config:
        user_agent = request.headers.get('User-Agent', '')
        logger.info(f"Filename '{filename}' not found as MAC, trying User-Agent: {user_agent}")
        
        # Extract MAC from Cisco phone User-Agent
        # Format: "Cisco-CP-8841-3PCC/11.0 (00562b043615)"
        if 'Cisco-' in user_agent and '(' in user_agent and ')' in user_agent:
            start = user_agent.find('(') + 1
            end = user_agent.find(')')
            potential_mac = user_agent[start:end]
            if len(potential_mac) == 12:  # MAC without separators
                phone_config = get_phone_by_mac(potential_mac)
                if phone_config:
                    mac_address = potential_mac
                    logger.info(f"Phone found by User-Agent MAC: {mac_address}")
    
    # Step 3: If still not found, try client IP mapping
    if not phone_config:
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
        logger.info(f"Trying IP-based lookup for client: {client_ip}")
        
        # Try to find phone by IP address
        config = load_phone_config()
        if config:
            for phone_id, phone_data in config.get('phones', {}).items():
                if phone_data.get('ip_address') == client_ip:
                    phone_config = phone_data
                    mac_address = phone_data.get('mac', '').replace(':', '').replace('-', '').lower()
                    logger.info(f"Phone found by IP mapping: {mac_address}")
                    break
    
    # Step 4: If still no phone found, return 404
    if not phone_config:
        logger.warning(f"No phone configuration found for request: filename='{filename}', User-Agent='{request.headers.get('User-Agent', '')}', IP='{request.environ.get('REMOTE_ADDR')}'")
        return "Phone not found", 404
    
    # Step 5: Generate and return XML configuration
    common_config = load_common_config()
    xml_content = generate_xml_config(phone_config, common_config)
    
    # Pretty print the XML
    xml_content = prettify_xml(xml_content)
    
    logger.info(f"Configuration served for phone with MAC: {mac_address} (requested as: {filename}.xml)")
    
    # Track metrics
    phone_config_requests.labels(ip=client_ip, phone_mac=mac_address).inc()
    phone_config_request_duration.observe(time.time() - start_time)
    
    return Response(xml_content, mimetype='application/xml')

@app.route('/status')
@requires_auth(['admin', 'monitor'])
def status():
    """API status endpoint with detailed metrics"""
    config = load_phone_config()
    common_config = load_common_config()
    service_config = load_service_config()
    
    # Calculate current metrics
    calculate_metrics()
    
    # Get discovery mode configuration
    discovery_config = service_config.get('discovery', {})
    discovery_enabled = discovery_config.get('enabled', False)
    
    # Get current metric values
    status_data = {
        'status': 'discovery' if discovery_enabled else 'active',
        'timestamp': datetime.now().isoformat(),
        'phones_configured': len(config.get('phones', {})) if config else 0,
        'common_config_loaded': bool(common_config),
        'discovery_mode': {
            'enabled': discovery_enabled,
            'exclude_macs': discovery_config.get('exclude_macs', []),
            'description': 'Configuration serving disabled for default config collection' if discovery_enabled else 'Normal operation'
        },
        'metrics': {
            'phone_config_differences': phone_config_differences._value._value,
            'phone_unexpected_params': phone_unexpected_params._value._value,
            'phone_activity_recent': phone_activity_recent._value._value,
            'reports_recent': reports_recent._value._value,
        },
        'service_config': {
            'metrics_enabled': service_config.get('monitoring', {}).get('metrics_enabled', True),
            'auth_enabled': service_config.get('auth', {}).get('enabled', False),
            'phone_activity_window_seconds': service_config.get('monitoring', {}).get('phone_activity_window', 3600),
            'report_activity_window_seconds': service_config.get('monitoring', {}).get('report_activity_window', 1800)
        }
    }
    
    return jsonify(status_data)

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.route('/report', methods=['POST'])
def receive_phone_report():
    """Receive configuration report from phone - expects raw XML POST data like PHP example"""
    return process_phone_report()

@app.route('/report/<mac_address>', methods=['POST'])
def receive_phone_report_by_mac(mac_address):
    """Receive configuration report from phone with MAC in URL"""
    return process_phone_report(mac_address)

@app.route('/reports')
@requires_auth(['admin'])
def list_reports():
    """List all phone reports"""
    try:
        reports = []
        for filename in os.listdir(REPORTS_DIR):
            if filename.endswith('.json'):
                filepath = os.path.join(REPORTS_DIR, filename)
                with open(filepath, 'r') as f:
                    report = json.load(f)
                    reports.append({
                        'filename': filename,
                        'mac_address': report.get('mac_address'),
                        'timestamp': report.get('timestamp'),
                        'report_type': report.get('report_type'),
                        'client_ip': report.get('client_ip')
                    })
        
        # Sort by timestamp (newest first)
        reports.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Phone Configuration Reports</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .btn { padding: 5px 10px; text-decoration: none; background: #007cba; color: white; border-radius: 3px; }
        .nav-links { 
            background: #f8f9fa; 
            padding: 15px; 
            border-radius: 5px; 
            margin-bottom: 20px;
            border-left: 4px solid #007cba;
        }
        .nav-links h3 { margin-top: 0; color: #007cba; }
        .nav-links a { 
            display: inline-block; 
            margin: 5px 10px 5px 0; 
            padding: 8px 12px; 
            background: #007cba; 
            color: white; 
            text-decoration: none; 
            border-radius: 3px; 
            font-size: 14px;
        }
        .nav-links a:hover { background: #0056b3; }
    </style>
</head>
<body>
    <h1>📋 Phone Configuration Reports</h1>
    <p>Total Reports: {{ reports|length }}</p>
    
    <div class="nav-links">
        <h3>🧭 Quick Navigation</h3>
        <a href="/">🏠 Main</a>
    </div>
    
    <table>
        <tr>
            <th>MAC Address</th>
            <th>Report Type</th>
            <th>Timestamp</th>
            <th>Client IP</th>
            <th>Actions</th>
        </tr>
        {% for report in reports %}
        <tr>
            <td>{{ report.mac_address }}</td>
            <td>{{ report.report_type }}</td>
            <td>{{ report.timestamp }}</td>
            <td>{{ report.client_ip }}</td>
            <td>
                <a href="/report-detail/{{ report.filename }}" class="btn">View</a>
                <a href="/compare/{{ report.mac_address }}" class="btn">Compare</a>
            </td>
        </tr>
        {% endfor %}
    </table>
    
    <h2>Configuration Instructions</h2>
    <p>To have phones report their configuration, add this to your XML config:</p>
    <pre>&lt;Report_Rule ua="na"&gt;http://{{ request.host }}/report&lt;/Report_Rule&gt;</pre>
</body>
</html>
        """, reports=reports)
        
    except Exception as e:
        logger.error(f"Error listing reports: {e}")
        return f"Error loading reports: {e}", 500

@app.route('/report-detail/<filename>')
@requires_auth(['admin'])
def view_report_detail(filename):
    """View detailed report"""
    try:
        filepath = os.path.join(REPORTS_DIR, filename)
        if not os.path.exists(filepath):
            return "Report not found", 404
        
        with open(filepath, 'r') as f:
            report = json.load(f)
        
        return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Report Detail - {{ report.mac_address }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .report-header { background: #f5f5f5; padding: 15px; border-radius: 5px; }
        .config-data { background: #fff; border: 1px solid #ddd; padding: 15px; margin: 10px 0; }
        pre { background: #f8f8f8; padding: 10px; overflow-x: auto; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .nav-links { 
            background: #f8f9fa; 
            padding: 15px; 
            border-radius: 5px; 
            margin-bottom: 20px;
            border-left: 4px solid #007cba;
        }
        .nav-links h3 { margin-top: 0; color: #007cba; }
        .nav-links a { 
            display: inline-block; 
            margin: 5px 10px 5px 0; 
            padding: 8px 12px; 
            background: #007cba; 
            color: white; 
            text-decoration: none; 
            border-radius: 3px; 
            font-size: 14px;
        }
        .nav-links a:hover { background: #0056b3; }
    </style>
</head>
<body>
    <h1>📄 Configuration Report Detail</h1>
    
    <div class="nav-links">
        <h3>🧭 Quick Navigation</h3>
        <a href="/compare/{{ report.mac_address }}">🔍 Compare Config</a>
        <a href="/reports">📋 Reports</a>
        <a href="/">🏠 Main</a>
    </div>
    
    <div class="report-header">
        <p><strong>MAC Address:</strong> {{ report.mac_address }}</p>
        <p><strong>Timestamp:</strong> {{ report.timestamp }}</p>
        <p><strong>Report Type:</strong> {{ report.report_type }}</p>
        <p><strong>Client IP:</strong> {{ report.client_ip }}</p>
        <p><strong>User Agent:</strong> {{ report.user_agent }}</p>
    </div>
    
    <h2>Configuration Data</h2>
    <div class="config-data">
        {% if report.data.raw_xml %}
            <h3>Raw XML Configuration</h3>
            <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 400px; overflow-y: auto;">{{ report.data.raw_xml | replace('\\n', '\n') | replace('\\"', '"') | replace('\\/', '/') }}</pre>
            
            <h3>Parsed Configuration Parameters</h3>
            <table>
                <tr><th>Parameter</th><th>Value</th></tr>
                {% for key, value in report.data.items() %}
                    {% if key != 'raw_xml' %}
                    <tr><td>{{ key }}</td><td>{{ value }}</td></tr>
                    {% endif %}
                {% endfor %}
            </table>
        {% else %}
            <h3>Configuration Data</h3>
            {% if report.data is mapping %}
                <table>
                    <tr><th>Parameter</th><th>Value</th></tr>
                    {% for key, value in report.data.items() %}
                        <tr>
                            <td style="word-break: break-all;">{{ key[:100] }}{% if key|length > 100 %}...{% endif %}</td>
                            <td style="word-break: break-all;">{{ value[:200] }}{% if value|length > 200 %}...{% endif %}</td>
                        </tr>
                    {% endfor %}
                </table>
            {% else %}
                <pre style="white-space: pre-wrap; word-wrap: break-word;">{{ report.data }}</pre>
            {% endif %}
        {% endif %}
    </div>
</body>
</html>
        """, report=report)
        
    except Exception as e:
        logger.error(f"Error viewing report: {e}")
        return f"Error loading report: {e}", 500

@app.route('/compare/<mac_address>')
@requires_auth(['admin'])
def compare_configurations(mac_address):
    """Compare expected vs reported configuration"""
    try:
        mac_clean = mac_address.replace(':', '').replace('-', '').lower()
        comparison = generate_comparison_report(mac_clean)
        
        if not comparison:
            return "No comparison data available", 404
        
        return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Configuration Comparison - {{ comparison.mac_address }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .match { background: #d4edda; }
        .mismatch { background: #f8d7da; }
        .missing { background: #fff3cd; }
        .nav-links { 
            background: #f8f9fa; 
            padding: 15px; 
            border-radius: 5px; 
            margin-bottom: 20px;
            border-left: 4px solid #007cba;
        }
        .nav-links h3 { margin-top: 0; color: #007cba; }
        .nav-links a { 
            display: inline-block; 
            margin: 5px 10px 5px 0; 
            padding: 8px 12px; 
            background: #007cba; 
            color: white; 
            text-decoration: none; 
            border-radius: 3px; 
            font-size: 14px;
        }
        .nav-links a:hover { background: #0056b3; }
        .section-header { margin-top: 30px; }
    </style>
</head>
<body>
    <h1>📊 Configuration Comparison</h1>
    <p><strong>MAC Address:</strong> {{ comparison.mac_address }}</p>
    <p><strong>Comparison Time:</strong> {{ comparison.timestamp }}</p>
    
    <div class="nav-links">
        <h3>🧭 Quick Navigation</h3>
        {% if comparison.differences %}
        <a href="#differences">🔍 Differences ({{ comparison.differences|length }})</a>
        {% endif %}
        {% if comparison.unexpected_parameters %}
        <a href="#unexpected">⚠️ Unexpected Parameters ({{ comparison.unexpected_parameters|length }})</a>
        {% endif %}
        <a href="#expected">📋 Expected Config ({{ comparison.expected_config|length }})</a>
        <a href="#reported">📱 Reported Config ({{ comparison.reported_config_count }})</a>
        <a href="/reports">📋 Reports</a>
        <a href="/">🏠 Main</a>
    </div>
    
    {% if comparison.differences %}
    <h2 id="differences" class="section-header">🔍 Configuration Differences ({{ comparison.differences|length }})</h2>
    <table>
        <tr>
            <th>Parameter</th>
            <th>Expected Value</th>
            <th>Reported Value</th>
            <th>Check Type</th>
        </tr>
        {% for diff in comparison.differences %}
        <tr class="mismatch">
            <td>{{ diff.parameter }}</td>
            <td>{{ diff.expected }}</td>
            <td>{{ diff.reported }}</td>
            <td>
                {% if diff.type == 'existence_check' %}
                    <span style="color: orange;">●</span> Existence Check
                {% else %}
                    <span style="color: red;">●</span> Value Mismatch
                {% endif %}
            </td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <h2 id="differences" class="section-header">✅ All Parameters Match</h2>
    <p>The phone's reported configuration matches all expected values.</p>
    {% endif %}
    
    {% if comparison.unexpected_parameters %}
    <h2 id="unexpected" class="section-header">⚠️ Unexpected Parameters ({{ comparison.unexpected_parameters|length }})</h2>
    <p>These parameters are reported by the phone but not defined in your configuration:</p>
    {% if comparison.unexpected_parameters %}
    <p><a href="/export-unexpected/{{ comparison.mac_address }}" style="background: #28a745; color: white; padding: 8px 12px; text-decoration: none; border-radius: 3px; display: inline-block; margin-bottom: 10px;">📤 Export as YAML for common.yml</a></p>
    {% endif %}
    <table>
        <tr>
            <th>Parameter</th>
            <th>Reported Value</th>
        </tr>
        {% for param in comparison.unexpected_parameters %}
        <tr style="background-color: #fff3cd;">
            <td>{{ param.parameter }}</td>
            <td>{{ param.reported_value }}</td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}
    
    <h2 id="expected" class="section-header">📋 Expected Configuration ({{ comparison.expected_config|length }} parameters)</h2>
    <table>
        <tr><th>Parameter</th><th>Value</th></tr>
        {% for key, value in comparison.expected_config.items() %}
        <tr><td>{{ key }}</td><td>{{ value }}</td></tr>
        {% endfor %}
    </table>
    
    <h2 id="reported" class="section-header">📱 Reported Configuration ({{ comparison.reported_config_count }} parameters)</h2>
    <table>
        <tr><th>Parameter</th><th>Value</th></tr>
        {% for key, value in comparison.reported_config.items() %}
        <tr><td>{{ key }}</td><td>{{ value }}</td></tr>
        {% endfor %}
    </table>
    
    <p id="back"><a href="/reports">← Back to Reports</a></p>
</body>
</html>
        """, comparison=comparison)
        
    except Exception as e:
        logger.error(f"Error comparing configurations: {e}")
        return f"Error comparing configurations: {e}", 500

@app.route('/export-unexpected/<mac_address>')
@requires_auth(['admin'])
def export_unexpected_parameters(mac_address):
    """Export unexpected parameters as YAML for common.yml"""
    try:
        mac_clean = mac_address.replace(':', '').replace('-', '').lower()
        comparison = generate_comparison_report(mac_clean)
        
        if not comparison or 'unexpected_parameters' not in comparison:
            return "No unexpected parameters found", 404
        
        # Create YAML content with the unexpected parameters
        yaml_content = "# Unexpected parameters exported from comparison report\n"
        yaml_content += f"# MAC: {mac_address}\n"
        yaml_content += f"# Exported on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        yaml_content += "# Add these to your config/common.yml under the 'common:' section\n\n"
        
        # Group parameters with their reported values as defaults
        export_data = {}
        for param in comparison['unexpected_parameters']:
            param_name = param['parameter']
            param_value = param['reported_value']
            
            # Add comment for each parameter
            yaml_content += f"# Parameter: {param_name}\n"
            # Convert all values to strings to ensure consistent quoting
            if param_value is None:
                export_data[param_name] = ''
            else:
                export_data[param_name] = str(param_value)
        
        # Custom YAML dumper to always quote string values while keeping keys plain
        class QuotedDumper(yaml.SafeDumper):
            pass
        
        def repr_str(dumper, data):
            # Always quote string values using single quotes
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style="'")
        
        def repr_mapping(dumper, tag, mapping, flow_style=None):
            node = yaml.SafeDumper.represent_mapping(dumper, tag, mapping, flow_style)
            # Ensure keys remain unquoted/plain style
            for key_node, value_node in node.value:
                if key_node.tag == 'tag:yaml.org,2002:str':
                    key_node.style = None
            return node
        
        QuotedDumper.add_representer(str, repr_str)
        QuotedDumper.represent_mapping = repr_mapping
        
        # Convert to YAML format with quoted values
        yaml_params = yaml.dump(export_data, Dumper=QuotedDumper, default_flow_style=False, allow_unicode=True, sort_keys=True, width=120)
        yaml_content += yaml_params
        
        # Return as downloadable file
        return Response(
            yaml_content,
            mimetype='application/x-yaml',
            headers={
                'Content-Disposition': f'attachment; filename="unexpected_params_{mac_clean}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.yml"',
                'Content-Type': 'application/x-yaml; charset=utf-8'
            }
        )
        
    except Exception as e:
        logger.error(f"Error exporting unexpected parameters: {e}")
        return f"Error exporting parameters: {e}", 500

def calculate_metrics():
    """Calculate metrics for Prometheus"""
    try:
        service_config = load_service_config()
        phone_window = service_config.get('monitoring', {}).get('phone_activity_window', 3600)
        report_window = service_config.get('monitoring', {}).get('report_activity_window', 1800)
        
        now = datetime.now()
        phone_cutoff = now - timedelta(seconds=phone_window)
        report_cutoff = now - timedelta(seconds=report_window)
        
        # Count phones with differences and unexpected parameters
        phones_with_differences = 0
        phones_with_unexpected = 0
        recent_phones = set()
        recent_reports_count = 0
        
        config = load_phone_config()
        if config:
            phones = config.get('phones', {})
            
            for phone_id, phone_data in phones.items():
                mac_address = phone_data.get('mac', '').replace(':', '').replace('-', '').lower()
                
                # Get latest report for this phone
                latest_report = None
                latest_timestamp = None
                
                for filename in os.listdir(REPORTS_DIR):
                    if filename.startswith(f"{mac_address}_config_"):
                        try:
                            filepath = os.path.join(REPORTS_DIR, filename)
                            with open(filepath, 'r') as f:
                                report = json.load(f)
                                report_time = datetime.fromisoformat(report.get('timestamp', ''))
                                
                                # Count recent reports
                                if report_time >= report_cutoff:
                                    recent_reports_count += 1
                                
                                # Track most recent report per phone
                                if latest_timestamp is None or report_time > latest_timestamp:
                                    latest_timestamp = report_time
                                    latest_report = report
                                    
                                    # Count recent phone activity
                                    if report_time >= phone_cutoff:
                                        recent_phones.add(mac_address)
                                        
                        except (ValueError, json.JSONDecodeError, FileNotFoundError):
                            continue
                
                # Check for differences in latest report
                if latest_report:
                    comparison = generate_comparison_report(mac_address)
                    if comparison:
                        if comparison.get('differences'):
                            phones_with_differences += 1
                        if comparison.get('unexpected_parameters'):
                            phones_with_unexpected += 1
        
        # Update Prometheus metrics
        phone_config_differences.set(phones_with_differences)
        phone_unexpected_params.set(phones_with_unexpected)
        phone_activity_recent.set(len(recent_phones))
        reports_recent.set(recent_reports_count)
        
    except Exception as e:
        logger.error(f"Error calculating metrics: {e}")

@app.route('/metrics')
@requires_auth(['admin', 'monitor'])
def metrics():
    """Prometheus metrics endpoint"""
    service_config = load_service_config()
    if not service_config.get('monitoring', {}).get('metrics_enabled', True):
        return "Metrics disabled", 404
    
    # Calculate current metrics
    calculate_metrics()
    
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

def extract_firmware_version_from_user_agent(user_agent):
    """Extract firmware version from Cisco phone User-Agent string"""
    try:
        # User-Agent format: "Cisco-CP-6841-3PCC/12.0.1 (c4c603731f67)"
        if 'Cisco-' in user_agent and '/' in user_agent:
            # Split by '/' and get the version part
            parts = user_agent.split('/')
            if len(parts) >= 2:
                # Get version part, remove any trailing info like " (mac)"
                version_part = parts[1].split(' ')[0]
                # Extract model for model-specific versions
                model_part = parts[0].replace('Cisco-', '') if parts[0].startswith('Cisco-') else None
                return version_part, model_part
        return None, None
    except Exception as e:
        logger.debug(f"Error extracting firmware version from User-Agent: {e}")
        return None, None

def needs_firmware_update(user_agent, firmware_config):
    """Check if phone needs firmware update based on User-Agent"""
    if not firmware_config.get('update_enabled', False):
        return False
    
    current_version, phone_model = extract_firmware_version_from_user_agent(user_agent)
    if not current_version:
        logger.debug("Could not extract firmware version from User-Agent")
        return False
    
    # Check for model-specific version first
    expected_version = firmware_config.get('expected_version', '12.0.1')
    if firmware_config.get('model_specific', {}).get('enabled', False):
        model_versions = firmware_config.get('model_specific', {}).get('versions', {})
        if phone_model and phone_model in model_versions:
            expected_version = model_versions[phone_model]
            logger.info(f"Using model-specific version {expected_version} for {phone_model}")
    
    needs_update = current_version != expected_version
    if needs_update:
        logger.info(f"Firmware update needed: {current_version} -> {expected_version} for model {phone_model}")
    else:
        logger.debug(f"Firmware version {current_version} is current for model {phone_model}")
    
    return needs_update

def generate_firmware_update_xml(firmware_config, phone_model=None):
    """Generate XML for firmware update"""
    log_messages = firmware_config.get('log_messages', {})
    
    # Get upgrade URL - check for model-specific URL first
    upgrade_url = firmware_config.get('upgrade_url', '')
    if firmware_config.get('model_specific', {}).get('enabled', False) and phone_model:
        model_urls = firmware_config.get('model_specific', {}).get('urls', {})
        if phone_model in model_urls:
            upgrade_url = model_urls[phone_model]
            logger.info(f"Using model-specific firmware URL for {phone_model}: {upgrade_url}")
    
    xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<device>
  <flat-profile>
    <Upgrade_Enable ua="na">Yes</Upgrade_Enable>
    <Upgrade_Error_Retry_Delay ua="na">{firmware_config.get('retry_delay', 3600)}</Upgrade_Error_Retry_Delay>
    <Upgrade_Rule ua="na">{upgrade_url}</Upgrade_Rule>
    <Log_Upgrade_Request_Msg ua="na">{log_messages.get('upgrade_request', '$PN $MAC -- Requesting upgrade $SCHEME://$SERVIP:$PORT$PATH')}</Log_Upgrade_Request_Msg>
    <Log_Upgrade_Success_Msg ua="na">{log_messages.get('upgrade_success', '$PN $MAC -- Successful upgrade $SCHEME://$SERVIP:$PORT$PATH -- $ERR')}</Log_Upgrade_Success_Msg>
    <Log_Upgrade_Failure_Msg ua="na">{log_messages.get('upgrade_failure', '$PN $MAC -- Upgrade failed: $ERR')}</Log_Upgrade_Failure_Msg>
    <User_Password></User_Password>
  </flat-profile>
</device>"""
    
    return xml_content

def process_phone_report(mac_address=None):
    """Shared function to process phone reports - expects raw XML POST data like PHP example"""
    try:
        # Check discovery mode - bypass IP authorization if discovery is enabled
        service_config = load_service_config()
        discovery_config = service_config.get('discovery', {})
        discovery_enabled = discovery_config.get('enabled', False)
        
        # Check if client IP is authorized (bypass in discovery mode)
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
        if not discovery_enabled and not is_client_ip_authorized(client_ip):
            logger.warning(f"Access denied for IP {client_ip} attempting to submit report")
            return jsonify({'error': 'Access denied - IP not authorized'}), 403
        
        if discovery_enabled:
            logger.info(f"Discovery mode enabled - accepting report from IP {client_ip}")
        
        # Get MAC address if not provided in URL
        if not mac_address:
            # Try to get MAC from User-Agent header
            user_agent = request.headers.get('User-Agent', '')
            if 'Cisco-' in user_agent and '(' in user_agent and ')' in user_agent:
                start = user_agent.find('(') + 1
                end = user_agent.find(')')
                potential_mac = user_agent[start:end]
                if len(potential_mac) == 12:
                    mac_address = potential_mac
            
            # Try to extract from XML content if still no MAC
            if not mac_address:
                try:
                    xml_content = request.get_data(as_text=True)
                    root = ET.fromstring(xml_content)
                    # Look for MAC in various XML elements
                    for tag in ['mac', 'MAC', 'macAddress', 'Mac_Address']:
                        mac_elem = root.find(f'.//{tag}')
                        if mac_elem is not None and mac_elem.text:
                            mac_address = mac_elem.text.replace(':', '').replace('-', '')
                            break
                except ET.ParseError:
                    logger.debug("Could not parse XML to extract MAC address")
            
            if not mac_address:
                logger.warning("Phone report received without MAC address")
                return jsonify({'error': 'MAC address required'}), 400
        
        # Clean MAC address
        mac_clean = mac_address.replace(':', '').replace('-', '').lower()
        
        # Read raw XML POST data directly (as per phone documentation)
        # Phone sends raw XML via HTTP POST, not form-encoded or JSON data
        raw_xml_data = request.get_data(as_text=True)
        
        if not raw_xml_data:
            logger.warning(f"Phone report received with empty POST data for MAC {mac_clean}")
            return jsonify({'error': 'No data received'}), 400
        
        # Parse the XML configuration data
        report_data = parse_phone_xml_config(raw_xml_data)
        report_data['raw_xml'] = raw_xml_data
        report_type = 'config'
        
        # Save the report
        filename = save_phone_report(mac_clean, report_data, report_type)
        
        if filename:
            logger.info(f"Phone report received from MAC {mac_clean}: {report_type}")
            phone_reports_received.labels(phone_mac=mac_clean, report_type=report_type).inc()
            return jsonify({
                'status': 'success',
                'message': 'Report received',
                'filename': filename,
                'mac': mac_clean
            })
        else:
            return jsonify({'error': 'Failed to save report'}), 500
            
    except Exception as e:
        logger.error(f"Error processing phone report: {e}")
        return jsonify({'error': 'Internal server error'}), 500



if __name__ == '__main__':
    try:
        # Ensure directories exist
        os.makedirs('/app/logs', exist_ok=True)
        os.makedirs('/app/reports', exist_ok=True)
        
        logger.info("Starting Cisco MPP Provisioning Service")
        
        # Test configuration loading
        phone_config = load_phone_config()
        common_config = load_common_config()
        
        if not phone_config:
            logger.warning("Phone configuration not loaded, but continuing...")
        if not common_config:
            logger.warning("Common configuration not loaded, but continuing...")
        
        logger.info(f"Starting Flask app on 0.0.0.0:8080")
        app.run(host='0.0.0.0', port=8080, debug=False)
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        print(f"ERROR: Failed to start application: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
