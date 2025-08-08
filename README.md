# Cisco MPP Phone Provisioning Service

Docker-based HTTP service that provides dynamic XML configuration provisioning for Cisco Multiplatform Phones (MPP). Automatically serves phone-specific configurations, firmware updates, and configuration validation.

> ⚠️ **Notice**: This service was primarily built with GitHub Copilot assistance but includes extensive human adjustments and testing. While tested, there may be edge cases or issues that haven't been identified. **Always test in a non-production environment first** and ensure you have complete backups before running on production systems. There is jank in the code, feel free to PR :)


## Features

- **Dynamic XML Generation**: Phone-specific configurations from YAML files
- **Universal Identifiers**: Supports MAC addresses, serial numbers, and custom identifiers  
- **Automatic Firmware Updates**: Version checking and upgrade XML delivery
- **Configuration Reporting**: Phones report actual config for validation
- **Configuration Comparison**: Compare expected vs actual phone settings
- **Discovery Mode**: Collect factory configurations from reset phones
- **IP-based Access Control**: Restrict endpoints to authorized phone IPs
- **Role-based Authentication**: Admin/monitor access for web interfaces
- **Prometheus Monitoring**: Comprehensive metrics and Grafana dashboards
- **Docker Deployment**: Easy and fast deployment with docker compose

## Quick Start

```bash
# Clone and start
git clone <repository>
cd docker-cisco-mpp-provisioning
docker-compose up -d

# Access web interface
http://localhost:8080
```

## Configuration Files

### Core Configuration

| File | Purpose |
|------|---------|
| `config/phones.yml` | Phone-specific settings (MAC, extensions, users) |
| `config/common.yml` | Shared settings (SIP server, timezone, directories) |
| `config/serviceconfig.yml` | Service behavior (discovery mode, auth, monitoring) |
| `config/firmware.yml` | Firmware update settings and URLs |
| `config/schema.yml` | XML structure and parameter definitions |
| `config/comparison.yml` | Configuration comparison rules and blacklists |

### Phone Configuration (`phones.yml`)

```yaml
phones:
  phone-01:
    mac: "00:11:22:33:44:55"
    ip_address: "192.168.1.10"
    # Cisco MPP Parameters
    Host_Name: "office-phone-01"
    Display_Name_1_: "Office Phone"
    User_ID_1_: "200"
    Password_1_: "your-sip-password"
    Station_Name: "phone-01"
    Station_Display_Name: "Office Phone (200)"

  phone-02:
    mac: "00:11:22:33:44:66"
    ip_address: "192.168.1.11"
    Host_Name: "office-phone-02"
    Display_Name_1_: "Reception"
    User_ID_1_: "206"
    Password_1_: "your-sip-password"
    Station_Name: "phone-02"
    Station_Display_Name: "Reception (206)"
```

### Common Configuration (`common.yml`)

```yaml
common:
  # SIP Proxy Configuration
  Proxy_1_: '192.168.1.100'
  
  # Administrative Settings
  Admin_Password: 'admin1234'

  # Time and Regional Settings
  Time_Zone: 'GMT+02:00'
  Daylight_Saving_Time_Enable: 'No'
  Time_Format: '24hr'
  Primary_NTP_Server: '192.168.1.1'
  
  # Directory Services
  XML_Directory_Service_Name: 'Company Directory'
  XML_Directory_Service_URL: 'http://your-server:8811/xml_directory.php'
  Personal_Directory_Enable: 'No'

  # Provisioning Settings
  Resync_Periodic: '120'
  Resync_Random_Delay: '10'
  Profile_Rule: 'http://your-server:8080/$MA.xml'
  Report_Rule: 'http://your-server:8080/report'
  Report_To_Server: 'On Local Change'
  Upload_Delay_On_Local_Change: '10'
  
  # Line Key Defaults
  Extended_Function_2_: 'fnc=sd;ext=161@$PROXY;nme=Security;'
  Short_Name_2_: 'Security'
  Short_Name_1_: '$USER'
```

### Service Configuration (`serviceconfig.yml`)

```yaml
# Discovery Mode - collect factory configs
discovery:
  enabled: false           # Enable to capture default configs
  exclude_macs: []         # MACs that still get normal config

# Monitoring
monitoring:
  metrics_enabled: true
  phone_activity_window: 3600    # Phone activity tracking (seconds)
  report_activity_window: 1800   # Report activity tracking (seconds)

# Authentication
auth:
  enabled: false           # Enable basic auth for web interface
  users:
    admin1:
      username: "admin"
      password: "secret"
      role: "admin"
    monitor1:
      username: "monitor"
      password: "readonly"
      role: "monitor"

# IP Whitelisting
ip_whitelist:
  - "192.168.1.200"      # Example: debugging PC
```

### Firmware Updates (`firmware.yml`)

```yaml
firmware:
  # Enable/disable firmware update functionality
  update_enabled: true
  
  # Expected firmware version for all phones
  expected_version: "12.0.1"
  
  # Firmware download URL (TFTP or HTTP)
  upgrade_url: "tftp://192.168.1.100/firmware/cmterm-68xx-3pcc.12-0-1-00001.cop"
  
  # Retry delay in seconds when upgrade fails
  retry_delay: 3600
  
  # Custom log messages with placeholders
  log_messages:
    upgrade_request: "$PN $MAC -- Requesting upgrade $SCHEME://$SERVIP:$PORT$PATH"
    upgrade_success: "$PN $MAC -- Successful upgrade $SCHEME://$SERVIP:$PORT$PATH -- $ERR"
    upgrade_failure: "$PN $MAC -- Upgrade failed: $ERR"
  
  # Optional: Phone model specific firmware versions and URLs
  # When enabled, different phone models can have different firmware versions and download URLs
  model_specific:
    enabled: false
    versions: {}
    urls: {}
    # Example when enabled:
    # versions:
    #   "CP-6841-3PCC": "12.0.1"
    #   "CP-8841-3PCC": "12.0.2"
    # urls:
    #   "CP-6841-3PCC": "tftp://192.168.1.100/firmware/cmterm-68xx-3pcc.12-0-1-00001.cop"
    #   "CP-8841-3PCC": "tftp://192.168.1.100/firmware/cmterm-88xx-3pcc.12-0-2-00001.cop"
```

### Schema Configuration (`schema.yml`)

```yaml
schema:
  # XML structure definition
  xml_structure:
    device:
      flat-profile: 'DYNAMIC_PARAMS'
  
  # All available Cisco MPP parameters
  flat_profile_params:
    ACD_Available_LED: ''
    ACD_Status_1_: 'Sync From Server'
    Admin_Password: ''
    Alert_Tone: '600@-19;.2(.05/0.05/1)'
    Display_Name_1_: ''
    Host_Name: ''
    Primary_NTP_Server: ''
    Proxy_1_: ''
    Report_Rule: ''
    Station_Name: ''
    Time_Zone: 'GMT+01:00'
    User_ID_1_: ''
    # ... (1000+ parameters available)
```

### Comparison Configuration (`comparison.yml`)

```yaml
comparison:
  # Parameters to exclude from comparison (sensitive or unreliable)
  blacklist:
    - mac                      # Not a Cisco parameter
    - ip_address              # Not a Cisco parameter
    - serial_number           # Not a Cisco parameter
    - raw_xml                 # Raw data, not a parameter
    - Admin_Password          # Sensitive
    - User_Password           # Sensitive
    - SIP_Password            # Sensitive
    - Set_Local_Date__mm_dd_yyyy_  # Dynamic timestamps
    - Set_Local_Time__HH_mm_       # Dynamic timestamps
```

## API Endpoints

### Phone Configuration
- `GET /<identifier>.xml` - Universal config endpoint (MAC/serial/ID)
  - IP restricted, supports firmware updates
  - Handles discovery mode

### Web Interface
- `GET /` - Main dashboard (requires auth)
- `GET /reports` - Configuration reports list (requires auth)
- `GET /report-detail/<filename>` - Detailed report view (requires auth)
- `GET /compare/<mac>` - Expected vs actual config comparison (requires auth)
- `GET /export-unexpected/<mac>` - Export unexpected parameters as YAML (requires auth)

### Phone Reporting
- `POST /report` - Receive config reports (IP restricted)
- `POST /report/<mac>` - Receive config for specific MAC (IP restricted)

### System
- `GET /status` - Service status with metrics (requires auth)
- `GET /health` - Health check endpoint
- `GET /metrics` - Prometheus metrics (requires auth)

## Special Features

### Discovery Mode
Enable in `serviceconfig.yml` to collect factory configurations:
- Returns 404 for config requests (phones use defaults)
- Reporting endpoints remain active
- IP authorization bypassed
- Excludes specific MACs if needed

When enabled, phones fall back to factory defaults and report their configuration, allowing you to capture baseline settings for new phone models or reference configurations.

### Configuration Comparison
Automatically compares expected (YAML) vs reported (phone) configurations:
- Identifies mismatches and missing parameters
- Excludes sensitive data (passwords, timestamps)
- Exports unexpected parameters as YAML
- Real-time validation of your YAML configurations

### Firmware Updates
Intercepts config requests to deliver firmware updates:
- Extracts version from User-Agent header: `Cisco-CP-6841-3PCC/12.0.1 (001122334455)`
- Supports model-specific versions and URLs
- Tracks update metrics
- Returns upgrade XML for outdated phones

Generated firmware update XML:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<device>
  <flat-profile>
    <Upgrade_Enable ua="na">Yes</Upgrade_Enable>
    <Upgrade_Rule ua="na">tftp://server/firmware.cop</Upgrade_Rule>
    <Upgrade_Error_Retry_Delay ua="na">3600</Upgrade_Error_Retry_Delay>
  </flat-profile>
</device>
```

### IP Authorization
Restricts access to phone endpoints:
- Uses IPs from `phones.yml`
- Additional IPs in `serviceconfig.yml` whitelist
- Bypassed in discovery mode

### Configuration Reporting
Phones automatically report their configuration for validation:

1. **Report Structure**: JSON files with timestamp, MAC, configuration data
2. **Report Storage**: Saved in `reports/` directory
3. **Comparison**: Expected (YAML) vs reported (phone) configurations
4. **Parameter Export**: Export unexpected parameters as YAML

Report data structure:
```json
{
  "timestamp": "2025-08-08T10:30:00",
  "mac_address": "001122334455",
  "report_type": "config",
  "client_ip": "192.168.1.10",
  "user_agent": "Cisco-CP-6841-3PCC/11.0 (001122334455)",
  "data": {
    "Station_Name": "phone-01",
    "Display_Name_1_": "Office Phone",
    "User_ID_1_": "200",
    "raw_xml": "<?xml version=\"1.0\"?>..."
  }
}
```

## Monitoring

### Prometheus Metrics
- `phone_config_requests_total{ip, phone_mac}` - Configuration requests by IP/MAC
- `phone_reports_received_total{phone_mac, report_type}` - Reports received by MAC/type
- `phone_config_differences` - Phones with config mismatches
- `phone_firmware_updates_total{current_version, expected_version, phone_model}` - Firmware updates served
- `phone_activity_recent` - Recent phone activity
- `reports_recent` - Recent report activity
- `phone_config_request_duration_seconds` - Config request processing time

### Grafana Dashboard
Pre-configured dashboard available in `grafana/grafana-dashboard.json` with panels for:
- Phone activity overview
- Configuration request rates
- Firmware update tracking
- Configuration differences
- Report activity

### Prometheus Configuration
Add to your `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'cisco-mpp-provisioning'
    static_configs:
      - targets: ['your-server:8080']
    scrape_interval: 30s
    metrics_path: /metrics
```

## Docker Deployment

### Services
- **app**: Python Flask application (port 8080)
- **nginx**: Reverse proxy with SSL termination (port 8080)

### Volumes
- `./config:/app/config` - Configuration files
- `./reports:/app/reports` - Phone reports storage
- `./logs:/app/logs` - Application logs

### Environment
Set in `docker-compose.yml`:
- `FLASK_ENV=production`
- Custom timezone and logging

## Security

### Authentication
- Basic HTTP authentication for web interface
- Role-based access (admin/monitor)
- Configurable users and passwords

### IP Restrictions
- Configuration endpoints limited to phone IPs
- Whitelist support for debugging
- Discovery mode bypass available

### Data Protection
- Sensitive parameters excluded from comparisons
- Password fields blacklisted in reports
- Secure configuration validation

## Usage Examples

### Enable Phone Reporting
Add to phone configuration in `common.yml`:
```yaml
Report_Rule: "http://your-server/report"
Report_To_Server: "On Local Change"
```

### Compare Configurations
1. Visit `/compare/<mac_address>`
2. View differences between expected and actual
3. Export unexpected parameters for common.yml

### Firmware Updates
1. Configure in `firmware.yml`:
   - Set `update_enabled: true`
   - Define `expected_version` and `upgrade_url`
   - Optionally enable model-specific versions and URLs
2. Phones automatically receive updates on next config request
3. Monitor progress via metrics

### Discovery Mode
1. Enable in `serviceconfig.yml`
2. Factory reset phones
3. Collect reports at `/reports`
4. Export parameters for configuration

## Scripts

The project includes utility scripts in the `scripts/` directory to help maintain and validate your configuration:

### Schema Generation (`generate_complete_schema.sh`)

Automatically generates a complete `schema.yml` file from actual phone reports:

```bash
# Run from project root
./scripts/generate_complete_schema.sh
```

**What it does:**
- Finds the latest phone config report in `reports/`
- Extracts all parameters reported by the phone
- Generates a complete `schema.yml` with all discovered parameters
- Backs up existing schema before overwriting

**Use cases:**
- Initial setup when you don't have a complete parameter list
- Adding support for new phone models with different parameters
- Ensuring you capture all available Cisco MPP parameters

### Schema Validation (`verify_schema_completeness.sh`)

Verifies that your current `schema.yml` includes all parameters from phone reports:

```bash
# Run from project root  
./scripts/verify_schema_completeness.sh
```

**What it does:**
- Compares `schema.yml` against the latest phone report
- Lists any missing parameters not in your schema
- Reports any extra parameters in schema not seen in reports
- Provides statistics on schema completeness

**Use cases:**
- Regular validation that your schema is up-to-date
- Detecting when phones report new parameters
- Cleaning up unused parameters from schema

Both scripts require Python 3 and should be run from the project root directory. Make sure you have phone reports available before running these scripts.

## Troubleshooting

### Common Issues
- **404 errors**: Check MAC address format and IP authorization
- **No reports**: Verify `Report_Rule` in configuration
- **Auth failures**: Check credentials in `serviceconfig.yml`
- **Missing metrics**: Ensure monitoring enabled
- **Firmware updates not working**: Check `update_enabled` and phone User-Agent format
- **Configuration mismatches**: Use comparison endpoint to identify differences

### Logs
- Application: `logs/provisioning.log`
- Container: `docker-compose logs app`
- Nginx: `docker-compose logs nginx`

### Configuration Validation
Use comparison endpoint to verify YAML configurations match actual phone settings.

## Best Practices

1. **Regular Monitoring**: Check reports daily to catch configuration drift
2. **Version Control**: Keep configuration files in version control
3. **Backup Configurations**: Regular backups of `config/` directory
4. **Security**: Change default passwords, enable HTTPS in production
5. **Cleanup**: Remove old report files periodically
6. **Testing**: Use discovery mode to validate new phone models
7. **Baseline Comparison**: Save initial configurations as reference

