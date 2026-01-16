# WCP Testbed SSH Config Parser

Python script to parse WCP testbed information from Jenkins and automatically add SSH configurations to `~/.ssh/config`.

**Note:** New SSH config entries are inserted at the beginning of the file for easy access to recently added testbeds.

## Overview

This script handles two types of testbeds:
1. **Regular testbeds** - Have `testbedIp` and `testbedPassword` directly in the JSON
2. **WCP testbeds** - Require connecting to vCenter to extract the actual WCP IP and password

## Features

- **Automatically detects** testbed type (regular vs WCP)
- **Connects to vCenter** to extract WCP credentials when needed
- **Supports both JSON formats**: nested (`vc.1.ip`) and flat (`vcenterIp`)
- **Saves JSON backups** to `~/.ssh/testbed_backups/` for reference
- **Inserts new entries** at the beginning of SSH config for easy access
- **Command-line options** for force overwrite and custom config paths

## Installation

### Requirements
- Python 3.6+
- `paramiko` - For SSH connections to vCenter
- `requests` - For fetching JSON from Jenkins

### Install Dependencies

```bash
pip3 install paramiko requests
```

## Usage

### Basic Usage
```bash
# Using the wrapper script (recommended)
./wcp_ssh https://jenkins-vcf-wcp-dev.devops.broadcom.net/view/all/job/dev-nsxvpc/8003/artifact/testbedInfo.json

# Or directly using the Python script
./parse_testbed.py https://jenkins-vcf-wcp-dev.devops.broadcom.net/view/all/job/dev-nsxvpc/8003/artifact/testbedInfo.json
```

### Force Overwrite (no confirmation prompt)
```bash
./wcp_ssh -f <URL>
```

### Custom SSH Config Path
```bash
./wcp_ssh -c /custom/path/ssh_config <URL>
```

### Help
```bash
./wcp_ssh -h
```

## How WCP Extraction Works

For WCP testbeds (when `testbedIp` is not present in JSON):

1. Extract vCenter IP and root password from JSON
2. SSH to vCenter and run `/usr/lib/vmware-wcp/decryptK8Pwd.py`
3. Parse the output to get the actual WCP IP and password
4. Use these credentials for the SSH config

## SSH Config Format

The scripts generate SSH config entries in this format:

```
# Description: WCP Testbed with NSX (#8003; nsx:10.192.34.97:F1!OyHLp+F5rn5Hp; vc:10.192.33.8:HNYWZe1A0y*teln_; esx:F1!OyHLp+F5rn5Hp)
Host 10.192.37.40-wcp-testbed
    User root
    HostName 10.192.37.40
    AddKeysToAgent yes
    #!! QuestionAnswer1 noM7p(YQ8cWH@FV$
```

## JSON Structure

The scripts handle testbed JSON with the following structure:

```json
{
  "vc": {
    "1": {
      "ip": "10.192.33.8",
      "password": "HNYWZe1A0y*teln_",
      "root_password": "Ca$hc0w1",
      "username": "administrator@vsphere.local"
    }
  },
  "nsxmanager": {
    "1": {
      "ip": "10.192.34.97",
      "password": "F1!OyHLp+F5rn5Hp",
      "build": "24569273"
    }
  },
  "esx": {
    "1": {
      "password": "F1!OyHLp+F5rn5Hp"
    }
  }
}
```

For regular testbeds, the JSON would also include:
```json
{
  "testbedIp": "10.192.37.40",
  "testbedPassword": "noM7p(YQ8cWH@FV$",
  "testbedUser": "root",
  "testbedName": "wcp-testbed"
}
```

## Backup and Security Notes

### JSON Backups
- All testbed JSON files are automatically saved to `~/.ssh/testbed_backups/`
- Backup files are named: `testbed_<build_number>_<timestamp>.json`
- Example: `testbed_8003_20240122_143052.json`
- These backups are useful for:
  - Debugging connection issues
  - Re-running the script if needed
  - Historical reference of testbed configurations

### Security Considerations
- Passwords are stored in SSH config comments for reference (be careful with sharing)
- The scripts use `StrictHostKeyChecking=no` for automated connections to vCenter
- JSON backups contain sensitive credentials - protect the backup directory appropriately

## Troubleshooting

### "testbedIp not found" error
The testbed is likely a WCP testbed. The script will automatically attempt to extract credentials from vCenter.

### "Failed to connect to vCenter"
Check if:
- vCenter is accessible from your machine
- Root password is correct in the JSON
- Network connectivity to vCenter is available

### "paramiko not installed"
Install with:
```bash
pip3 install paramiko requests
```

### "Connection timeout"
The vCenter might be slow to respond. The script has a 30-second timeout for SSH connections.

## Example Workflow

```bash
# 1. Get the testbed JSON URL from Jenkins
URL="https://jenkins-vcf-wcp-dev.devops.broadcom.net/view/all/job/dev-nsxvpc/8003/artifact/testbedInfo.json"

# 2. Parse and add to SSH config
./wcp_ssh "$URL"

# 3. Connect to the testbed
ssh 10.192.37.40-wcp-testbed
```

## Advanced Usage

### Processing Multiple Testbeds
```bash
# Process multiple testbeds in sequence
for build in 8001 8002 8003; do
    ./wcp_ssh -f "https://jenkins-vcf-wcp-dev.devops.broadcom.net/view/all/job/dev-nsxvpc/${build}/artifact/testbedInfo.json"
done
```

### Using Saved JSON Backups
If you have a saved JSON backup, you can create a simple wrapper:
```bash
# Re-process a saved JSON
python3 -c "import json; print(json.load(open('~/.ssh/testbed_backups/testbed_8003_20240122_143052.json')))" | \
    python3 parse_testbed.py -
```

### Listing Recent Testbeds
```bash
# Show recently added testbeds from SSH config
grep -A 5 "# Description: WCP Testbed" ~/.ssh/config | head -30

# List all JSON backups
ls -lt ~/.ssh/testbed_backups/ | head -10
```
