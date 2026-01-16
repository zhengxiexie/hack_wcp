#!/usr/bin/env python3
"""
Parse WCP testbed info from Jenkins and append to SSH config
Usage: ./parse_testbed.py <testbed_info_url>
"""

import json
import sys
import os
import re
import requests
import paramiko
import warnings
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple
import argparse

# Suppress paramiko warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)


class TestbedParser:
    def __init__(self, url: str, ssh_config_path: str = None):
        self.url = url
        self.ssh_config_path = ssh_config_path or os.path.expanduser("~/.ssh/config")
        self.testbed_data = {}
        self.is_wcp = False  # Flag to determine if this is a WCP testbed
        self.json_backup_dir = os.path.expanduser("~/.ssh/testbed_backups")
        
    def fetch_testbed_json(self) -> Dict:
        """Fetch testbed JSON from Jenkins URL"""
        try:
            response = requests.get(self.url, timeout=30)
            response.raise_for_status()
            json_data = response.json()
            
            # Save JSON backup
            self.save_json_backup(json_data)
            
            return json_data
        except requests.RequestException as e:
            print(f"\033[0;31mError fetching testbed info: {e}\033[0m")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"\033[0;31mError parsing JSON: {e}\033[0m")
            sys.exit(1)
    
    def save_json_backup(self, json_data: Dict):
        """Save JSON data as backup file"""
        # Create backup directory if it doesn't exist
        os.makedirs(self.json_backup_dir, exist_ok=True)
        
        # Generate filename with timestamp and build number
        build_num = self.extract_build_number()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"testbed_{build_num}_{timestamp}.json"
        backup_path = os.path.join(self.json_backup_dir, filename)
        
        # Save JSON with proper formatting
        with open(backup_path, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        print(f"\033[1;33mSaved JSON backup: {backup_path}\033[0m")
            
    def extract_build_number(self) -> str:
        """Extract build number from URL"""
        match = re.search(r'/(\d+)/artifact/', self.url)
        if match:
            return match.group(1)
        # Try to get from the end of URL path
        match = re.search(r'/(\d+)/', self.url)
        return match.group(1) if match else "unknown"
        
    def execute_remote_command(self, host: str, user: str, password: str, command: str) -> str:
        """Execute command on remote host via SSH"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(host, username=user, password=password, timeout=30)
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            if error and not output:
                raise Exception(f"Command failed: {error}")
            
            return output
        finally:
            ssh.close()
    
    def extract_wcp_info(self, json_data: Dict) -> Tuple[str, str]:
        """Extract WCP IP and password like extract_wcp does"""
        try:
            # Get VC information
            vc_info = json_data.get('vc', {}).get('1', {})
            vc_ip = vc_info.get('ip', '')
            root_password = vc_info.get('root_password', '')
            
            if not vc_ip or not root_password:
                raise Exception("VC IP or root password not found")
            
            print(f"\033[1;33mConnecting to vCenter at {vc_ip} to get WCP credentials...\033[0m")
            
            # Execute decryptK8Pwd.py on vCenter
            decrypt_output = self.execute_remote_command(
                vc_ip, "root", root_password,
                "/usr/lib/vmware-wcp/decryptK8Pwd.py"
            )
            
            # Parse output for IP and password
            output_lines = decrypt_output.splitlines()
            wcp_ip = None
            wcp_password = None
            
            for line in output_lines:
                if 'IP:' in line:
                    wcp_ip = line.split(': ')[1].strip()
                elif 'PWD:' in line:
                    wcp_password = line.split(': ')[1].strip()
            
            if not wcp_ip or not wcp_password:
                raise Exception("Failed to extract WCP IP or password from decryptK8Pwd output")
            
            return wcp_ip, wcp_password
            
        except Exception as e:
            print(f"\033[0;31mFailed to extract WCP credentials: {e}\033[0m")
            return None, None
    
    def parse_testbed_data(self, json_data: Dict) -> Dict:
        """Parse testbed JSON and extract relevant fields"""
        # First check if this is a regular testbed or WCP testbed
        testbed_ip = json_data.get('testbedIp', '')
        testbed_password = json_data.get('testbedPassword', '')
        
        # If testbedIp is not present, try WCP extraction
        if not testbed_ip:
            print("\033[1;33mNo testbedIp found, attempting WCP extraction...\033[0m")
            wcp_ip, wcp_password = self.extract_wcp_info(json_data)
            if wcp_ip and wcp_password:
                testbed_ip = wcp_ip
                testbed_password = wcp_password
                self.is_wcp = True
            else:
                print("\033[0;31mError: Could not extract WCP testbed information\033[0m")
                sys.exit(1)
        
        # Extract NSX Manager info
        nsx_info = json_data.get('nsxmanager', {}).get('1', {})
        nsx_ip = nsx_info.get('ip', '') or json_data.get('nsxManagerIp', '')
        nsx_password = nsx_info.get('password', '') or json_data.get('nsxPassword', '')
        
        # Extract vCenter info
        vc_info = json_data.get('vc', {}).get('1', {})
        vc_ip = vc_info.get('ip', '') or json_data.get('vcenterIp', '')
        vc_password = vc_info.get('password', '') or json_data.get('vcenterPassword', '')
        
        # Extract ESX info
        esx_info = json_data.get('esx', {}).get('1', {})
        esx_password = esx_info.get('password', '') or json_data.get('esxPassword', '')
        
        data = {
            'testbed_ip': testbed_ip,
            'testbed_user': json_data.get('testbedUser', 'root'),
            'testbed_password': testbed_password,
            'testbed_name': json_data.get('testbedName', 'wcp-testbed'),
            'nsx_ip': nsx_ip,
            'nsx_user': json_data.get('nsxUser', 'admin'),
            'nsx_password': nsx_password,
            'vc_ip': vc_ip,
            'vc_user': json_data.get('vcenterUser', 'administrator@vsphere.local'),
            'vc_password': vc_password,
            'esx_password': esx_password,
            'build_number': self.extract_build_number()
        }
        
        # Validate required fields
        if not data['testbed_ip']:
            print("\033[0;31mError: testbed IP not found\033[0m")
            sys.exit(1)
        if not data['testbed_password']:
            print("\033[0;31mError: testbed password not found\033[0m")
            sys.exit(1)
            
        return data
        
    def generate_description(self, data: Dict) -> str:
        """Generate description line for SSH config"""
        desc = f"# Description: WCP Testbed with NSX (#{data['build_number']}"
        
        # Add NSX info
        if data['nsx_ip'] and data['nsx_password']:
            desc += f"; nsx:{data['nsx_ip']}:{data['nsx_password']}"
            
        # Add vCenter info
        if data['vc_ip'] and data['vc_password']:
            desc += f"; vc:{data['vc_ip']}:{data['vc_password']}"
            
        # Add ESX password
        if data['esx_password']:
            desc += f"; esx:{data['esx_password']}"
            
        desc += ")"
        return desc
        
    def generate_ssh_config(self, data: Dict) -> str:
        """Generate SSH config entry"""
        description = self.generate_description(data)
        host_alias = f"{data['testbed_ip']}-{data['testbed_name']}"
        
        config = f"""{description}
Host {host_alias}
    User {data['testbed_user']}
    HostName {data['testbed_ip']}
    AddKeysToAgent yes
    #!! QuestionAnswer1 {data['testbed_password']}"""
        
        return config, host_alias
        
    def check_existing_entry(self, host_alias: str) -> bool:
        """Check if host already exists in SSH config"""
        if not os.path.exists(self.ssh_config_path):
            return False
            
        with open(self.ssh_config_path, 'r') as f:
            content = f.read()
            return f"Host {host_alias}" in content
            
    def remove_existing_entry(self, host_alias: str):
        """Remove existing host entry from SSH config"""
        if not os.path.exists(self.ssh_config_path):
            return
        
        # Read the current content
        with open(self.ssh_config_path, 'r') as f:
            content = f.read()
        
        # Remove the entry
        lines = content.split('\n')
        new_lines = []
        skip = False
        
        for i, line in enumerate(lines):
            if line.strip() == f"Host {host_alias}":
                skip = True
                # Find the previous description comment if exists
                if i > 0 and new_lines and new_lines[-1].startswith("# Description:"):
                    new_lines.pop()
                continue
            elif skip and (line.startswith("Host ") or (i == len(lines) - 1 and not line.strip())):
                skip = False
                if line.startswith("Host "):
                    new_lines.append(line)
            elif not skip:
                new_lines.append(line)
                
        with open(self.ssh_config_path, 'w') as f:
            f.write('\n'.join(new_lines))
            
    def insert_to_ssh_config(self, config: str):
        """Insert SSH config entry at the beginning of ~/.ssh/config"""
        # Read existing content if file exists
        existing_content = ""
        if os.path.exists(self.ssh_config_path):
            with open(self.ssh_config_path, 'r') as f:
                existing_content = f.read()
        
        # Write new entry at the beginning, followed by existing content
        with open(self.ssh_config_path, 'w') as f:
            f.write(config)
            if existing_content:
                # Add separator if existing content doesn't start with newline
                if not existing_content.startswith('\n'):
                    f.write('\n\n')
                else:
                    f.write('\n')
                f.write(existing_content)
            
    def run(self, force: bool = False):
        """Main execution flow"""
        print(f"\033[1;33mFetching testbed info from: {self.url}\033[0m")
        
        # Fetch and parse JSON
        json_data = self.fetch_testbed_json()
        print("\033[1;33mParsing testbed information...\033[0m")
        
        # Parse data
        data = self.parse_testbed_data(json_data)
        
        # Generate SSH config
        config, host_alias = self.generate_ssh_config(data)
        
        # Check for existing entry
        if self.check_existing_entry(host_alias):
            if not force:
                print(f"\033[1;33mWarning: Host {host_alias} already exists in SSH config\033[0m")
                response = input("Do you want to replace it? (y/n): ")
                if response.lower() != 'y':
                    print("\033[0;31mAborted\033[0m")
                    return
            self.remove_existing_entry(host_alias)
            
        # Insert at the beginning of SSH config
        self.insert_to_ssh_config(config)
        
        # Print success message
        print(f"\033[0;32m✓ Successfully added SSH config for {host_alias}\033[0m")
        print(f"\033[0;32m  Testbed IP: {data['testbed_ip']}\033[0m")
        print(f"\033[0;32m  Build: #{data['build_number']}\033[0m")
        
        if data['nsx_ip']:
            print(f"\033[0;32m  NSX Manager: {data['nsx_ip']}\033[0m")
        if data['vc_ip']:
            print(f"\033[0;32m  vCenter: {data['vc_ip']}\033[0m")
            
        print(f"\n\033[1;33mYou can now connect using:\033[0m")
        print(f"\033[0;32m  ssh {host_alias}\033[0m")
        
        # Also print the config for reference
        print(f"\n\033[1;33mSSH Config Entry:\033[0m")
        print(config)


def main():
    parser = argparse.ArgumentParser(description='Parse WCP testbed info and add to SSH config')
    parser.add_argument('url', help='Jenkins testbed info URL')
    parser.add_argument('--force', '-f', action='store_true', 
                       help='Force overwrite existing SSH config entry')
    parser.add_argument('--ssh-config', '-c', 
                       help='Path to SSH config file (default: ~/.ssh/config)')
    
    args = parser.parse_args()
    
    # Create parser and run
    testbed_parser = TestbedParser(args.url, args.ssh_config)
    testbed_parser.run(force=args.force)


if __name__ == '__main__':
    main()
