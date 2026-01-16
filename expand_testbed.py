#!/usr/bin/env python3
"""
扩展 Supervisor Node 磁盘空间脚本
自动从 Jenkins testbedInfo.json 解析参数
通过 vSphere REST API 扩容 ESXi 上的磁盘，然后在 OS 层扩展分区

Usage: ./expand_sp_disk.py <testbed_info_url>
"""

import sys
import os
import re
import json
import requests
import paramiko
import warnings
import urllib3
from typing import Tuple, Optional, Dict, Any

warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 默认配置
TARGET_DISK_SIZE_GB = 70
TARGET_CPU = 8


def print_header(title: str):
    print(f"\n{'=' * 50}")
    print(title)
    print('=' * 50)


def print_step(step: str):
    print(f"\n[{step}]")


def ssh_exec(host: str, user: str, password: str, cmd: str, timeout: int = 60) -> str:
    """执行 SSH 命令"""
    print(f"  [执行] ssh {user}@{host} \"{cmd}\"")
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(host, username=user, password=password, timeout=timeout)
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        
        result = output + error
        print(f"  [输出] {result[:200]}..." if len(result) > 200 else f"  [输出] {result}")
        return result
    except Exception as e:
        print(f"  [错误] {e}")
        return ""
    finally:
        ssh.close()


class VSphereAPI:
    """vSphere REST API 客户端"""
    
    def __init__(self, vc_ip: str, username: str, password: str):
        self.vc_ip = vc_ip
        self.base_url = f"https://{vc_ip}"
        self.session = requests.Session()
        self.session.verify = False
        self.session_id = None
        self.username = username
        self.password = password
    
    def login(self) -> bool:
        """登录获取 session"""
        print(f"  登录 vCenter: {self.vc_ip}")
        url = f"{self.base_url}/rest/com/vmware/cis/session"
        try:
            resp = self.session.post(url, auth=(self.username, self.password))
            if resp.status_code == 200:
                self.session_id = resp.json().get('value')
                self.session.headers['vmware-api-session-id'] = self.session_id
                print(f"  登录成功")
                return True
            else:
                print(f"  登录失败: {resp.status_code} {resp.text}")
                return False
        except Exception as e:
            print(f"  登录异常: {e}")
            return False
    
    def logout(self):
        """登出"""
        if self.session_id:
            try:
                self.session.delete(f"{self.base_url}/rest/com/vmware/cis/session")
            except:
                pass
    
    def list_vms(self, name_filter: str = None) -> list:
        """列出 VM"""
        url = f"{self.base_url}/rest/vcenter/vm"
        params = {}
        if name_filter:
            params['filter.names'] = name_filter
        
        resp = self.session.get(url, params=params)
        if resp.status_code == 200:
            return resp.json().get('value', [])
        return []
    
    def get_vm(self, vm_id: str) -> dict:
        """"获取 VM 详情"""
        url = f"{self.base_url}/rest/vcenter/vm/{vm_id}"
        resp = self.session.get(url)
        if resp.status_code == 200:
            return resp.json().get('value', {})
        return {}
    
    def get_vm_guest_identity(self, vm_id: str) -> dict:
        """"获取 VM Guest 信息 (IP 等)"""
        url = f"{self.base_url}/rest/vcenter/vm/{vm_id}/guest/identity"
        resp = self.session.get(url)
        if resp.status_code == 200:
            return resp.json().get('value', {})
        return {}
    
    def get_vm_guest_networking(self, vm_id: str) -> dict:
        """"获取 VM 网络信息"""
        url = f"{self.base_url}/api/vcenter/vm/{vm_id}/guest/networking"
        resp = self.session.get(url)
        if resp.status_code == 200:
            return resp.json()
        return {}
    
    def get_vm_disks(self, vm_id: str) -> list:
        """"获取 VM 磁盘列表"""
        vm_info = self.get_vm(vm_id)
        return vm_info.get('disks', {})
    
    def resize_disk(self, vm_id: str, disk_id: str, size_gb: int) -> bool:
        """"扩容磁盘"""
        url = f"{self.base_url}/rest/vcenter/vm/{vm_id}/hardware/disk/{disk_id}"
        data = {
            "spec": {
                "capacity": size_gb * 1024 * 1024 * 1024  # 转换为字节
            }
        }
        print(f"  扩容磁盘: {disk_id} -> {size_gb}GB")
        resp = self.session.patch(url, json=data)
        if resp.status_code == 200:
            print(f"  扩容成功")
            return True
        else:
            print(f"  扩容失败: {resp.status_code} {resp.text}")
            return False


def extract_build_number(url: str) -> str:
    """从 URL 中提取 build number"""
    match = re.search(r'/(\d+)/artifact/', url)
    if match:
        return match.group(1)
    match = re.search(r'/(\d+)/', url)
    return match.group(1) if match else "unknown"


def fetch_testbed_json(source: str) -> dict:
    """
    获取 testbedInfo.json
    支持: URL 或本地文件路径
    URL 会自动缓存到 ./testbed/{build_number}.json
    """
    # 检查是 URL 还是本地文件
    if source.startswith('http://') or source.startswith('https://'):
        # 提取 build number
        build_number = extract_build_number(source)
        cache_dir = "./testbed"
        cache_file = f"{cache_dir}/{build_number}.json"
        
        # 检查缓存是否存在
        if os.path.exists(cache_file):
            print(f"  使用缓存: {cache_file}")
            with open(cache_file, 'r') as f:
                return json.load(f)
        
        # 下载并缓存
        print(f"  下载: {source}")
        response = requests.get(source, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        # 保存到缓存
        os.makedirs(cache_dir, exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"  已缓存到: {cache_file}")
        
        return data
    else:
        # 本地文件
        print(f"  读取本地文件: {source}")
        with open(source, 'r') as f:
            return json.load(f)


def get_wcp_credentials(vc_ip: str, vc_root_pass: str) -> Tuple[str, str]:
    """"通过 VC 获取 WCP (Supervisor) 凭据"""
    output = ssh_exec(vc_ip, "root", vc_root_pass, "/usr/lib/vmware-wcp/decryptK8Pwd.py")
    
    sp_ip = None
    sp_pass = None
    
    for line in output.splitlines():
        if 'IP:' in line:
            sp_ip = line.split('IP:')[1].strip()
        elif 'PWD:' in line:
            sp_pass = line.split('PWD:')[1].strip()
    
    return sp_ip, sp_pass


def find_vm_by_ip(api: VSphereAPI, target_ip: str) -> Optional[Dict[str, Any]]:
    """"通过 IP 查找 VM"""
    # 先获取所有 SupervisorControlPlaneVM
    all_vms = api.list_vms()
    print(f"  总共找到 {len(all_vms)} 个 VM")
    
    supervisor_vms = [vm for vm in all_vms if 'SupervisorControlPlane' in vm.get('name', '')]
    print(f"  其中 SupervisorControlPlaneVM: {len(supervisor_vms)} 个")
    
    for vm in supervisor_vms:
        vm_id = vm['vm']
        vm_name = vm['name']
        print(f"  检查 VM: {vm_name} ({vm_id})")
        
        # 获取 VM 的 IP 地址
        guest_info = api.get_vm_guest_identity(vm_id)
        ip_address = guest_info.get('ip_address', '')
        
        if ip_address == target_ip:
            print(f"  匹配! IP: {ip_address}")
            return vm
        
        # 也检查网络信息
        net_info = api.get_vm_guest_networking(vm_id)
        if net_info:
            nics = net_info.get('dns', {}) or {}
            # 检查 JSON 响应中是否包含目标 IP
            if target_ip in str(net_info):
                print(f"  匹配! 在网络信息中找到 IP")
                return vm
    
    # 如果没有匹配，返回第一个
    if supervisor_vms:
        print(f"  IP 匹配未找到，使用第一个 SupervisorControlPlaneVM")
        return supervisor_vms[0]
    
    return None


def expand_disk_partition(sp_ip: str, sp_user: str, sp_pass: str):
    """在 OS 层扩展分区"""
    
    # 1. 获取 sda4 起始扇区
    print_step("1/7 获取 sda4 原始起始扇区")
    fdisk_output = ssh_exec(sp_ip, sp_user, sp_pass, "fdisk -l /dev/sda")
    
    start_sector = None
    for line in fdisk_output.splitlines():
        if '/dev/sda4' in line:
            parts = line.split()
            if len(parts) >= 2:
                start_sector = parts[1]
                break
    
    if not start_sector:
        print(f"  错误: 无法获取 sda4 起始扇区")
        print(f"  fdisk 输出: {fdisk_output}")
        return False
    
    print(f"  sda4 起始扇区: {start_sector}")
    
    # 2. 重新扫描 SCSI 设备
    print_step("2/7 重新扫描 SCSI 设备")
    ssh_exec(sp_ip, sp_user, sp_pass, "echo 1 > /sys/block/sda/device/rescan")
    
    # 3. 检查磁盘大小
    print_step("3/7 检查磁盘大小")
    ssh_exec(sp_ip, sp_user, sp_pass, "lsblk /dev/sda")
    
    # 4. 使用 fdisk 重新分区
    print_step("4/7 重新分区 sda4")
    fdisk_cmds = f"d\\n4\\nn\\np\\n4\\n{start_sector}\\n\\nN\\nw\\n"
    ssh_exec(sp_ip, sp_user, sp_pass, f"echo -e '{fdisk_cmds}' | fdisk /dev/sda || true")
    
    # 5. 扩展物理卷
    print_step("5/7 扩展物理卷")
    ssh_exec(sp_ip, sp_user, sp_pass, "pvresize /dev/sda4")
    
    # 6. 扩展逻辑卷
    print_step("6/7 扩展逻辑卷")
    ssh_exec(sp_ip, sp_user, sp_pass, "lvextend -l +100%FREE /dev/mapper/vg_root_0-lv_root_0 || true")
    
    # 7. 扩展文件系统
    print_step("7/7 扩展文件系统")
    ssh_exec(sp_ip, sp_user, sp_pass, "resize2fs /dev/mapper/vg_root_0-lv_root_0")
    
    return True


def main():
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <TESTBED_INFO_URL>")
        print(f"示例: {sys.argv[0]} https://jenkins-vcf-wcp-dev.devops.broadcom.net/view/all/job/dev-nsxvpc/13989/artifact/testbedInfo.json")
        sys.exit(1)
    
    testbed_url = sys.argv[1]
    
    print_header("扩展 Supervisor Node 磁盘空间")
    
    # ========================================
    # 解析 testbedInfo.json
    # ========================================
    print_header("准备工作: 解析 testbed 信息")
    
    print_step("步骤1: 下载 testbedInfo.json")
    testbed_json = fetch_testbed_json(testbed_url)
    
    # 解析 VC 信息
    vc_info = testbed_json.get('vc', {}).get('1', {})
    vc_ip = vc_info.get('ip', '')
    vc_root_pass = vc_info.get('root_password', '')
    vc_pass = vc_info.get('password', '')
    vc_user = "administrator@vsphere.local"
    
    print(f"  VC IP: {vc_ip}")
    print(f"  VC Password: {vc_pass}")
    
    if not vc_ip or not vc_root_pass:
        print("错误: 无法从 JSON 中获取 VC IP 或密码")
        sys.exit(1)
    
    # 获取 WCP 凭据
    print_step("步骤2: 通过 VC 获取 Supervisor 凭据")
    print(f"  连接 VC: root@{vc_ip}")
    
    sp_ip, sp_pass = get_wcp_credentials(vc_ip, vc_root_pass)
    
    if not sp_ip or not sp_pass:
        print("错误: 无法获取 Supervisor 凭据")
        sys.exit(1)
    
    print(f"  Supervisor IP: {sp_ip}")
    print(f"  Supervisor 密码已获取")
    
    sp_user = "root"
    
    # ========================================
    # 第一部分: 通过 vSphere API 扩容 VM 磁盘
    # ========================================
    print_header("第一部分: 通过 vSphere API 扩容 VM 磁盘")
    
    api = VSphereAPI(vc_ip, vc_user, vc_pass)
    
    if not api.login():
        print("错误: 无法登录 vCenter")
        sys.exit(1)
    
    try:
        print_step("步骤1: 查找 SupervisorControlPlaneVM")
        print(f"  目标 IP: {sp_ip}")
        
        vm = find_vm_by_ip(api, sp_ip)
        
        if not vm:
            print("错误: 无法找到对应的 VM")
            sys.exit(1)
        
        vm_id = vm['vm']
        vm_name = vm['name']
        print(f"  找到 VM: {vm_name} (ID: {vm_id})")
        
        print_step("步骤2: 检查当前磁盘配置")
        vm_detail = api.get_vm(vm_id)
        disks_raw = vm_detail.get('disks', {})
        
        # 处理不同的数据格式 (dict 或 list)
        disks = {}
        if isinstance(disks_raw, dict):
            disks = disks_raw
        elif isinstance(disks_raw, list):
            for disk in disks_raw:
                if isinstance(disk, dict):
                    disk_key = disk.get('key') or disk.get('disk') or disk.get('label', 'unknown')
                    disks[disk_key] = disk.get('value', disk)
        
        print(f"  磁盘信息 (raw): {disks_raw}")
        print(f"  磁盘信息:")
        for disk_id, disk_info in disks.items():
            if isinstance(disk_info, dict):
                capacity = disk_info.get('capacity', 0)
            else:
                capacity = 0
            capacity_gb = capacity / (1024**3) if capacity else 0
            print(f"    {disk_id}: {capacity_gb:.1f} GB")
        
        print_step("步骤3: 扩容磁盘")
        # 尝试通过 API 扩容
        disk_expanded = False
        for disk_id, disk_info in disks.items():
            if isinstance(disk_info, dict):
                current_capacity = disk_info.get('capacity', 0)
            else:
                current_capacity = 0
            current_gb = current_capacity / (1024**3) if current_capacity else 0
            
            if current_gb < TARGET_DISK_SIZE_GB and current_gb > 0:
                print(f"  尝试扩容 {disk_id}: {current_gb:.1f}GB -> {TARGET_DISK_SIZE_GB}GB")
                if api.resize_disk(vm_id, disk_id, TARGET_DISK_SIZE_GB):
                    disk_expanded = True
                    break
                else:
                    print(f"  API 扩容失败，可能需要手动扩容")
            elif current_gb >= TARGET_DISK_SIZE_GB:
                print(f"  {disk_id} 已经是 {current_gb:.1f}GB，无需扩容")
                disk_expanded = True
        
        if not disk_expanded:
            print(f"\n  注意: 无法通过 API 自动扩容，请手动在 vSphere UI 中扩容:")
            print(f"    1. 登录 vCenter: https://{vc_ip}")
            print(f"    2. 找到 VM: {vm_name}")
            print(f"    3. 编辑设置 -> 硬盘 -> 扩容到 {TARGET_DISK_SIZE_GB}GB")
            print()
            input("  磁盘扩容完成后按 Enter 继续...")
    
    finally:
        api.logout()
    
    # ========================================
    # 第二部分: 在 OS 层扩展分区
    # ========================================
    print_header("第二部分: 在 OS 层扩展分区")
    
    success = expand_disk_partition(sp_ip, sp_user, sp_pass)
    
    if success:
        print_header("验证结果")
        ssh_exec(sp_ip, sp_user, sp_pass, "df -h /")
        ssh_exec(sp_ip, sp_user, sp_pass, "lsblk /dev/sda")
        
        print_header("磁盘扩展成功完成!")
    else:
        print_header("磁盘扩展失败")
        sys.exit(1)


if __name__ == '__main__':
    main()
