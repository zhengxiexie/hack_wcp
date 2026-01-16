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
import ssl
import json
import requests
import paramiko
import warnings
import urllib3
from typing import Tuple, Optional, Dict, Any, List
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

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


class ESXiDiskResizer:
    """通过 ESXi 直接连接扩容磁盘（绕过 vCenter 权限限制）"""
    
    def __init__(self, esx_hosts: List[Dict[str, str]]):
        self.esx_hosts = esx_hosts
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def find_and_resize_supervisor_vm(self, target_size_gb: int) -> bool:
        """在所有 ESXi 主机上查找并扩容 SupervisorControlPlaneVM"""
        target_size_kb = target_size_gb * 1024 * 1024
        
        for esx in self.esx_hosts:
            print(f"  尝试连接 ESXi: {esx['ip']}")
            try:
                si = SmartConnect(
                    host=esx['ip'], 
                    user=esx['user'], 
                    pwd=esx['pass'], 
                    sslContext=self.ssl_context
                )
            except Exception as e:
                print(f"    连接失败: {e}")
                continue
            
            try:
                content = si.RetrieveContent()
                vms = self._get_supervisor_vms(content)
                
                if not vms:
                    print(f"    未找到 SupervisorControlPlaneVM")
                    continue
                
                for vm in vms:
                    print(f"    找到 VM: {vm.name}")
                    for device in vm.config.hardware.device:
                        if isinstance(device, vim.vm.device.VirtualDisk):
                            capacity_gb = device.capacityInKB / 1024 / 1024
                            print(f"      磁盘 key={device.key}: {capacity_gb:.1f} GB")
                            
                            if capacity_gb < target_size_gb:
                                if self._resize_disk(vm, device.key, target_size_kb):
                                    return True
                            else:
                                print(f"      已经是 {capacity_gb:.1f}GB，无需扩容")
                                return True
            finally:
                Disconnect(si)
        
        return False
    
    def _get_supervisor_vms(self, content):
        """查找 SupervisorControlPlaneVM"""
        container = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.VirtualMachine], True
        )
        vms = [vm for vm in container.view if "SupervisorControlPlane" in vm.name]
        container.Destroy()
        return vms
    
    def _resize_disk(self, vm, disk_key: int, new_size_kb: int) -> bool:
        """扩容磁盘"""
        print(f"      尝试扩容磁盘 (key={disk_key}) 到 {new_size_kb / 1024 / 1024:.1f} GB")
        
        disk_device = None
        for device in vm.config.hardware.device:
            if isinstance(device, vim.vm.device.VirtualDisk) and device.key == disk_key:
                disk_device = device
                break
        
        if not disk_device:
            print(f"        错误: 未找到磁盘")
            return False
        
        disk_spec = vim.vm.device.VirtualDeviceSpec()
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
        disk_spec.device = vim.vm.device.VirtualDisk()
        disk_spec.device.key = disk_device.key
        disk_spec.device.backing = disk_device.backing
        disk_spec.device.controllerKey = disk_device.controllerKey
        disk_spec.device.unitNumber = disk_device.unitNumber
        disk_spec.device.capacityInKB = new_size_kb
        
        config_spec = vim.vm.ConfigSpec()
        config_spec.deviceChange = [disk_spec]
        
        print(f"        执行 ReconfigVM_Task...")
        try:
            task = vm.ReconfigVM_Task(spec=config_spec)
            while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                pass
            
            if task.info.state == vim.TaskInfo.State.success:
                print(f"        扩容成功!")
                return True
            else:
                print(f"        扩容失败: {task.info.error}")
                return False
        except Exception as e:
            print(f"        异常: {e}")
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


def get_esx_hosts_from_testbed(testbed_json: dict) -> List[Dict[str, str]]:
    """从 testbed JSON 提取 ESXi 主机信息"""
    esx_hosts = []
    esx_info = testbed_json.get('esx', {})
    
    for key, esx in esx_info.items():
        # 只使用 compute cluster 的 ESXi (key 1-3)
        if key in ['1', '2', '3']:
            esx_hosts.append({
                'ip': esx.get('ip', ''),
                'user': esx.get('username', 'root'),
                'pass': esx.get('password', '')
            })
    
    return esx_hosts


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
    # 第一部分: 通过 ESXi 直接扩容 VM 磁盘
    # ========================================
    print_header("第一部分: 通过 ESXi 直接扩容 VM 磁盘")
    
    print_step("步骤1: 提取 ESXi 主机信息")
    esx_hosts = get_esx_hosts_from_testbed(testbed_json)
    print(f"  找到 {len(esx_hosts)} 个 ESXi 主机")
    for esx in esx_hosts:
        print(f"    - {esx['ip']}")
    
    print_step("步骤2: 查找并扩容 SupervisorControlPlaneVM")
    resizer = ESXiDiskResizer(esx_hosts)
    disk_expanded = resizer.find_and_resize_supervisor_vm(TARGET_DISK_SIZE_GB)
    
    if not disk_expanded:
        print(f"\n  错误: 无法通过 ESXi 扩容磁盘")
        print(f"  请手动在 vSphere UI 中扩容:")
        print(f"    1. 登录 vCenter: https://{vc_ip}")
        print(f"    2. 找到 SupervisorControlPlaneVM")
        print(f"    3. 编辑设置 -> 硬盘 -> 扩容到 {TARGET_DISK_SIZE_GB}GB")
        print()
        input("  磁盘扩容完成后按 Enter 继续...")
    
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
