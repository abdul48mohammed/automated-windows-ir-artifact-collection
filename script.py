#!/usr/bin/env python3
"""
IR Collection Automation Script
Converted from PowerShell to Python
"""

import os
import sys
import json
import subprocess
import argparse
import datetime
import shutil
import hashlib
import glob
from pathlib import Path
import winreg
import psutil
import socket

def run_command(cmd, capture_output=True):
    """Execute a command and return result"""
    try:
        if capture_output:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout
        else:
            subprocess.run(cmd, shell=True)
            return ""
    except Exception as e:
        return f"Error executing command: {str(e)}"

def setup_directories(case_path, subdirs):
    """Create case directory structure"""
    Path(case_path).mkdir(parents=True, exist_ok=True)
    for subdir in subdirs:
        Path(case_path, subdir).mkdir(parents=True, exist_ok=True)

def collect_host_info(case_path):
    """Collect host and system information"""
    print("Collecting host and system information...")
    
    # Basic system info
    with open(Path(case_path, "hostinfo.txt"), "w") as f:
        f.write(f"Computer Name: {socket.gethostname()}\n")
        f.write(f"OS: {sys.platform}\n")
        f.write(f"Python Version: {sys.version}\n")
        f.write(f"Collection Time: {datetime.datetime.now().isoformat()}\n")
    
    # System info via systeminfo command
    systeminfo_output = run_command("systeminfo")
    with open(Path(case_path, "systeminfo.txt"), "w") as f:
        f.write(systeminfo_output)

def collect_event_logs(case_path, skip_logs):
    """Collect Windows event logs"""
    if skip_logs:
        return
        
    print("Collecting event logs...")
    log_names = ["Security", "System", "Application", "Windows PowerShell"]
    
    for log_name in log_names:
        try:
            output_path = Path(case_path, "logs", f"{log_name}.evtx")
            cmd = f'wevtutil epl "{log_name}" "{output_path}"'
            run_command(cmd, capture_output=False)
        except Exception as e:
            error_msg = f"Failed to export {log_name} log: {str(e)}\n"
            with open(Path(case_path, "errors.log"), "a") as f:
                f.write(error_msg)

def collect_processes_services(case_path):
    """Collect process and service information"""
    print("Collecting process and service information...")
    
    # Processes
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time', 'cmdline', 'username']):
        try:
            processes.append({
                'Name': proc.info['name'],
                'Id': proc.info['pid'],
                'Path': proc.info['exe'],
                'StartTime': datetime.datetime.fromtimestamp(proc.info['create_time']).isoformat() if proc.info['create_time'] else '',
                'CommandLine': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                'User': proc.info['username']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    with open(Path(case_path, "process", "processes.csv"), "w") as f:
        f.write("Name,Id,Path,StartTime,CommandLine,User\n")
        for proc in processes:
            f.write(f'"{proc["Name"]}",{proc["Id"]},"{proc["Path"]}","{proc["StartTime"]}","{proc["CommandLine"]}","{proc["User"]}"\n')
    
    # Services
    services = []
    for service in psutil.win_service_iter():
        services.append({
            'Name': service.name(),
            'Status': service.status(),
            'DisplayName': service.display_name(),
            'StartType': 'Unknown'  # psutil doesn't provide start type directly
        })
    
    with open(Path(case_path, "process", "services.csv"), "w") as f:
        f.write("Name,Status,DisplayName,StartType\n")
        for service in services:
            f.write(f'"{service["Name"]}","{service["Status"]}","{service["DisplayName"]}","{service["StartType"]}"\n')

def collect_network_info(case_path, skip_network):
    """Collect network information"""
    if skip_network:
        return
        
    print("Collecting network information...")
    
    # TCP connections
    with open(Path(case_path, "network", "tcp_connections.csv"), "w") as f:
        f.write("LocalAddress,LocalPort,RemoteAddress,RemotePort,Status,Pid\n")
        for conn in psutil.net_connections(kind='tcp'):
            if conn.laddr and conn.raddr:
                f.write(f"{conn.laddr.ip},{conn.laddr.port},{conn.raddr.ip},{conn.raddr.port},{conn.status},{conn.pid}\n")
    
    # UDP endpoints
    with open(Path(case_path, "network", "udp_endpoints.csv"), "w") as f:
        f.write("LocalAddress,LocalPort,Pid\n")
        for conn in psutil.net_connections(kind='udp'):
            if conn.laddr:
                f.write(f"{conn.laddr.ip},{conn.laddr.port},{conn.pid}\n")
    
    # IP configuration
    ipconfig_output = run_command("ipconfig /all")
    with open(Path(case_path, "network", "ipconfig.txt"), "w") as f:
        f.write(ipconfig_output)
    
    # DNS cache
    dns_output = run_command("ipconfig /displaydns")
    with open(Path(case_path, "network", "dns_cache.txt"), "w") as f:
        f.write(dns_output)
    
    # Netstat
    netstat_output = run_command("netstat -ano")
    with open(Path(case_path, "network", "netstat_ano.txt"), "w") as f:
        f.write(netstat_output)

def collect_registry_triage(case_path):
    """Collect registry information"""
    print("Collecting registry information...")
    
    reg_keys = [
        ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", winreg.HKEY_LOCAL_MACHINE),
        ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", winreg.HKEY_LOCAL_MACHINE),
        ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", winreg.HKEY_CURRENT_USER),
        ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", winreg.HKEY_CURRENT_USER)
    ]
    
    for key_path, hive in reg_keys:
        try:
            name = key_path.replace("\\", "_").replace(":", "")
            output_file = Path(case_path, "registry", f"{name}.reg")
            cmd = f'reg export "{key_path}" "{output_file}" /y'
            run_command(cmd, capture_output=False)
        except Exception as e:
            error_msg = f"Failed to export registry key {key_path}: {str(e)}\n"
            with open(Path(case_path, "errors.log"), "a") as f:
                f.write(error_msg)

def collect_filesystem_triage(case_path):
    """Collect filesystem information"""
    print("Collecting filesystem information...")
    
    fs_paths = [
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/Recent"),
        "C:\\Windows\\Prefetch",
        "C:\\Windows\\Temp",
        os.environ.get('TEMP', '')
    ]
    
    for path in fs_paths:
        if os.path.exists(path):
            try:
                name = os.path.basename(path) or os.path.basename(os.path.dirname(path))
                with open(Path(case_path, "fs", f"{name}_listing.csv"), "w") as f:
                    f.write("Name,Length,LastWriteTime,LastAccessTime,CreationTime,Attributes\n")
                    for item in Path(path).iterdir():
                        try:
                            stat = item.stat()
                            f.write(f'"{item.name}",{stat.st_size},{datetime.datetime.fromtimestamp(stat.st_mtime).isoformat()},'
                                   f'{datetime.datetime.fromtimestamp(stat.st_atime).isoformat()},'
                                   f'{datetime.datetime.fromtimestamp(stat.st_ctime).isoformat()},{stat.st_filemode}\n')
                        except (PermissionError, OSError):
                            continue
            except Exception as e:
                error_msg = f"Failed to process path {path}: {str(e)}\n"
                with open(Path(case_path, "errors.log"), "a") as f:
                    f.write(error_msg)

def collect_additional_artifacts(case_path):
    """Collect additional artifacts"""
    print("Collecting additional artifacts...")
    
    # Scheduled tasks
    try:
        tasks_output = run_command('schtasks /query /fo CSV /v')
        with open(Path(case_path, "artifacts", "scheduled_tasks.csv"), "w") as f:
            f.write(tasks_output)
    except Exception as e:
        pass
    
    # User sessions
    try:
        user_output = run_command('query user')
        with open(Path(case_path, "artifacts", "user_sessions.txt"), "w") as f:
            f.write(user_output)
    except Exception as e:
        pass

def calculate_hashes(case_path):
    """Calculate file hashes for collected artifacts"""
    print("Calculating file hashes...")
    
    hash_file = Path(case_path, "hashes.csv")
    with open(hash_file, "w") as f:
        f.write("Path,SHA256,FileSize,LastModified\n")
    
    for file_path in Path(case_path).rglob('*'):
        if file_path.is_file() and file_path.stat().st_size < 100 * 1024 * 1024:  # 100MB limit
            try:
                # Calculate SHA256 hash
                sha256_hash = hashlib.sha256()
                with open(file_path, "rb") as file:
                    for chunk in iter(lambda: file.read(4096), b""):
                        sha256_hash.update(chunk)
                
                file_stat = file_path.stat()
                relative_path = file_path.relative_to(case_path)
                
                with open(hash_file, "a") as f:
                    f.write(f'"{relative_path}",{sha256_hash.hexdigest()},{file_stat.st_size},'
                           f'{datetime.datetime.fromtimestamp(file_stat.st_mtime).isoformat()}\n')
            except Exception as e:
                continue

def create_manifest(case_path, files_to_hash):
    """Create collection manifest"""
    print("Creating manifest...")
    
    total_size = sum(f.stat().st_size for f in Path(case_path).rglob('*') if f.is_file())
    
    manifest = {
        "CaseID": str(datetime.datetime.now().timestamp()),
        "CasePath": str(case_path),
        "Timestamp": datetime.datetime.now().isoformat(),
        "Host": socket.gethostname(),
        "User": os.environ.get('USERNAME', ''),
        "Investigator": f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}",
        "ItemsCollected": len(files_to_hash),
        "TotalSizeMB": round(total_size / (1024 * 1024), 2),
        "ScriptVersion": "2.0_python"
    }
    
    with open(Path(case_path, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

def compress_output(case_path):
    """Compress the output directory"""
    print("Compressing output...")
    zip_path = f"{case_path}.zip"
    shutil.make_archive(case_path, 'zip', case_path)
    shutil.rmtree(case_path)
    return zip_path

def main():
    parser = argparse.ArgumentParser(description='IR Collection Automation Script')
    parser.add_argument('--out-root', default='C:\\IR_Auto\\output', help='Output root directory')
    parser.add_argument('--days-back', type=int, default=7, help='Number of days back to collect')
    parser.add_argument('--skip-logs', action='store_true', help='Skip event logs collection')
    parser.add_argument('--skip-network', action='store_true', help='Skip network collection')
    parser.add_argument('--compress-output', action='store_true', help='Compress output to zip')
    
    args = parser.parse_args()
    
    # Check if running as administrator (Windows)
    if os.name == 'nt':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Error: This script must be run as Administrator")
                sys.exit(1)
        except:
            print("Warning: Could not verify administrator privileges")
    
    # Initialize
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    case_path = Path(args.out_root) / f"auto_run_{timestamp}"
    subdirs = ["logs", "registry", "process", "network", "fs", "artifacts"]
    
    print(f"Starting IR collection to: {case_path}")
    
    # Create directory structure
    setup_directories(case_path, subdirs)
    
    # Collection phases
    collect_host_info(case_path)
    collect_event_logs(case_path, args.skip_logs)
    collect_processes_services(case_path)
    collect_network_info(case_path, args.skip_network)
    collect_registry_triage(case_path)
    collect_filesystem_triage(case_path)
    collect_additional_artifacts(case_path)
    
    # Get files for hashing before potential compression
    files_to_hash = [f for f in Path(case_path).rglob('*') 
                    if f.is_file() and f.stat().st_size < 100 * 1024 * 1024]
    
    calculate_hashes(case_path)
    create_manifest(case_path, files_to_hash)
    
    # Compression
    final_output = case_path
    if args.compress_output:
        zip_path = compress_output(case_path)
        final_output = zip_path
        print(f"IR collection complete (compressed): {zip_path}")
    else:
        print(f"IR collection complete: {case_path}")
    
    # Summary
    total_size = sum(f.stat().st_size for f in Path(final_output).rglob('*') if f.is_file())
    
    print("\n=== COLLECTION SUMMARY ===")
    print(f"Files Collected: {len(files_to_hash)}")
    print(f"Total Size: {round(total_size / (1024 * 1024), 2)} MB")
    print("Artifacts: Processes, Services, Network, Registry, Event Logs, Filesystem")
    print(f"Output: {final_output}")

if __name__ == "__main__":
    main()