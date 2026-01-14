#!/usr/bin/env python3
"""
IR Collection Automation Script (Windows)
- Exports host/system info
- Exports event logs (optionally ALL channels to reach 500+ artifacts)
- Collects process/service/network info
- Exports registry run keys
- Filesystem triage (recursive + days-back filter)
- Scheduled tasks + user sessions
- SHA256 hashes + manifest
- Optional ZIP compression

REQUIRES: psutil  (pip install psutil)
RUN AS: Administrator
"""

import os
import sys
import json
import subprocess
import argparse
import datetime
import shutil
import hashlib
from pathlib import Path
import socket

# Windows-only imports (guarded)
if os.name == "nt":
    import ctypes
    import winreg
    import psutil
else:
    print("This script is intended for Windows only.")
    sys.exit(1)


def run_command(cmd: str, capture_output: bool = True) -> str:
    """Execute a command and return stdout (best effort)."""
    try:
        if capture_output:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
            # Some commands write to stderr even on success; include if stdout empty
            out = result.stdout or ""
            err = result.stderr or ""
            return out if out.strip() else err
        else:
            subprocess.run(cmd, shell=True)
            return ""
    except Exception as e:
        return f"Error executing command: {str(e)}"


def is_admin() -> bool:
    """Check if running as admin on Windows."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def safe_filename(name: str) -> str:
    """Make a filesystem-safe filename."""
    return "".join(c if c.isalnum() or c in (" ", "-", "_", ".", "(", ")") else "_" for c in name).strip()


def setup_directories(case_path: Path, subdirs):
    """Create case directory structure."""
    case_path.mkdir(parents=True, exist_ok=True)
    for subdir in subdirs:
        (case_path / subdir).mkdir(parents=True, exist_ok=True)


def write_error(case_path: Path, msg: str):
    with open(case_path / "errors.log", "a", encoding="utf-8") as f:
        f.write(msg.rstrip() + "\n")


def collect_host_info(case_path: Path):
    """Collect host and system information."""
    print("[1/8] Collecting host and system information...")

    with open(case_path / "hostinfo.txt", "w", encoding="utf-8") as f:
        f.write(f"Computer Name: {socket.gethostname()}\n")
        f.write(f"User: {os.environ.get('USERNAME', '')}\n")
        f.write(f"Domain: {os.environ.get('USERDOMAIN', '')}\n")
        f.write(f"OS Platform: {sys.platform}\n")
        f.write(f"Python Version: {sys.version}\n")
        f.write(f"Collection Time: {datetime.datetime.now().isoformat()}\n")

    systeminfo_output = run_command("systeminfo")
    with open(case_path / "systeminfo.txt", "w", encoding="utf-8") as f:
        f.write(systeminfo_output)


def collect_event_logs(case_path: Path, skip_logs: bool, all_event_logs: bool, max_event_logs: int):
    """Collect Windows event logs (default 4, or ALL channels for 500+)."""
    if skip_logs:
        print("[2/8] Skipping event logs (as requested).")
        return

    print("[2/8] Collecting event logs...")

    if all_event_logs:
        all_logs_raw = run_command("wevtutil el")
        log_names = [ln.strip() for ln in all_logs_raw.splitlines() if ln.strip()]
        log_names = log_names[:max_event_logs]
        print(f"      Exporting {len(log_names)} event log channels (cap={max_event_logs})...")
    else:
        log_names = ["Security", "System", "Application", "Windows PowerShell"]
        print("      Exporting default logs: Security, System, Application, Windows PowerShell...")

    exported = 0
    for log_name in log_names:
        try:
            out_name = safe_filename(log_name) + ".evtx"
            output_path = case_path / "logs" / out_name
            cmd = f'wevtutil epl "{log_name}" "{output_path}"'
            run_command(cmd, capture_output=False)
            if output_path.exists():
                exported += 1
        except Exception as e:
            write_error(case_path, f"Failed to export log '{log_name}': {e}")

    print(f"      Event logs exported: {exported}")


def collect_processes_services(case_path: Path):
    """Collect process and service information."""
    print("[3/8] Collecting process and service information...")

    # Processes
    proc_csv = case_path / "process" / "processes.csv"
    with open(proc_csv, "w", encoding="utf-8") as f:
        f.write("Name,Id,Path,StartTime,CommandLine,User\n")
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time', 'cmdline', 'username']):
            try:
                info = proc.info
                name = (info.get("name") or "").replace('"', '""')
                pid = info.get("pid") or ""
                path = (info.get("exe") or "").replace('"', '""')
                ct = info.get("create_time")
                start_time = datetime.datetime.fromtimestamp(ct).isoformat() if ct else ""
                cmdline = " ".join(info.get("cmdline") or [])
                cmdline = cmdline.replace('"', '""')
                user = (info.get("username") or "").replace('"', '""')
                f.write(f'"{name}",{pid},"{path}","{start_time}","{cmdline}","{user}"\n')
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                write_error(case_path, f"Process iter error: {e}")

    # Services
    svc_csv = case_path / "process" / "services.csv"
    with open(svc_csv, "w", encoding="utf-8") as f:
        f.write("Name,Status,DisplayName\n")
        try:
            for service in psutil.win_service_iter():
                try:
                    s = service.as_dict()
                    name = (s.get("name") or "").replace('"', '""')
                    status = (s.get("status") or "").replace('"', '""')
                    display = (s.get("display_name") or "").replace('"', '""')
                    f.write(f'"{name}","{status}","{display}"\n')
                except Exception:
                    continue
        except Exception as e:
            write_error(case_path, f"Service iter error: {e}")


def collect_network_info(case_path: Path, skip_network: bool):
    """Collect network information."""
    if skip_network:
        print("[4/8] Skipping network collection (as requested).")
        return

    print("[4/8] Collecting network information...")

    # TCP connections
    tcp_csv = case_path / "network" / "tcp_connections.csv"
    with open(tcp_csv, "w", encoding="utf-8") as f:
        f.write("LocalAddress,LocalPort,RemoteAddress,RemotePort,Status,Pid\n")
        try:
            for conn in psutil.net_connections(kind='tcp'):
                try:
                    if conn.laddr and conn.raddr:
                        f.write(f"{conn.laddr.ip},{conn.laddr.port},{conn.raddr.ip},{conn.raddr.port},{conn.status},{conn.pid}\n")
                except Exception:
                    continue
        except Exception as e:
            write_error(case_path, f"TCP collection error: {e}")

    # UDP endpoints
    udp_csv = case_path / "network" / "udp_endpoints.csv"
    with open(udp_csv, "w", encoding="utf-8") as f:
        f.write("LocalAddress,LocalPort,Pid\n")
        try:
            for conn in psutil.net_connections(kind='udp'):
                try:
                    if conn.laddr:
                        f.write(f"{conn.laddr.ip},{conn.laddr.port},{conn.pid}\n")
                except Exception:
                    continue
        except Exception as e:
            write_error(case_path, f"UDP collection error: {e}")

    # IP config / DNS / netstat
    (case_path / "network" / "ipconfig.txt").write_text(run_command("ipconfig /all"), encoding="utf-8", errors="replace")
    (case_path / "network" / "dns_cache.txt").write_text(run_command("ipconfig /displaydns"), encoding="utf-8", errors="replace")
    (case_path / "network" / "netstat_ano.txt").write_text(run_command("netstat -ano"), encoding="utf-8", errors="replace")


def collect_registry_triage(case_path: Path):
    """Collect registry information."""
    print("[5/8] Collecting registry triage...")

    reg_keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]

    for key_path in reg_keys:
        try:
            name = safe_filename(key_path.replace("\\", "_").replace(":", ""))
            output_file = case_path / "registry" / f"{name}.reg"
            cmd = f'reg export "{key_path}" "{output_file}" /y'
            run_command(cmd, capture_output=False)
        except Exception as e:
            write_error(case_path, f"Failed to export registry key {key_path}: {e}")


def collect_filesystem_triage(case_path: Path, days_back: int, max_fs_items: int):
    """Collect filesystem triage (recursive + days-back filter)."""
    print("[6/8] Collecting filesystem triage...")

    cutoff = datetime.datetime.now() - datetime.timedelta(days=days_back)

    fs_paths = [
        str(Path.home() / "Desktop"),
        str(Path.home() / "Downloads"),
        str(Path.home() / "Recent"),
        r"C:\Windows\Prefetch",
        r"C:\Windows\Temp",
        os.environ.get("TEMP", ""),
    ]

    def include_item(p: Path) -> bool:
        try:
            st = p.stat()
            return datetime.datetime.fromtimestamp(st.st_mtime) >= cutoff
        except Exception:
            return False

    for path in fs_paths:
        if not path or not os.path.exists(path):
            continue

        base = Path(path)
        out_csv = case_path / "fs" / f"{safe_filename(base.name)}_recursive_last{days_back}d.csv"

        count = 0
        try:
            with open(out_csv, "w", encoding="utf-8") as f:
                f.write("FullPath,Name,Length,LastWriteTime,LastAccessTime,CreationTime,IsDir\n")

                for item in base.rglob("*"):
                    if count >= max_fs_items:
                        break
                    if not include_item(item):
                        continue
                    try:
                        st = item.stat()
                        f.write(
                            f'"{str(item)}","{item.name.replace("\"","\"\"")}",{st.st_size},'
                            f'{datetime.datetime.fromtimestamp(st.st_mtime).isoformat()},'
                            f'{datetime.datetime.fromtimestamp(st.st_atime).isoformat()},'
                            f'{datetime.datetime.fromtimestamp(st.st_ctime).isoformat()},'
                            f'{item.is_dir()}\n'
                        )
                        count += 1
                    except (PermissionError, OSError):
                        continue

            print(f"      {base}: rows written={count} (cap={max_fs_items})")

        except Exception as e:
            write_error(case_path, f"Failed to triage path {path}: {e}")


def collect_additional_artifacts(case_path: Path):
    """Collect additional artifacts (scheduled tasks, user sessions)."""
    print("[7/8] Collecting additional artifacts...")

    try:
        tasks_output = run_command('schtasks /query /fo CSV /v')
        (case_path / "artifacts" / "scheduled_tasks.csv").write_text(tasks_output, encoding="utf-8", errors="replace")
    except Exception as e:
        write_error(case_path, f"Scheduled tasks error: {e}")

    try:
        user_output = run_command('query user')
        (case_path / "artifacts" / "user_sessions.txt").write_text(user_output, encoding="utf-8", errors="replace")
    except Exception as e:
        write_error(case_path, f"User sessions error: {e}")


def calculate_hashes(case_path: Path, max_file_size_mb: int = 100):
    """Calculate SHA256 hashes for collected artifacts."""
    print("[8/8] Calculating file hashes + writing manifest...")

    limit = max_file_size_mb * 1024 * 1024
    hash_file = case_path / "hashes.csv"
    with open(hash_file, "w", encoding="utf-8") as f:
        f.write("Path,SHA256,FileSize,LastModified\n")

    files_hashed = 0
    for file_path in case_path.rglob("*"):
        if not file_path.is_file():
            continue
        try:
            if file_path.stat().st_size > limit:
                continue

            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as fp:
                for chunk in iter(lambda: fp.read(1024 * 1024), b""):
                    sha256_hash.update(chunk)

            st = file_path.stat()
            rel = file_path.relative_to(case_path)
            with open(hash_file, "a", encoding="utf-8") as f:
                f.write(
                    f'"{rel.as_posix()}",{sha256_hash.hexdigest()},{st.st_size},'
                    f'{datetime.datetime.fromtimestamp(st.st_mtime).isoformat()}\n'
                )
            files_hashed += 1
        except Exception:
            continue

    # Manifest
    total_size = sum(p.stat().st_size for p in case_path.rglob("*") if p.is_file())
    all_files = [p for p in case_path.rglob("*") if p.is_file()]

    manifest = {
        "CaseID": str(datetime.datetime.now().timestamp()),
        "CasePath": str(case_path),
        "Timestamp": datetime.datetime.now().isoformat(),
        "Host": socket.gethostname(),
        "User": os.environ.get("USERNAME", ""),
        "Investigator": f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}",
        "FilesWritten": len(all_files),
        "FilesHashed": files_hashed,
        "TotalSizeMB": round(total_size / (1024 * 1024), 2),
        "ScriptVersion": "2.1_python_alllogs_fsrecursive"
    }

    with open(case_path / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


def compress_output(case_path: Path) -> Path:
    """Compress output directory and remove folder."""
    print("Compressing output to ZIP...")
    zip_path = Path(str(case_path) + ".zip")
    shutil.make_archive(str(case_path), "zip", str(case_path))
    shutil.rmtree(case_path, ignore_errors=True)
    return zip_path


def file_size_mb(path: Path) -> float:
    """Size helper: works for folder or file."""
    if path.is_file():
        return round(path.stat().st_size / (1024 * 1024), 2)
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except Exception:
                continue
    return round(total / (1024 * 1024), 2)


def main():
    parser = argparse.ArgumentParser(description="IR Collection Automation Script (Windows)")
    parser.add_argument("--out-root", default=r"C:\IR_Auto\output", help="Output root directory")
    parser.add_argument("--days-back", type=int, default=7, help="Days back for filesystem triage filter")
    parser.add_argument("--skip-logs", action="store_true", help="Skip event logs")
    parser.add_argument("--skip-network", action="store_true", help="Skip network collection")
    parser.add_argument("--compress-output", action="store_true", help="Compress output to ZIP and delete folder")

    # The key option to get 500+ artifacts:
    parser.add_argument("--all-event-logs", action="store_true",
                        help="Export ALL Windows event log channels (often 200–800+ .evtx files)")
    parser.add_argument("--max-event-logs", type=int, default=800,
                        help="Safety cap for number of event log channels to export")
    parser.add_argument("--max-fs-items", type=int, default=5000,
                        help="Max filesystem rows per path (avoid huge outputs)")

    args = parser.parse_args()

    if not is_admin():
        print("ERROR: Run this script as Administrator.")
        print("Tip: Start Menu -> type 'cmd' -> Right click -> Run as administrator")
        sys.exit(1)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    case_path = Path(args.out_root) / f"auto_run_{timestamp}"
    subdirs = ["logs", "registry", "process", "network", "fs", "artifacts"]

    print(f"\nStarting IR collection to:\n  {case_path}\n")
    setup_directories(case_path, subdirs)

    collect_host_info(case_path)
    collect_event_logs(case_path, args.skip_logs, args.all_event_logs, args.max_event_logs)
    collect_processes_services(case_path)
    collect_network_info(case_path, args.skip_network)
    collect_registry_triage(case_path)
    collect_filesystem_triage(case_path, args.days_back, args.max_fs_items)
    collect_additional_artifacts(case_path)
    calculate_hashes(case_path)

    final_output = case_path
    if args.compress_output:
        final_output = compress_output(case_path)

    print("\n=== COLLECTION SUMMARY ===")
    print(f"Output: {final_output}")
    print(f"Total size: {file_size_mb(final_output)} MB")
    if isinstance(final_output, Path) and final_output.suffix.lower() == ".zip":
        print("Mode: Compressed ZIP")
    else:
        print("Mode: Folder output")

    # Quick count of artifacts (files)
    if final_output.is_dir():
        files_written = sum(1 for _ in final_output.rglob("*") if _.is_file())
        print(f"Files written: {files_written}")
    else:
        print("Files written: (inside ZIP)")

    print("\nDone.")


if __name__ == "__main__":
    main()
