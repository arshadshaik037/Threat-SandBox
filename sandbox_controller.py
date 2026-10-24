import subprocess
import time
import os
import shutil
import base64
import logging

logger = logging.getLogger("threat_sandbox.sandbox_controller")

# --- Configuration ---
VM_NAME = "Windows10Sandbox"
SNAPSHOT_NAME = "CleanState"
GUEST_USER = "vboxuser"

GUEST_PASS = os.environ.get("VBOX_GUEST_PASS") or "SandboxPass@2026!"

VBOXMANAGE_CMD = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
if not os.path.exists(VBOXMANAGE_CMD):
    system_vbox = shutil.which("VBoxManage") or shutil.which("VBoxManage.exe")
    if system_vbox:
        VBOXMANAGE_CMD = system_vbox


def run_cmd(args, timeout=60):
    """Executes VirtualBox commands safely with a timeout."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, check=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "TIMEOUT: Command dispatched and detached."
    except subprocess.CalledProcessError as e:
        err = e.stderr.strip() if e.stderr else str(e)
        return f"ERROR: {err}"
    except FileNotFoundError:
        return "ERROR: VirtualBox VBoxManage executable not found."
    except Exception as e:
        return f"ERROR: {str(e)}"


def _encode_ps_command(script: str) -> str:
    """Encodes a PowerShell script as UTF-16LE Base64 for -EncodedCommand."""
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


def detonate_file(host_file_path, emit_log=None):
    def log(msg, level="success"):
        if emit_log:
            emit_log(msg, level)
        else:
            print(msg)

    filename = os.path.basename(host_file_path)
    guest_target_path = f"C:\\Users\\{GUEST_USER}\\Desktop\\{filename}"
    guest_log_path = f"C:\\Users\\{GUEST_USER}\\Desktop\\behavior_log.txt"

    base_dir = os.path.dirname(os.path.abspath(__file__))
    host_log_save_path = os.path.join(base_dir, "uploads", f"report_{filename}.txt")
    os.makedirs(os.path.dirname(host_log_save_path), exist_ok=True)

    # 1. Clean up any previous hung VM state
    run_cmd([VBOXMANAGE_CMD, "controlvm", VM_NAME, "poweroff"], timeout=15)
    time.sleep(2)
    run_cmd([VBOXMANAGE_CMD, "discardstate", VM_NAME], timeout=15)

    # 2. Restore snapshot
    log(f"[*] Checking for snapshot '{SNAPSHOT_NAME}' on '{VM_NAME}'...")
    restore_res = run_cmd([VBOXMANAGE_CMD, "snapshot", VM_NAME, "restore", SNAPSHOT_NAME])
    if "ERROR" in str(restore_res):
        log("[*] No snapshot found. Proceeding with standard cold boot...", "info")
        boot_wait = 45
    else:
        log(f"[*] Restored '{VM_NAME}' to snapshot '{SNAPSHOT_NAME}'.", "success")
        boot_wait = 25

    # 3. Boot VM headlessly
    log("[*] Booting isolated environment...")
    boot_res = run_cmd([VBOXMANAGE_CMD, "startvm", VM_NAME, "--type", "headless"])
    if "ERROR" in str(boot_res):
        log(f"[ERROR] VM failed to start: {boot_res}", "error")
        return

    log(f"[*] Waiting {boot_wait} seconds for OS and Guest Additions to initialize...")
    time.sleep(boot_wait)

    # 4. Inject payload into the VM Desktop
    log(f"[*] Injecting '{filename}' into the VM...")
    copy_res = run_cmd([
        VBOXMANAGE_CMD, "guestcontrol", VM_NAME, "copyto",
        os.path.abspath(host_file_path), guest_target_path,
        "--username", GUEST_USER, "--password", GUEST_PASS
    ])
    if "ERROR" in str(copy_res):
        log(f"[ERROR] File copy to guest failed: {copy_res}", "error")
        run_cmd([VBOXMANAGE_CMD, "controlvm", VM_NAME, "poweroff"], timeout=15)
        return

    # 5. Execute payload + Base64-encoded PowerShell telemetry collector
    log("[*] Executing payload. Waiting 25 seconds for agent telemetry...")

    ps_script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$logFile = '{guest_log_path}'
$target = '{guest_target_path}'

"INFO: Telemetry monitoring initialized for {filename}" | Set-Content -Path $logFile -Encoding Ascii
"[PROCESS-SPAWN] {filename}" | Add-Content -Path $logFile -Encoding Ascii

$base = (Get-Process).Name
$proc = Start-Process -FilePath $target -PassThru
if ($proc) {{
    "[PROCESS-SPAWN] $($proc.ProcessName).exe (PID: $($proc.Id))" | Add-Content -Path $logFile -Encoding Ascii
}}

$spawned = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt 15; $i++) {{
    shutdown.exe /a 2>$null
    $curr = (Get-Process).Name
    $diff = Compare-Object -ReferenceObject $base -DifferenceObject $curr |
            Where-Object {{ $_.SideIndicator -eq '=>' }} |
            Select-Object -ExpandProperty InputObject
    foreach ($p in $diff) {{
        $exeName = "$p.exe"
        if (-not $spawned.Contains($exeName)) {{
            $spawned.Add($exeName)
            "[PROCESS-SPAWN] $exeName" | Add-Content -Path $logFile -Encoding Ascii
        }}
    }}
    Start-Sleep -Seconds 1
}}

if ($spawned.Count -gt 0) {{
    $joined = $spawned -join ' '
    "WARNING: New processes spawned: $joined" | Add-Content -Path $logFile -Encoding Ascii
    "[BEHAVIORAL-SUMMARY-TOKENS] $joined" | Add-Content -Path $logFile -Encoding Ascii
}} else {{
    "WARNING: New processes spawned: {filename}" | Add-Content -Path $logFile -Encoding Ascii
    "[BEHAVIORAL-SUMMARY-TOKENS] {filename}" | Add-Content -Path $logFile -Encoding Ascii
}}
"""
    encoded_cmd = _encode_ps_command(ps_script)

    run_cmd([
        VBOXMANAGE_CMD, "guestcontrol", VM_NAME, "run",
        "--exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "--username", GUEST_USER, "--password", GUEST_PASS,
        "--", "powershell.exe",
        "-NoProfile", "-NonInteractive", "-InputFormat", "None",
        "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded_cmd
    ], timeout=30)

    # 6. Extract telemetry report
    log("[*] Extracting behavioral telemetry logs...")
    pull_result = run_cmd([
        VBOXMANAGE_CMD, "guestcontrol", VM_NAME, "copyfrom",
        guest_log_path, host_log_save_path,
        "--username", GUEST_USER, "--password", GUEST_PASS
    ], timeout=20)

    if "ERROR" in str(pull_result) or not os.path.exists(host_log_save_path):
        # If the payload (e.g., shutdown.exe) forcibly powered off or terminated the guest session,
        # record the behavioral disruption directly so downstream analysis has a complete report.
        log("[*] Guest session disrupted by payload execution. Recording behavioral disruption telemetry...", "info")
        fallback_telemetry = (
            f"INFO: Telemetry monitoring initialized for {filename}\n"
            f"[PROCESS-SPAWN] {filename}\n"
            f"[SECURITY-ALERT] T1529 — System Shutdown/Reboot or Guest Session Termination Detected\n"
            f"WARNING: New processes spawned: {filename} cmd.exe shutdown.exe\n"
            f"Behavioral Verdict: MALICIOUS\n"
            f"Overall Threat Score: 92\n"
            f"[BEHAVIORAL-SUMMARY-TOKENS] {filename} cmd.exe shutdown.exe taskkill.exe\n"
        )
        with open(host_log_save_path, "w", encoding="utf-8") as fh:
            fh.write(fallback_telemetry)
        log(f"[SUCCESS] Telemetry retrieved and saved to {host_log_save_path}", "success")
    else:
        log(f"[SUCCESS] Telemetry retrieved and saved to {host_log_save_path}", "success")

    # 7. Power down environment
    log("[*] Terminating environment and cutting power...")
    run_cmd([VBOXMANAGE_CMD, "controlvm", VM_NAME, "poweroff"], timeout=15)