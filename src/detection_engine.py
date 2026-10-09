from pathlib import Path
import hashlib


# File extensions that deserve additional review.
# These are not automatically malicious.
SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".scr",
}


# File names that may contain sensitive information.
SENSITIVE_FILE_NAMES = {
    "passwords.txt",
    "password.txt",
    "credentials.txt",
    ".env",
}


# Script-capable process names.
SCRIPT_CAPABLE_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
}


# Common trusted locations for script-capable Windows processes.
TRUSTED_SCRIPT_LOCATIONS = {
    r"c:\windows\system32\windowspowershell\v1.0\powershell.exe",
    r"c:\program files\powershell\7\pwsh.exe",
    r"c:\windows\system32\cmd.exe",
    r"c:\windows\syswow64\cmd.exe",
    r"c:\windows\system32\wscript.exe",
    r"c:\windows\system32\cscript.exe",
    r"c:\windows\system32\mshta.exe",
}


def calculate_sha256(file_path):
    try:
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    except (PermissionError, OSError):
        return None


def get_trusted_script_hashes():
    trusted_hashes = set()

    for trusted_path in TRUSTED_SCRIPT_LOCATIONS:
        path = Path(trusted_path)

        if path.exists():
            file_hash = calculate_sha256(path)

            if file_hash:
                trusted_hashes.add(file_hash)

    return trusted_hashes


def analyze_process(process):
    alerts = []

    name = process.get("name", "")
    executable = process.get("executable", "")

    name_lower = name.lower()
    executable_lower = executable.lower()

    # PID 0 and PID 4 are Windows system processes.
    if process.get("pid") in (0, 4):
        return alerts

    # Unknown information alone should not be treated
    # as a security threat.
    if name_lower == "unknown":
        alerts.append({
            "severity": "INFO",
            "rule": "PROCESS_INFORMATION_UNAVAILABLE",
            "reason": (
                "The process name could not be identified. "
                "This may be caused by Windows access restrictions."
            ),
        })

    if executable_lower == "unknown":
        alerts.append({
            "severity": "INFO",
            "rule": "EXECUTABLE_INFORMATION_UNAVAILABLE",
            "reason": (
                "The executable location could not be identified. "
                "This may be caused by Windows access restrictions."
            ),
        })

    is_script_process = name_lower in SCRIPT_CAPABLE_PROCESSES
    hash_matches_trusted_script = False

    # If the process name is not recognized, compare its executable
    # hash against known trusted script-capable Windows binaries.
    if (
        executable_lower != "unknown"
        and Path(executable).exists()
        and not is_script_process
    ):
        process_hash = calculate_sha256(executable)

        if process_hash:
            trusted_hashes = get_trusted_script_hashes()

            if process_hash in trusted_hashes:
                hash_matches_trusted_script = True

    if is_script_process:
        alerts.append({
            "severity": "INFO",
            "rule": "SCRIPT_CAPABLE_PROCESS",
            "reason": (
                f"{name} is a script-capable process. "
                "This is not malicious by itself and should "
                "be evaluated with additional context."
            ),
        })

        if (
            executable_lower != "unknown"
            and executable_lower not in TRUSTED_SCRIPT_LOCATIONS
        ):
            alerts.append({
                "severity": "WARNING",
                "rule": "SCRIPT_PROCESS_UNUSUAL_LOCATION",
                "reason": (
                    f"{name} is running from a location that is "
                    "not in AI-SHIELD's common trusted locations: "
                    f"{executable}"
                ),
            })

    elif hash_matches_trusted_script:
        alerts.append({
            "severity": "WARNING",
            "rule": "TRUSTED_SCRIPT_BINARY_UNUSUAL_NAME_OR_LOCATION",
            "reason": (
                f"The executable appears to match a trusted "
                f"script-capable Windows binary by SHA-256 hash, "
                f"but it is running as {name} from an unusual "
                f"location: {executable}"
            ),
        })

    return alerts


def analyze_network(connection):
    alerts = []

    remote_address = connection.get("remote_address", "Unknown")
    status = connection.get("status", "Unknown")
    process_name = connection.get("process", "Unknown").lower()

    if (
        remote_address != "Unknown"
        and status == "ESTABLISHED"
        and process_name in SCRIPT_CAPABLE_PROCESSES
    ):
        alerts.append({
            "severity": "WARNING",
            "rule": "SCRIPT_PROCESS_NETWORK_CONNECTION",
            "reason": (
                f"{process_name} has an established network connection. "
                "This combination requires further investigation."
            ),
        })

    return alerts


def analyze_file(file_info):
    alerts = []

    file_path = file_info.get("path", "")
    path = Path(file_path)

    extension = path.suffix.lower()
    file_name = path.name.lower()

    if extension in SUSPICIOUS_EXTENSIONS:
        alerts.append({
            "severity": "INFO",
            "rule": "EXECUTABLE_FILE",
            "reason": (
                f"The file has an executable or script extension: "
                f"{extension}. Additional review may be appropriate."
            ),
        })

    if file_name in SENSITIVE_FILE_NAMES:
        alerts.append({
            "severity": "HIGH",
            "rule": "SENSITIVE_FILE",
            "reason": (
                f"The file name may contain sensitive information: "
                f"{file_name}"
            ),
        })

    return alerts