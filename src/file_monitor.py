from pathlib import Path
import time


def get_file_info(file_path):
    path = Path(file_path)

    try:
        if not path.exists():
            return {
                "path": str(path),
                "exists": False,
            }

        stat = path.stat()

        return {
            "path": str(path.resolve()),
            "exists": True,
            "size": stat.st_size,
            "modified": time.ctime(stat.st_mtime),
            "extension": path.suffix or "None",
        }

    except (PermissionError, OSError) as error:
        return {
            "path": str(path),
            "exists": "Unknown",
            "error": str(error),
        }


def monitor_directory(directory):
    directory_path = Path(directory)

    if not directory_path.exists():
        print(f"Directory not found: {directory}")
        return []

    files = []

    try:
        for file_path in directory_path.rglob("*"):
            if file_path.is_file():
                files.append(get_file_info(file_path))

    except (PermissionError, OSError) as error:
        print(f"Unable to scan directory: {error}")

    return files


def get_file_paths(files):
    return {
        file_info["path"]
        for file_info in files
        if file_info.get("exists") is True
    }


def detect_new_files(previous_files, current_files):
    previous_paths = get_file_paths(previous_files)
    current_paths = get_file_paths(current_files)

    new_paths = current_paths - previous_paths

    return [
        file_info
        for file_info in current_files
        if file_info.get("path") in new_paths
    ]


def print_file_scan(directory):
    files = monitor_directory(directory)

    print(f"Files detected: {len(files)}")
    print()

    for file_info in files[:20]:
        print(f"Path:       {file_info['path']}")
        print(f"Exists:     {file_info['exists']}")

        if file_info["exists"] is True:
            print(f"Size:       {file_info['size']} bytes")
            print(f"Modified:   {file_info['modified']}")
            print(f"Extension:  {file_info['extension']}")

        print("-" * 70)


if __name__ == "__main__":
    print_file_scan(".")