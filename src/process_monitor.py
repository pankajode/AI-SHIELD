import psutil


def get_running_processes():
    processes = []

    for process in psutil.process_iter(
        ["pid", "name", "exe", "username", "status"]
    ):
        try:
            info = process.info

            processes.append({
                "pid": info["pid"],
                "name": info["name"] or "Unknown",
                "executable": info["exe"] or "Unknown",
                "username": info["username"] or "Unknown",
                "status": info["status"] or "Unknown",
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes


def print_processes():
    processes = get_running_processes()

    print(f"Running processes: {len(processes)}")
    print()

    for process in processes[:20]:
        print(f"PID:          {process['pid']}")
        print(f"Name:         {process['name']}")
        print(f"Location:     {process['executable']}")
        print(f"User:         {process['username']}")
        print(f"Status:       {process['status']}")
        print("-" * 60)


if __name__ == "__main__":
    print_processes()