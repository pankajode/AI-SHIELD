import psutil


def get_network_connections():
    connections = []

    try:
        raw_connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print("Access denied: some network information requires Administrator privileges.")
        return connections
    except Exception as error:
        print(f"Unable to read network connections: {error}")
        return connections

    for connection in raw_connections:
        try:
            pid = connection.pid
            process_name = "Unknown"
            executable = "Unknown"

            if pid is not None:
                try:
                    process = psutil.Process(pid)
                    process_name = process.name()
                    executable = process.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            local_address = (
                f"{connection.laddr.ip}:{connection.laddr.port}"
                if connection.laddr
                else "Unknown"
            )

            remote_address = (
                f"{connection.raddr.ip}:{connection.raddr.port}"
                if connection.raddr
                else "Unknown"
            )

            connections.append({
                "pid": pid,
                "process": process_name,
                "executable": executable,
                "local_address": local_address,
                "remote_address": remote_address,
                "status": connection.status,
            })

        except Exception:
            continue

    return connections


def print_connections():
    connections = get_network_connections()

    print(f"Network connections detected: {len(connections)}")
    print()

    for connection in connections[:20]:
        print(f"PID:             {connection['pid']}")
        print(f"Process:         {connection['process']}")
        print(f"Executable:      {connection['executable']}")
        print(f"Local address:   {connection['local_address']}")
        print(f"Remote address:  {connection['remote_address']}")
        print(f"Status:          {connection['status']}")
        print("-" * 70)


if __name__ == "__main__":
    print_connections()