"""Command line interface entrypoint for DockerWard."""

import argparse
import json
import sys
from rich.console import Console
from rich.table import Table

from dockerward import __version__
from dockerward.collector.client import DockerClientManager, DockerConnectionError
from dockerward.collector.inspector import ContainerInspector

console = Console()


def format_bytes(num_bytes: int) -> str:
    """Format byte integers into human-readable memory units."""
    if num_bytes <= 0:
        return "[red]Unlimited[/red]"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def cmd_ping(client_mgr: DockerClientManager) -> int:
    """Check connectivity to the local Docker daemon."""
    try:
        client_mgr.get_client()
        console.print("[bold green]✓ Successfully connected to Docker daemon[/bold green]")
        return 0
    except DockerConnectionError as err:
        console.print(f"[bold red]✗ Connection failed:[/bold red] {err}")
        if err.hint:
            console.print(f"[yellow]Hint:[/yellow] {err.hint}")
        return 1


def cmd_inspect(inspector: ContainerInspector, target: str | None, as_json: bool) -> int:
    """Extract and display telemetry for running containers."""
    try:
        if target:
            telemetry_list = [inspector.inspect_by_id_or_name(target)]
        else:
            telemetry_list = inspector.inspect_all(only_running=True)

        if not telemetry_list:
            console.print("[yellow]No active containers found running on the host.[/yellow]")
            return 0

        if as_json:
            data = [t.model_dump() for t in telemetry_list]
            console.print_json(json.dumps(data))
            return 0

        for t in telemetry_list:
            table = Table(
                title=f"Container Telemetry: [bold cyan]{t.identity.name}[/bold cyan] ({t.identity.short_id})",
                border_style="dim",
            )
            table.add_column("Category", style="bold white", width=22)
            table.add_column("Property", style="dim cyan", width=26)
            table.add_column("Runtime Value", style="white")

            # Identity
            table.add_row("Identity", "Image", t.identity.image)
            table.add_row("Identity", "Status", f"[green]{t.identity.status}[/green]")

            # Security
            user_color = "red" if t.security.is_root else "green"
            table.add_row("Security", "User (UID)", f"[{user_color}]{t.security.user or 'root (UID 0)'}[/{user_color}]")
            
            priv_color = "bold red" if t.security.privileged else "green"
            table.add_row("Security", "Privileged Mode", f"[{priv_color}]{t.security.privileged}[/{priv_color}]")

            ro_color = "green" if t.security.read_only_rootfs else "yellow"
            table.add_row("Security", "Read-Only Rootfs", f"[{ro_color}]{t.security.read_only_rootfs}[/{ro_color}]")

            seccomp_display = "[red]UNCONFINED (Disabled)[/red]" if t.security.seccomp_unconfined else "[green]Default Filter[/green]"
            table.add_row("Security", "Seccomp Profile", seccomp_display)

            # Capabilities
            cap_drop_desc = "[green]ALL dropped[/green]" if t.capabilities.drops_all else f"[yellow]{', '.join(t.capabilities.cap_drop) or 'None'}[/yellow]"
            table.add_row("Capabilities", "CapDrop", cap_drop_desc)
            cap_add_desc = f"[red]{', '.join(t.capabilities.cap_add)}[/red]" if t.capabilities.cap_add else "[dim]None[/dim]"
            table.add_row("Capabilities", "CapAdd", cap_add_desc)

            # Resources
            mem_desc = format_bytes(t.resources.memory_bytes)
            cpu_desc = f"{t.resources.nano_cpus / 1e9:.2f} CPUs" if t.resources.nano_cpus > 0 else "[red]Unlimited[/red]"
            pids_desc = str(t.resources.pids_limit) if t.resources.pids_limit else "[red]Unlimited[/red]"
            table.add_row("Resources (cgroups)", "Memory Limit", mem_desc)
            table.add_row("Resources (cgroups)", "CPU Limit", cpu_desc)
            table.add_row("Resources (cgroups)", "PIDs Limit", pids_desc)

            # Mounts
            if t.mounts:
                for idx, m in enumerate(t.mounts, 1):
                    tag = "[bold red]DOCKER SOCKET[/bold red]" if m.is_docker_socket else f"[{m.mode}]"
                    table.add_row(f"Mount #{idx}", f"{m.source} ({tag})", f"-> {m.destination}")
            else:
                table.add_row("Mounts", "Volume / Binds", "[dim]No mounts detected[/dim]")

            # Network
            net_desc = f"[red]HOST (Bypasses NetNS)[/red]" if t.network.shares_host_network else t.network.network_mode
            table.add_row("Network", "Network Mode", net_desc)
            if t.network.port_bindings:
                for p in t.network.port_bindings:
                    exp_tag = "[red]Public (0.0.0.0)[/red]" if p.is_publicly_exposed else "[green]Local[/green]"
                    table.add_row("Network", f"Port {p.container_port}", f"Host: {p.host_ip}:{p.host_port} ({exp_tag})")

            console.print(table)
            console.print()

        return 0

    except Exception as err:
        console.print(f"[bold red]Inspection error:[/bold red] {err}")
        return 1


def main() -> None:
    """CLI parser and router."""
    parser = argparse.ArgumentParser(
        prog="dockerward",
        description="DockerWard: Runtime security audit & posture tool for Docker containers",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: ping
    subparsers.add_parser("ping", help="Verify connection to local Docker daemon")

    # Command: inspect
    inspect_p = subparsers.add_parser("inspect", help="Collect and inspect telemetry for running containers")
    inspect_p.add_argument("target", nargs="?", default=None, help="Container name or ID (optional)")
    inspect_p.add_argument("--json", action="store_true", help="Output raw telemetry as JSON")

    args = parser.parse_args()

    client_mgr = DockerClientManager()
    inspector = ContainerInspector(client_mgr)

    if args.command == "ping":
        sys.exit(cmd_ping(client_mgr))
    elif args.command == "inspect":
        sys.exit(cmd_inspect(inspector, args.target, args.json))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
