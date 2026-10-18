from __future__ import annotations

import argparse
import csv
import html
import os
import sys
import time
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from cloud_d.application import CloudDApplication
    from cloud_d.server import main as run_server
else:
    from .application import CloudDApplication
    from .server import main as run_server


RESULTS_DIR = Path(__file__).resolve().parent / "results"


def write_results(report: dict) -> tuple[Path, Path]:
    """Write a compact metrics CSV and node-health SVG without exposing file contents."""
    charts_dir = RESULTS_DIR / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)
    metrics_path = RESULTS_DIR / "metrics.csv"
    chart_path = charts_dir / "node_health.svg"
    fields = (
        "rounds", "total_attacks", "blocked", "block_rate", "total_records",
        "protected", "compromised", "protection_rate", "damage_taken",
    )
    with metrics_path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerow({field: report.get(field, "") for field in fields})

    nodes = report.get("node_health", [])
    width, row_height = 760, 58
    height = 72 + len(nodes) * row_height
    bars = []
    for index, node in enumerate(nodes):
        y = 42 + index * row_height
        health = max(0, min(100, int(node.get("health", 0))))
        color = "#54d69b" if health > 70 else "#ffc66d" if health > 30 else "#ff7887"
        name = html.escape(str(node.get("name", "Cloud node")))
        bars.append(
            f'<text x="24" y="{y + 17}" fill="#eaf0fa" font-size="14">{name}</text>'
            f'<rect x="220" y="{y}" width="440" height="20" rx="6" fill="#26344d" />'
            f'<rect x="220" y="{y}" width="{health * 4.4:.1f}" height="20" rx="6" fill="{color}" />'
            f'<text x="680" y="{y + 16}" fill="#c7d4e7" font-size="13">{health} HP</text>'
        )
    chart = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        '<rect width="100%" height="100%" fill="#0a1020" />'
        '<text x="24" y="27" fill="#52d6d0" font-family="sans-serif" font-size="16" font-weight="700">CLOUD-D · NODE HEALTH</text>'
        + "".join(bars)
        + "</svg>"
    )
    chart_path.write_text(chart, encoding="utf-8")
    return metrics_path, chart_path


def run_console(delay: float = 0.0) -> dict:
    """Run the attacker/defender loop and print a concise round-by-round trace."""
    app = CloudDApplication()
    print("Cloud-D console simulation · synthetic cloud · no live resources")
    while not app.cloud.is_game_over():
        state = app.simulate_round()
        round_number = state["round"]
        print(f"\n{'=' * 58}\nROUND {round_number}/{state['max_rounds']}\n{'=' * 58}")
        round_events = [event for event in state["events"] if event["round"] == round_number]
        for event in round_events:
            print(f"  {event['message']}")
        if delay:
            time.sleep(delay)

    report = app.cloud.final_report()
    print("\nFINAL REPORT")
    for key, value in report.items():
        if key != "node_health":
            print(f"  {key:20} {value}")
    metrics_path, chart_path = write_results(report)
    print(f"\nMetrics saved to {metrics_path}")
    print(f"Node-health chart saved to {chart_path}")
    app.close()
    return report


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the local Cloud-D simulation.")
    parser.add_argument("--console", action="store_true", help="Run the simulation in the terminal and save results.")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically.")
    parser.add_argument("--host", default="127.0.0.1", help="Interface to bind (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8765")), help="HTTP port (defaults to PORT or 8765).")
    parser.add_argument("--delay", type=float, default=0.0, help="Seconds to pause between console rounds.")
    args = parser.parse_args(argv)

    if args.delay < 0:
        parser.error("--delay must be zero or greater.")
    if args.console:
        run_console(args.delay)
        return

    server_args = ["--host", args.host, "--port", str(args.port)]
    if args.no_browser:
        server_args.append("--no-browser")
    run_server(server_args)


if __name__ == "__main__":
    main()
