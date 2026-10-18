# Cloud-D local cloud simulation

Cloud-D is a self-contained educational project: a Python simulation engine, local web dashboard, simulated cloud storage, attacker and defender agents, decision engine, and downloadable reports. It uses Python’s standard library only; no package installation is needed.

## Start Cloud-D

**macOS:** Open this `outputs` folder and double-click **Start Cloud-D.command**. A Terminal window starts the local engine and opens the dashboard. Keep Terminal open while using the app; press **Ctrl+C** there to stop it. If macOS blocks the first launch, Control-click the command file, choose **Open**, then confirm **Open**.

**Windows:** Double-click **Start-Cloud-D-Windows.bat**. Keep its console window open while using the dashboard.

Do not open `index.html` directly. The browser page needs the local Python engine for uploads, downloads, and simulation actions.

Python 3.10 or newer is required. The launcher checks for Python and prints a clear message if it is missing. This project has no third-party dependencies.

## Start from a terminal

```bash
cd outputs
python3 -m cloud_d.main
```

The launcher opens `http://127.0.0.1:8765/`. If the browser does not open automatically, visit that address after starting the engine. `python3 run_cloud_d.py` is also supported from this folder. `python3 -m cloud_d.main --console` runs the full attacker/defender exercise in the terminal and writes `cloud_d/results/metrics.csv` plus `cloud_d/results/charts/node_health.svg`.

## Deploy with GitHub and Render

The `render.yaml` file configures a Python web service, health check, and a required secret access password. Create a Blueprint from the repository’s root `render.yaml`. Render prompts for `CLOUD_D_ACCESS_PASSWORD`; set a strong password of at least 16 characters and keep it out of GitHub. The deployed dashboard asks for this password before it reads state, runs simulations, uploads, or downloads files. This deployment was created from the public repository URL; automatic deploys after future GitHub pushes require connecting the GitHub provider to Render, or you can trigger a manual deploy in Render.

The Blueprint uses Render’s free service plan. Free services can sleep after inactivity, and their local filesystem is temporary; this prototype keeps uploads in process memory, so uploads and simulation state can reset when the service sleeps, restarts, or redeploys. Durable online file storage needs a persistent storage service and is not configured here. The deployed site is a protected student demo, not a production cloud security service.

## Load your own sample records

The **Cloud** page opens by default. Choose a destination node and upload any file type, including PDF, Word, text, spreadsheet, image, CSV, or JSON files. You can also use **Add documents** on an individual cloud node to target it directly, or drag files into the upload area. CSV and JSON files are modeled as records; other files are stored as opaque simulated documents that attackers can target. Download any uploaded file from the stored-files list. Uploads are limited to 10 MB total per upload and 10,000 structured data rows. You can append files or replace the selected node’s sample data. The other nodes remain intact.

Use **Security Overview** for the defense controls and security metrics, **Simulation** for the live agent network and attack/defense event stream, **Attack Simulation** for the threat lab controls, and **Defense Report** for the run summary.

In local mode, uploaded files are held in the local Python process’s memory. In hosted mode, the browser sends files to the Render service, where they are held in process memory for that session. The dashboard shows file names, counts, and opaque record IDs; downloads return the selected file to the authorized browser. Hosted uploads can be cleared when the service sleeps, restarts, or redeploys, so use sample data and avoid sensitive files. A new simulation run restarts node health while retaining uploaded files in the current running session.

## Simulation model

- Five nodes: Auth Server, API Gateway, Primary DB, Customer DB, and Backup Server.
- Four attackers: Credential-Bot, FloodSwarm, Injector-X, and GhostUser.
- Four defenders: AuthSentinel, FlowGuardian, QueryShield, and BehaviorWatch.
- Credential-Bot uses depth-two Minimax to choose a credential tactic against modeled defender replies. QueryShield uses Expectimax chance nodes to compare defenses against uncertain SQL parser outcomes.
- The Decision Engine ranks defender utility proposals and resolves qualifying actions against attacks in the round. Defenders also use cross-round attack signature counts as shared intelligence.
- A run is capped at 20 rounds and may end sooner if three cloud nodes reach zero health. The dashboard shows actual node damage and record compromise from the simulation. Reports can be printed or exported as JSON and CSV.

## Limits

This is a local educational simulation, not a live cloud defense system. It does not connect to infrastructure, inspect real traffic, train a machine-learning model, or change firewall rules. Minimax and Expectimax are simplified bounded search models. Uploaded files become local simulated cloud records; document contents are not parsed or displayed.
