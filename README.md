# Cloud-D multi-agent cloud security simulation

Cloud-D is an educational project with a Python API service, a web dashboard, a simulated cloud, four attacker agents, four defender agents, and SQLite storage. The API is the single entry point for login, folder and file operations, and staff simulation controls; it routes each account to its assigned storage area.

## Start Cloud-D

**macOS:** Double-click **Cloud-D.app** once to install the background service. It starts automatically at login and keeps running without a Terminal window. After setup, opening `index.html` automatically routes to the local dashboard. The first setup copies a runtime into `~/Library/Application Support/Cloud-D`, prepares a private Python environment, and installs the required package. Rebuild and reopen the app after changing project code so its runtime copy is refreshed. To remove automatic startup, delete `~/Library/LaunchAgents/edu.psgtech.cloudd.plist` and restart the Mac.

**Windows:** Double-click **Start-Cloud-D-Windows.bat**. The first launch prepares a private Python environment and installs the required package. The browser opens automatically; keep the starter window open while using Cloud-D.

Uploads, downloads, database operations, and simulations need the local Python service. Python 3.10 or newer is required. On macOS, the project includes **Build-Cloud-D-Mac-App.command** to recreate the one-time installer app if needed.

To start from a terminal after launcher setup:

```bash
.venv/bin/python -m cloud_d.main
```

On Windows, use `.venv\Scripts\python.exe -m cloud_d.main`.

## Accounts and access

Sign in with the username and password saved on the account; Cloud-D reads the registered role automatically. New users follow the **Create an account** link below the sign-in form, then provide an email address, a unique username, and password before choosing **Customer** or **Staff**. Email is collected during account creation; the username is the sign-in ID and is shown as the account name. Usernames are case-insensitive and must be 3–30 characters using letters, numbers, dots, underscores, or hyphens. Passwords are salted and hashed with scrypt; the app stores a hash of the session token and expires sessions after 12 hours. Signing out revokes the current session.

On first launch after this update, existing accounts receive a username based on the part of their saved email before `@` (with a numeric suffix if needed to make it unique). That username is shown beside the account role after sign-in. The primary and recovery databases are migrated together, so existing accounts and files remain available.

Staff signup requires a valid **Staff Registration Code**. On macOS, the first-time installer generates a private local code, displays it once, and stores it in `~/.cloud-d/staff-registration-code`. Configure `CLOUD_D_STAFF_REGISTRATION_CODE` on hosted services. Missing or incorrect codes are rejected immediately, and no account or pending request is created. Existing deployments can temporarily keep using the legacy `CLOUD_D_STAFF_INVITE_CODE` or `CLOUD_D_ACCESS_PASSWORD` setting; both are checked as registration codes for compatibility.

The account role determines the hidden storage destination:

- **Customer** accounts use their private folders in the simulated **Customer DB**.
- **Staff** accounts use shared operator folders in the simulated **Primary DB**. Security overview, agent simulation, threat lab, and reports are staff-only.

Users can select an existing folder or create one. They cannot select another account’s storage area. Customer files are private to that customer account; staff files are shared with staff operators.

## Storage, encryption, versions, and recovery

Cloud-D keeps a primary SQLite database and a separate SQLite recovery database. Both contain account, folder, and node metadata; file contents are encrypted with **AES-256-GCM** before the encrypted blobs are saved. The rest of the SQLite metadata is not encrypted as a whole database. Passwords are stored as salted scrypt hashes, not plaintext. The app decrypts an authorized file inside the Python service when preparing a download.

By default, the local data folder is:

- macOS/Linux: `~/.cloud-d/`
- Windows: `%USERPROFILE%\.cloud-d\`

It contains `cloud-d.sqlite3`, `cloud-d-backup.sqlite3`, and `encryption.key`. Keep all three together when backing up or moving local Cloud-D data. The key is created automatically and restricted to the current user where supported. If the key is lost, encrypted file contents cannot be recovered; Cloud-D will not silently generate a replacement for an existing database. Do not commit any of these files or secrets to GitHub.

Set `CLOUD_D_DATA_DIR` to use a different data folder. Alternatively, `CLOUD_D_ENCRYPTION_KEY` can hold a URL-safe base64 encoding of exactly 32 random bytes. Keep that secret stable for as long as the database is needed; it takes precedence over `encryption.key`.

Every upload is written to the account’s assigned primary area and mirrored as an encrypted file copy into the recovery database. The **Restore** action appears if a current primary copy is missing while its recovery copy remains available. If the primary SQLite file is replaced or lost while the backup database and key remain intact, Cloud-D rebuilds the primary file from the recovery copy on startup. Simulation state and active login sessions are not backed up.

Staff can use the **Cryptographic demonstration** controls in the Cloud page to verify and authenticate encrypted primary-node copies or re-encrypt them with fresh AES-GCM ciphertext. Verification happens inside the Python service; plaintext is not sent to the browser. This demonstrates file-content confidentiality and integrity while keeping the deployment intentionally suitable for classroom demonstrations.

When a filename already exists in the same folder, a popup offers **Update** or **Replace**. **Update** saves a new numbered version and keeps its history. **Replace** overwrites the file and removes its earlier versions. UTC timestamps are stored with revisions. Use **Versions** to inspect or download an earlier revision. A simulation reset preserves uploaded files and version history.

The app parses CSV, JSON, JSON Lines, and NDJSON into simulated records. Other file types are stored as encrypted opaque documents. Uploads are limited to 10 MB total per request and 10,000 structured rows. The dashboard shows filenames and metadata, not document contents.

## Dashboard and simulation

The **Cloud** page is the default page. Upload files into folders, search or filter the file list, download or restore files, and view saved versions. The **Security Overview** shows defenses and metrics. **Simulation** shows the agent network and event stream. **Attack Simulation** contains the threat lab controls. **Defense Report** summarizes a run.

The simulated cloud has five nodes: Auth Server, API Gateway, Primary DB, Customer DB, and Backup Server. Four attacker agents—Credential-Bot, FloodSwarm, Injector-X, and GhostUser—face AuthSentinel, FlowGuardian, QueryShield, and BehaviorWatch. Credential-Bot uses depth-two Minimax; QueryShield uses Expectimax chance nodes. The Decision Engine ranks defender utility proposals and resolves qualifying actions. Runs process up to 20 rounds and may end earlier if three nodes reach zero health. Reports can be printed or exported as JSON and CSV.

## GitHub and Render

`render.yaml` configures the Python service and health check. Set `CLOUD_D_STAFF_REGISTRATION_CODE` in Render’s environment settings to a secret of at least 16 characters. Legacy `CLOUD_D_STAFF_INVITE_CODE` and `CLOUD_D_ACCESS_PASSWORD` values are also accepted during migration. Email is collected at signup; all accounts sign in with a username and password.

The current Render Free service uses a temporary filesystem. The primary database, recovery database, and generated encryption key can all be lost when its instance is replaced. A recovery database on that same temporary filesystem is useful for demonstrating restore behavior, but it is not an offsite or durable backup. Durable hosted storage needs persistent storage and a separately protected, stable encryption key.

## Limits

Cloud-D is an educational simulation, not a production identity service or live cloud defense system. It does not connect to infrastructure, inspect real traffic, train a machine-learning model, or change firewall rules. Minimax and Expectimax are simplified bounded search models. Use production identity, authorization, storage, and backup services before handling real customer data.
