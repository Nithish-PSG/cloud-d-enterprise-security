# Cloud-D: Remaining Work Handoff

**Prepared:** 2026-10-19  
**Purpose:** Give the next coding agent the project context, completed work, known limits, and the remaining roadmap. Continue in the existing repository; do not recreate the project from scratch.

## Project and repository

- Project: **Cloud-D**, an educational multi-agent cloud-security simulation.
- GitHub account: `Nithish-PSG`
- Repository: <https://github.com/Nithish-PSG/cloud-d-enterprise-security>
- Main branch: `main`
- Base commit when this handoff was written: `98fc2a8` (`Include project handoff document`).
- The working project is the repository root containing `index.html`, `cloud-d.js`, and `cloud_d/`.
- Existing hosted URL: <https://cloud-d-demo.onrender.com/>
- `render.yaml` deploys the Python service and has `autoDeploy: true`.

## User's intended product

Build a realistic-feeling **manual cloud simulation** in Python and a web UI. A user should be able to sign in, upload and download files in an assigned cloud area, and see attacker and defender agents act against simulated cloud nodes. This is an educational simulation, not a connection to a real AWS/Azure/GCP environment or a live traffic-defense product.

Customer accounts should use their own Customer DB area. Staff accounts should use the shared Primary DB area and staff-only security/simulation screens. A recovery database should help restore file data. Future Android and iPhone apps were explicitly deferred until the current project is finished.

## Already implemented

- Dashboard pages for **Cloud**, **Security Overview**, **Simulation/Agent Network**, **Attack Simulation/Threat Lab**, and **Defense Report**.
- Python simulation with five logical nodes, four attacker agents, four defender agents, and a decision engine.
- Credential-Bot uses depth-two Minimax; QueryShield uses Expectimax chance nodes; other behaviors use stochastic or utility heuristics.
- Simulation metrics, event history, node health, reports, and JSON/CSV export.
- Username/password login; role is looked up after login. Signup collects email, username, and password, then lets the new user select Customer or Staff. Staff signup requires a matching Staff Registration Code.
- A Show/Hide control on the login/signup password field.
- Role-assigned folder areas, folder creation, uploads/downloads, search/filter, version history, and a duplicate-file popup with **Update** (keep a new version) or **Replace** (discard old versions).
- SQLite primary and recovery databases. Uploaded file contents are encrypted with AES-256-GCM before storage. Passwords are salted and hashed with scrypt; sessions are stored as token hashes.
- Local recovery copies for account/folder/file metadata and encrypted file blobs. The README describes startup recovery and current limits.
- macOS background-service installer sources and a Windows batch launcher. The macOS service starts at login after the one-time installer setup. The Windows launcher still requires the user to start the `.bat` file and keep its window open.
- GitHub and Render configuration. The app source and the Windows handoff document were pushed to the existing `main` branch.

Main files to read first: `README.md`, `index.html`, `cloud-d.js`, `cloud_d/server.py`, `cloud_d/application.py`, `cloud_d/storage.py`, `cloud_d/cloud/enterprise_cloud.py`, and `render.yaml`.

## Remaining work and gaps

### A. Explicitly deferred: Android and iPhone apps

No native or packaged mobile app has been built. The user said to do this later, after finishing the current work. First stabilize the backend and decide whether the mobile client will be a responsive web app/PWA, React Native, or another approach; do not begin a native rewrite without checking with the user.

### B. Durable hosted storage

The current Render Free deployment stores SQLite databases and the encryption key on the service's local filesystem. That filesystem is temporary and can be replaced, losing both the primary and recovery copies. The recovery DB is on the same host, so it is not an offsite backup.

Before treating hosted accounts as durable, select and configure persistent storage (for example, managed PostgreSQL plus object storage, or a supported persistent disk), define migrations, and keep a stable encryption key in a secret manager. Design and verify backup/restore across host replacement. Do not move existing user data or change the database schema destructively without a migration and backup plan.

### C. Clarify logical versus physical database nodes

Customer DB, Primary DB, Auth Server, API Gateway, and Backup Server are represented by the simulation/UI and role-based storage routing. The app is still one Python service backed by SQLite; these are not independent database servers or microservices. The recovery database is a separate SQLite file, but it shares the same machine/storage fate in the hosted deployment.

If the project only needs to demonstrate nodes, keep the logical simulation and explain it accurately. If the user expects independently running services, agree on that scope before splitting the app and define APIs, deployment, authentication, and recovery between services.

### D. Decide whether encryption must cover the whole database

AES-256-GCM currently protects uploaded file contents. SQLite account, folder, and other metadata is not encrypted as a complete database. The key is kept separately and must remain stable to decrypt stored files. Confirm what “encrypt the database nodes” means for the project. If whole-database encryption is required, compare SQLCipher or application-level field encryption and document what remains visible; do not imply the current build encrypts every database field.

### E. Verify hosted configuration and deployment behavior

- Check Render's latest deployment/build and health endpoint after source changes.
- Verify `CLOUD_D_STAFF_REGISTRATION_CODE` is configured in Render's environment settings. Its value must never be committed or put in the handoff. `render.yaml` marks it `sync: false`, so it needs a dashboard value.
- Confirm staff signup, customer signup, login, uploads, downloads, duplicate handling, and session behavior on the hosted service.
- Keep in mind that a document-only Git push may still trigger Render because auto-deploy is enabled.
- The current public-facing hostname contains `demo`; changing the Render service URL requires a service/domain change and is separate from editing the repository name.

### F. Windows startup experience

`Start-Cloud-D-Windows.bat` prepares a virtual environment and launches the server, but the terminal window must remain open. A background Windows service or login-start task and a simple user-facing installer have not been implemented. The macOS setup is ahead of the Windows setup; do not describe both as fully automatic yet.

### G. Automated validation and reproducible evaluation

There is no test suite in the repository. Add and run focused unit/integration tests for signup and login, role separation, folder access, upload/download, duplicate Update/Replace, encrypted recovery and restore, and simulation decisions/report metrics. Also test startup on macOS and Windows and the Render health endpoint. Preserve user data during migration tests.

The abstract originally quoted particular block/protection percentages. Treat those as simulation results only; make each result reproducible, record the run configuration/seed, and ensure reports do not present simulated metrics as real-world security guarantees. The README correctly states that this is an educational simulation and does not inspect real traffic, train a model, or change real firewalls.

### H. Production authentication and operations (recommended if this becomes a real service)

The current username/password and staff-code flow is adequate for a classroom simulation, not a hardened identity service. If real users or sensitive documents are ever involved, plan email verification, password reset, login throttling/lockout, MFA, secure cookie/HTTPS review, staff-code rotation, audit logging, and account-management procedures. This is a recommended production-hardening list, not a claim that the user has already requested every item.

### I. Review project identity before further public sharing

The report section in `index.html` contains the author's name and student ID. Before making additional public copies or screenshots, confirm the repository's visibility and whether that identifying text should remain. Do not add credentials, staff codes, `.env` files, SQLite databases, or `encryption.key` to GitHub; `.gitignore` excludes the main local data and secret paths.

## Suggested order for the next agent

1. Read the files listed above and inspect the current Git status before editing. Preserve the existing implementation and user data.
2. Check the live Render deployment and required environment variables; report any deployment limitation plainly.
3. Add automated tests for the existing local simulation and storage/auth flows, then fix defects those tests reveal.
4. Ask the user to choose the storage target for durable hosted data before changing the live persistence architecture.
5. Confirm whether whole-database encryption and physically separate services are project requirements or conceptual nodes only.
6. Improve Windows launch/install behavior if cross-platform desktop use is still a priority.
7. Start Android/iPhone work only after the user returns to the mobile-app goal.

## Copy-ready instruction for the next agent

Continue the existing Cloud-D project in the GitHub repository above. Read this handoff and `README.md` first; do not rebuild the app from scratch. The current app already includes authentication, role-specific simulated cloud folders, encrypted file uploads, versions, recovery, attacker/defender simulation, and GitHub/Render configuration. Work through the remaining items in the suggested order. Be clear that Cloud-D is currently an educational simulation, file contents (not all SQLite metadata) are encrypted, and Render's local filesystem is temporary. Keep secrets and local databases out of Git. Ask before making destructive data migrations, changing hosting ownership, or starting the deferred mobile-app rewrite. Report what you changed and what you verified.
