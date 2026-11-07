# Clone, dependencies and startup

The source repository includes dependency manifests and installers. Downloaded
packages, credentials, compiled binaries and historical lab output stay outside
Git. A clone contains the code and reusable fixtures; it does not contain the
Running/Candidate state, accounts, CA private keys, trained models or additional
ET rules installed on a particular appliance.

## Development on Windows or Linux

Install Git, Go 1.22+, Node.js 22+ with npm, and Python 3.10+. Python 3.11 or
3.12 is recommended if you also need the existing experimental ML requirements.
Internet access to the Go module proxy, npm registry and (for Python options)
PyPI is required for the first setup.

On Ubuntu, Python virtual environments also need the `python3-venv` package
(`sudo apt-get install python3-venv`) when using either Python dependency option.

```sh
git clone https://github.com/huyvinh0605/NGFW.git
cd NGFW
python scripts/bootstrap-dev.py
```

On Ubuntu use `python3` if `python` is not available. The script downloads Go
modules using `go.mod/go.sum` and runs `npm ci` using `web/package-lock.json`.
It checks toolchain versions first; it does not install Go/Node/Python itself.
Rerun it after changing branches or updating manifests.

For the Python lab controller dependencies:

```sh
python scripts/bootstrap-dev.py --with-lab-tools
```

This creates `.venv` and installs the pinned direct dependencies in
`tests/integration/requirements.txt`; pip resolves their transitive packages.
Use `.venv\Scripts\python.exe` on Windows or `.venv/bin/python` on Linux for
the runners. Installing these packages does not connect to a VM or run traffic.
The manifests currently pin Requests and Paramiko from their official
[Requests](https://pypi.org/project/requests/2.34.2/) and
[Paramiko](https://pypi.org/project/paramiko/5.1.0/) releases.

The optional `--with-ml` flag installs `ml/service/requirements.txt` into the
same virtual environment. That directory is experimental: installing packages
does not train a model, enable Risk/ML, or add ML protection to M1–M4.

Verify the source:

```sh
go test -count=1 ./...
go vet ./...
cd web
npm test
npm run build
```

Start the development API in one terminal (PowerShell example):

```powershell
$env:NGFW_API_TOKEN = "choose-a-local-development-token"
$env:NGFW_STATE_DIR = ".\state"
go run .\cmd\ngfw-api
```

In another terminal run `cd web` then `npm run dev` and open
`http://127.0.0.1:5173`. For a POSIX shell, use `export NGFW_API_TOKEN=...` and
`export NGFW_STATE_DIR=./state` before `go run ./cmd/ngfw-api`. The development
API/UI can be used without Linux dataplane privileges; runtime session,
Commit/Rollback and enforcement need the Linux engine.

## Ubuntu 24.04 appliance

The appliance installer downloads Ubuntu packages and Go modules, runs Go
tests, builds the engine/API, and installs their systemd units. It needs root.
For M3 it also installs the Suricata package and the repository's sensor assets:

```sh
sudo bash scripts/install-linux.sh --with-inspection
```

Review `/etc/ngfw/lab.json` and `/etc/ngfw/ngfw.env`, particularly interface
names, addressing, routes and management access, before enabling the services.
Then follow the [Ubuntu installation steps](../README.md#ubuntu-installation)
and the M3 preflight instructions. `--start` is an explicit service/network
activation step. Cloning or running `bootstrap-dev.py` never activates it.

The backend installer does not install Node/npm or start Vite. Prepare the UI
as a normal user with the development bootstrap command. On the Linux VM, run
this command from the repository root to start the UI in the background:

```sh
bash start-web.sh
```

The script finds `web/` relative to its own real path, so a home-directory
symlink also works, for example `~/start-web.sh`. It reuses Vite already
serving that checkout on port 5173 and refuses a port owned by another service.
It does not install dependencies, rebuild binaries, restart backend services,
or change Running/Candidate. New process logs are in
`~/.local/state/ngfw/web-5173/vite.log`. Set `NGFW_WEB_PORT` or `NGFW_WEB_HOST`
to override the default port or bind address.

Vite is a development server. The script keeps it running after SSH closes;
it does not configure automatic startup after reboot. The default `0.0.0.0`
exposes it on the VM's listening interfaces. Use the management network when
accessing it remotely, such as `http://192.168.100.1:5173` in this lab.

## M4 and lab-specific assets

M4 is installed separately with `scripts/install-m4-assets.sh`; it requires
the M1/M2 account, Suricata and `acl` prerequisites from the appliance setup.
Build the proxy explicitly:

```sh
go build -o /tmp/ngfw-proxy ./cmd/ngfw-proxy
sudo bash scripts/install-m4-assets.sh --proxy-binary /tmp/ngfw-proxy
```

Review [M4 CA provisioning](m4/CA_PROVISIONING.md) and
[M4 deployment](../tests/integration/m4/README.md#t29-deployment-and-evidence-collection)
before starting the proxy or enabling a selector. The dependency bootstrap
does not generate or copy a CA, change Running/Candidate, or enable M4.

The basic Suricata rule assets are tracked under `deploy/inspection/`. Extra
ET rules and runtime manifests installed during a lab exercise are not fetched
by the development bootstrap. Historical reports linking to `artifacts/`
require the separately retained evidence described below.

## Local run evidence

The entire `artifacts/` directory is ignored by Git, including reports,
screenshots, PCAPs, logs and temporary binaries. Existing local evidence is
retained; the source repository does not publish or delete it. Links from older
acceptance documents to run folders require a separate copy of those artifacts.

The development bootstrap creates a local `artifacts/go.mod` marker if missing.
This keeps generated Go clients and archived source overlays outside the main
`go test ./...` package scan. It preserves an existing marker and all run data;
the marker is also ignored by Git. Reusable test code and synthetic fixtures
belong in `tests/` or `scripts/`, rather than in a historical run folder.
