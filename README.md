# QDS Network IDS

QDS is a passive, flow-based network intrusion detection system. It turns
packet traffic into flow metadata, evaluates the flow with rules and a model,
and presents detection evidence through an API and web console. It is designed
to avoid long-term packet retention: captures are bounded and packets are
truncated before feature extraction.

## Repository layout

- `app/` — FastAPI service, sensor client, detection pipeline, and UI-facing
  API.
- `app/module1_aggregator/` — packet parsing and flow-feature aggregation.
- `app/module2_detector/` — inference and rule evaluation code.
- `app/module3_explainer/` — verdict and explanation generation.
- `app/module4_orchestrator/` — pipeline coordination.
- `native_worker/` — optional Vulkan-accelerated worker.
- `web/` — browser dashboard.
- `models_training/` — reproducible training and ONNX conversion scripts.

## Privacy and Git hygiene

This repository intentionally excludes local datasets, packet captures, model
artifacts, runtime databases, virtual environments, and `.env` files. Keep
those materials on approved storage only. The tracked `.env.example` is a
template with placeholders; never replace its values with live credentials.

After cloning, create your local configuration:

```sh
copy .env.example .env
```

On macOS or Linux, use `cp .env.example .env` instead. Fill in `.env` with
unique local secrets before starting the stack.

## Local production stack

1. Copy `.env.example` to `.env`, replace every value with a unique secret, and
   do not commit it.
2. Run `docker compose up --build`.
3. Sign in at `http://localhost:8080` using `admin` and the configured bootstrap
   password. The API is at `http://localhost:8000`.
4. For AI explanations, wait for the Ollama service, then run
   `docker compose exec ollama ollama pull qwen2.5:3b` once. The dashboard's AI
   status will turn ready after the model is installed.
5. For Windows live capture, open an Administrator PowerShell in this folder
   and run `./Start-Live-Capture.ps1`; then use **Go live** in the dashboard.
   Captures are limited to a 64 MB circular buffer and packets are truncated
   to 128 bytes before flow extraction. Stop the capture in the dashboard to
   analyze and ingest its flows.
6. Register another sensor by sending its heartbeat with `X-Sensor-Token`, then
   run `python -m app.sensor --interface <interface> --api <api-url> --sensor-id <id>`.

Linux capture requires libpcap and `pcapy-ng`, with `CAP_NET_RAW` and
`CAP_NET_ADMIN` rather than a fully privileged container. Windows capture
requires Npcap in WinPcap-compatible mode and an elevated sensor service.

## Operations

- `/healthz` is a process liveness endpoint; `/readyz` verifies database/model
  readiness; `/metrics` is Prometheus-compatible.
- Back up the `qds-postgres` volume before upgrades. Redis is a transient
  enrichment queue; alerts are committed before they are enqueued.
- Rotate `QDS_SENSOR_TOKEN`, JWT secret, and bootstrap credentials before any
  exposure beyond a trusted network. Put TLS and a reverse proxy in front of the
  dashboard/API.
- Set a database retention job appropriate for your organization before launch.
  Raw uploaded PCAPs are deleted immediately after parsing.

## Model governance

`app/module2_detector/model_manifest.json` binds the runtime to feature order,
artifact checksum, labels, and provenance. The bundled legacy model is not a
production promotion: retrain on a time-separated, held-out dataset and update
the manifest with evaluation metrics before deployment.

## Release gates

Do not promote this code to a monitored production network until a qualified
operator has: replaced every example secret; deployed TLS; confirmed database
backup/restore; replayed representative PCAPs; load-tested the intended sensor
hardware below 100 Mbps; and approved a newly trained model package. GPU mode
must stay disabled until its output parity with CPU feature extraction is proven.
