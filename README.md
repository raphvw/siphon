# Siphon

Siphon is a small, self-hosted file copier with a web UI. Add jobs that fetch a URL into a chosen destination path, run them on a schedule, and optionally filter text or XML content before replacing a file.

## Features

- Add, edit, remove, and run file jobs from the web UI.
- Set a schedule from 1 minute to 24 hours.
- Pass extra curl arguments per job as separate values (never through a shell).
- Add per-job text filters using substring or regular-expression matching.
- Add XML event filters by record element and field. Matching records are de-duplicated against the current destination.
- Keep named handlers in Python for future workflows that need custom logic.
- Require HTTP Basic authentication for the UI and API.

## Run locally

1. Copy `env.example` to `.env` and set a strong `SIPHON_PASSWORD` (and optional `SIPHON_USERNAME`).
2. Run `docker compose up --build`.
3. Open `http://localhost:27686` and sign in with the username and password from `.env`.

The app saves settings to `config/config.yaml`. It creates an empty configuration if the file does not exist. `config/config.example.yaml` shows the minimal structure.

## TrueNAS SCALE

1. Copy the project folder to `/mnt/apps/Siphon`.
2. Create `/mnt/apps/Siphon/config` and `/mnt/apps/Siphon/output` in the dataset.
3. Review `truenas-compose.yaml`, set a unique `SIPHON_USERNAME` and strong `SIPHON_PASSWORD`, and confirm the host path mounted at `/data` is where you want copied files to go.
4. Install it from **Apps → Discover → Custom App → Install via YAML**.

The YAML builds the image from `/mnt/apps/Siphon` and publishes the UI at host port `27686`. The default icon is the included `siphon.png`; set `SIPHON_ICON_URL` in the Compose environment to use a hosted icon instead. Keep the UI on a trusted network or behind Tailscale/reverse-proxy access controls.

For updates, preserve `/mnt/apps/Siphon/config/config.yaml` and the output data so UI-managed jobs and copied files remain intact. Update the app source and Compose YAML, then redeploy to build the new image.

## Filters

Every job has an **Add filter** control. **Match downloaded text** checks UTF-8 text or HTML up to 8 MiB and copies the file when any rule matches. **Match new XML records** checks attributes or child fields under a configured record element and only replaces the destination when a matching record has not already been saved. Rules combine as “any match.”

The Wurm camps example in `examples/wurm-camps.yaml` demonstrates the previous appearance, claim, and secure-victory rules. Existing `wurm_camps` job configurations migrate to the editable XML-filter format when read by the updated app.

Text filters are intended for text documents and HTML. Files without filters are copied every run. XML mode expects parseable XML.

## Configuration shape

```yaml
interval_minutes: 15
jobs:
  - id: sample
    name: Sample file
    source: https://example.org/status.txt
    destination: /data/status.txt
    args:
      - --max-time
      - "30"
```

Destinations must be under `ALLOWED_DEST_ROOTS` (set to `/data` in the Compose examples). Mount only the host directories the app needs.

## License

Siphon is released under the MIT License. See [LICENSE](LICENSE).
