# Grafana dashboard for prompt-shield

Ready-to-import Grafana dashboard for [prompt-shield](https://github.com/mthamil107/prompt-shield)'s Prometheus `/metrics` endpoint. Visualizes scan volume, block rate, per-detector fire rates, latency percentiles, and input-size distributions.

## Contents

- [`prompt-shield-dashboard.json`](prompt-shield-dashboard.json) — Grafana dashboard export (schema version 39, works with Grafana 10.x and above)

## Prerequisites

1. A running prompt-shield instance with observability enabled:
   ```python
   from prompt_shield.observability import PromptShieldMetrics
   metrics = PromptShieldMetrics()
   ```
2. HTTP handler exposing `/metrics` (typically via FastAPI middleware or a plain WSGI/ASGI wrapper — see `prompt_shield/observability/__init__.py`).
3. Prometheus scraping the `/metrics` endpoint at a reasonable interval (30s is fine).
4. Grafana ≥ 10.x with your Prometheus data source configured.

## Import into your Grafana

1. Grafana UI → **Dashboards → New → Import**
2. Upload `prompt-shield-dashboard.json` (or paste its content into the JSON field)
3. When prompted, select your **Prometheus** data source and click **Import**

The dashboard is variable-driven — the `${datasource}` template variable at the top of the dashboard lets you switch between multiple Prometheus data sources without editing panels.

## Panels

| Row | Panels |
|---|---|
| **Overview** | Scans/sec · Block rate · Scan latency p50 · Detections/sec |
| **Actions** | Scans-by-action time series · Action distribution (donut) |
| **Detectors** | Top-20 detectors by detection count · Detections by severity |
| **Latency** | Percentile time series (p50/p95/p99) · Latency heatmap |
| **Input size** | Char-size heatmap · Token-size heatmap |

## Prometheus metrics visualized

The dashboard queries these metrics (all exposed by `PromptShieldMetrics`):

- `prompt_shield_scans_total` (counter, label: `action ∈ {block, flag, log, pass}`)
- `prompt_shield_detections_total` (counter, labels: `detector_id`, `severity`)
- `prompt_shield_scan_duration_seconds_bucket` (histogram)
- `prompt_shield_scan_input_size_chars_bucket` (histogram)
- `prompt_shield_scan_input_size_tokens_bucket` (histogram)

If your metrics have a different prefix, use the "Find and replace" feature in Grafana's dashboard settings to rewrite the queries in bulk.

## Publishing to grafana.com

To share this dashboard on [grafana.com's public dashboard library](https://grafana.com/grafana/dashboards/):

1. Log into [grafana.com](https://grafana.com/) with a free account
2. Go to **Dashboards → New dashboard**
3. Upload `prompt-shield-dashboard.json`
4. Add title (already set: "prompt-shield — LLM prompt-injection firewall"), description, tags
5. Click **Publish** — your dashboard gets a `grafana.com/grafana/dashboards/<id>` URL

Once published, users can import it in their Grafana instance with a single-line dashboard ID instead of downloading the JSON.

## Alerting suggestions

The dashboard doesn't ship alert rules by default (alerting policy is highly opinionated). If you want to alert:

| Condition | Suggested threshold | Severity |
|---|---|---|
| `sum(rate(prompt_shield_scans_total{action="block"}[5m])) / sum(rate(prompt_shield_scans_total[5m])) > 0.20` | Block rate above 20% for 10 min | Warning (probable attack campaign) |
| `histogram_quantile(0.95, sum by (le) (rate(prompt_shield_scan_duration_seconds_bucket[5m]))) > 0.5` | p95 latency > 500ms for 10 min | Warning (perf regression) |
| `sum(rate(prompt_shield_scans_total{action="block"}[5m])) > 100` | > 100 blocks/sec | Critical (large attack) |
| `absent(prompt_shield_scans_total)` | No scans reported for 5 min | Critical (scraping broken) |

## Feedback

If you deploy this, please open an issue with what you'd add/change: https://github.com/mthamil107/prompt-shield/issues
