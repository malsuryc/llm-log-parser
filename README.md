# LLM Log Parser & Incident Tagger

Two small AI-powered tools in one repo:
- Sliding Window Log Analyzer for cluster/system logs
- Incident Tagger that labels ServiceNow incidents by category

## Quick Start

1) Prepare environment variables (OpenAI-compatible endpoint):

```bash
cp .env.example .env
# Edit .env and set at least:
# OPENAI_API_URL=http://<your-openai-compatible-endpoint>/v1
# OPENAI_API_KEY=your-api-key-or-dummy
```

2) Run either tool:

- Log analysis (sliding window):
```bash
python src/main.py
```

- Incident tagging (reads formatted-incidents.json, writes enriched-incidents.json):
```bash
python src/tag_incidents.py --model "gpt-oss 120b"
```

---

## Incident Tagger (ServiceNow) 🏷️

Script: `src/tag_incidents.py`

Purpose: Tag each incident (from `formatted-incidents.json`) with one category and write results to `enriched-incidents.json`.

### Categories

- infrastructure: some incident with our infrastructure, or suspected so
- account: request for approving account, create account
- operation: adding members, transferring data, increase storage etc
- billing: anything related to $
- internal: <reserved>
- node-contrib: user want to buy their own node
- advanced: support case requiring significant efforts to support, e.g. installing software

If nothing matches, the tag is left empty.

### Input and Output

- Input: `formatted-incidents.json` with an `incidents` array (each item may contain fields like `number`, `short_description`, `description`, `caller`, `department`, `state`).
- Output: `enriched-incidents.json` (same structure) with extra fields per incident:
   - `ai_tag`: one of the categories above or empty string
   - `ai_confidence`: 0..1 (when provided by the model)
   - `ai_rationale`: short reason (when provided)

Example output snippet:

```json
{
   "incidents": [
      {
         "number": "INC0201963",
         "short_description": "[HPC4] Rebooting of computing node - ocean3",
         "ai_tag": "infrastructure",
         "ai_confidence": 0.92,
         "ai_rationale": "Node reboot and site-wide issue suggests infra"
      }
   ]
}
```

### Usage

```bash
python src/tag_incidents.py \
   --input formatted-incidents.json \
   --output enriched-incidents.json \
   --batch-size 20 \
   --model "gpt-oss 120b"
```

Notes:
- Uses your OpenAI-compatible endpoint from `OPENAI_API_URL` and `OPENAI_API_KEY`.
- Default files: `--input formatted-incidents.json`, `--output enriched-incidents.json`.
- Tags are validated to the allowed set; unknowns become empty.
- Processes incidents in batches (default 20) to reduce prompt size.

---

## Sliding Window Log Analyzer 🧪

Script: `src/main.py`

Purpose: Analyze large logs via overlapping windows, deduplicate issues, and group similar ones with AI.

### How it works

- Reads your log defined by `LOG_FILE_PATH` in `.env`.
- Processes windows with overlap controlled by `WINDOW_SIZE` and `STEP_SIZE`.
- Sends each window to the model (code uses `Qwen-32B`).
- Merges and deduplicates issues across windows.
- Optionally groups issues by similarity.

### Run

```bash
python src/main.py
```

### Output

Files saved under `output/` with timestamps, including:
- `log_analysis_YYYYMMDD_HHMMSS.yaml` — full window-by-window and merged issues
- `grouped_analysis_YYYYMMDD_HHMMSS.log` — readable grouped summary

---

## Configuration

Environment variables (set in `.env`):

- Common
   - `OPENAI_API_URL` — OpenAI-compatible base URL (required)
   - `OPENAI_API_KEY` — API key (dummy is fine for local models)

- Log analyzer
   - `LOG_FILE_PATH` — path to the log file to analyze
   - `WINDOW_SIZE` — lines per window (default: 100)
   - `STEP_SIZE` — step size between windows (default: 90)
   - `MAX_WINDOWS` — max windows to process (empty = no limit)
   - `DELAY_SECONDS` — delay between API calls (default: 2)
   - `START_LINE` — first line to start from (default: 1)

Model notes:
- Incident Tagger default model: `gpt-oss 120b` (override with `--model`).
- Log Analyzer model: `Qwen-32B` (configured in code).

---

## Development

Optional helper commands (if you use `tox`):

```bash
tox -e format      # format with black + isort
tox -e mypy        # type-check
tox -e lint        # lint with pylint
tox                # run tests (if present)
```

## License

MIT
