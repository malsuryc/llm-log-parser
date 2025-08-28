import os
import json
import argparse
import textwrap
from typing import List, Dict, Any

from dotenv import load_dotenv
from openai import OpenAI


ALLOWED_TAGS = [
    "infrastructure",  # some incident with our infrastructure, or suspected so
    "account",          # request for approving account, create account
    "operation",        # adding members, transferring data, increase storage etc
    "billing",          # anything related to $
    "internal",         # <reserved>
    "node-contrib",     # user wants to buy their own node
    "advanced",         # support requiring significant efforts, e.g. installing software
]


def _truncate(text: str, limit: int = 800) -> str:
    if not text:
        return ""
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def build_prompt(batch_items: List[Dict[str, Any]]) -> str:
    rules = textwrap.dedent(
        f"""
        You are an incident triage assistant. Tag each incident with ONE of the following labels (or an empty string if none apply):
        - infrastructure: some incident with our infrastructure, or suspected so
        - account: request for approving account, create account
        - operation: adding members, transferring data, increase storage etc
        - billing: anything related to $
        - internal: <reserved>
        - node-contrib: user want to buy their own node
        - advanced: support case requiring significant efforts to support, e.g. installing software

        If nothing matches, leave the tag as an empty string "".

        Output STRICT JSON only, no prose, with this shape:
        {{
          "results": [
            {{
              "number": "INCxxxxx",
              "tag": "infrastructure|account|operation|billing|internal|node-contrib|advanced|",
              "confidence": 0.0_to_1.0,
              "rationale": "<=200 chars why this tag fits"
            }}
          ]
        }}
        """
    ).strip()

    cases = [
        {
            "number": it.get("number"),
            "short_description": _truncate(it.get("short_description", ""), 280),
            "description": _truncate(it.get("description", ""), 1000),
            "caller": it.get("caller", ""),
            "department": it.get("department", ""),
            "state": it.get("state", ""),
        }
        for it in batch_items
    ]

    return (
        rules
        + "\n\nIncidents to tag (JSON):\n" 
        + json.dumps({"incidents": cases}, ensure_ascii=False)
    )


def call_ai(client: OpenAI, prompt: str, model: str) -> Dict[str, Any]:
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=4096,
    )
    content = resp.choices[0].message.content or ""

    # Extract JSON if wrapped in fences
    txt = content.strip()
    if "```" in txt:
        start = txt.find("```")
        # Try to find second fence
        end = txt.find("```", start + 3)
        if end != -1:
            txt = txt[start + 3 : end].strip()
            # Remove optional language token like json
            if txt.startswith("json\n"):
                txt = txt[5:]
            elif txt.startswith("yaml\n"):
                txt = txt[5:]

    try:
        data = json.loads(txt)
        if isinstance(data, dict) and "results" in data:
            return data
    except Exception:
        pass

    # Fallback to empty results on parse failure
    return {"results": []}


def validate_tag(tag: str) -> str:
    if not tag:
        return ""
    tag = tag.strip().lower()
    return tag if tag in ALLOWED_TAGS else ""


def enrich_incidents(incidents: List[Dict[str, Any]], ai_results: Dict[str, Dict[str, Any]]):
    for inc in incidents:
        number = inc.get("number")
        res = ai_results.get(number)
        if res:
            inc["ai_tag"] = validate_tag(res.get("tag", ""))
            if "confidence" in res:
                inc["ai_confidence"] = res.get("confidence")
            if "rationale" in res:
                inc["ai_rationale"] = res.get("rationale")
        else:
            inc.setdefault("ai_tag", "")


def batch(iterable: List[Any], size: int) -> List[List[Any]]:
    return [iterable[i : i + size] for i in range(0, len(iterable), size)]


def main():
    parser = argparse.ArgumentParser(description="AI tag incidents from a JSON file.")
    parser.add_argument("--input", default="formatted-incidents.json", help="Path to input incidents JSON")
    parser.add_argument("--output", default="enriched-incidents.json", help="Path to write enriched JSON")
    parser.add_argument("--batch-size", type=int, default=20, help="Incidents per AI request")
    parser.add_argument("--model", default="gpt-oss 120b", help="Model name to use")
    args = parser.parse_args()

    load_dotenv()

    api_url = os.getenv("OPENAI_API_URL")
    api_key = os.getenv("OPENAI_API_KEY", "dummy-key")

    if not api_url:
        raise SystemExit("OPENAI_API_URL is required in environment")

    # Read incidents
    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    incidents = data.get("incidents") if isinstance(data, dict) else data
    if not isinstance(incidents, list):
        raise SystemExit("Input JSON must contain an 'incidents' array or be a list of incidents")

    client = OpenAI(base_url=api_url, api_key=api_key)

    # Collect AI results keyed by incident number
    results_by_number: Dict[str, Dict[str, Any]] = {}

    for i, chunk in enumerate(batch(incidents, args.batch_size), start=1):
        prompt = build_prompt(chunk)
        ai_out = call_ai(client, prompt, args.model)
        for item in ai_out.get("results", []):
            number = item.get("number")
            if number:
                item["tag"] = validate_tag(item.get("tag", ""))
                results_by_number[number] = item

    # Enrich and write
    enrich_incidents(incidents, results_by_number)

    out = data if isinstance(data, dict) else {"incidents": incidents}
    if isinstance(out, dict):
        out["incidents"] = incidents

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    print(f"Tagged {len(results_by_number)} incidents -> {args.output}")


if __name__ == "__main__":
    main()
