import csv
import io
import json


def read_uploaded_file(file) -> str:
    """Read an uploaded file and return its contents as a string.

    Handles .log, .txt, .json, and .csv formats.
    """
    raw = file.read()
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")

    if not raw.strip():
        return ""

    name = getattr(file, "name", "")

    if name.endswith(".json"):
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return "\n".join(json.dumps(entry) for entry in data)
            return json.dumps(data)
        except json.JSONDecodeError:
            return raw

    if name.endswith(".csv"):
        reader = csv.DictReader(io.StringIO(raw))
        lines = []
        for row in reader:
            lines.append(" | ".join(f"{k}: {v}" for k, v in row.items()))
        return "\n".join(lines)

    # .log, .txt, or unknown — return as-is
    return raw
