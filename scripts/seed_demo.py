import json
from pathlib import Path
from urllib import request

ROOT = Path(__file__).resolve().parents[1]
API = "http://localhost:8000/api"

with open(ROOT / "samples" / "demo_case.json", "r", encoding="utf-8") as handle:
    payload = json.load(handle)

req = request.Request(
    f"{API}/cases",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)

with request.urlopen(req) as response:
    print(response.read().decode("utf-8"))
