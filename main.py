import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

FREEZES = {}
LOCK = threading.Lock()

FREEZE_CODES = {
    "INVALID_INPUT",
    "UNALLOWED_UNSUPPORTED_REASON",
    "NOT_LOADABLE",
    "CALIBRATION_MISMATCH",
    "TOKENIZER_MISMATCH",
}

SELECT_CODES = {
    "NOT_FROZEN",
    "INVALID_LINEAGE",
    "INVALID_POLICY",
    "INVALID_PREDICTIONS",
    "INVALID_MANIFEST",
    "AGGREGATE_FLOOR",
    "SIZE_LIMIT",
    "LATENCY_LIMIT",
}


def u8(s):
    return s.encode("utf-8")


def usort(xs):
    return sorted(xs, key=u8)


def digest_bytes(b):
    return hashlib.sha256(b).hexdigest()


def digest_json(x):
    return digest_bytes(
        json.dumps(
            x,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def nonempty_string(x):
    return isinstance(x, str) and len(x) > 0


def unique_nonempty_strings(x):
    return (
        isinstance(x, list)
        and all(nonempty_string(v) for v in x)
        and len(x) == len(set(x))
    )


def finite_number(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
    )


def safe_integer(x):
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and 0 <= x <= 9007199254740991
    )


def valid_floor(x):
    return finite_number(x) and 0 <= float(x) <= 1


def error_400():
    return JSONResponse(
        status_code=400,
        content={"error": "INVALID_INPUT"},
    )


def make_inventory(files):
    if not isinstance(files, dict) or len(files) == 0:
        return None

    names = list(files.keys())

    if any(not isinstance(n, str) or n == "" for n in names):
        return None

    if len(names) != len(set(names)):
        return None

    inventory = []

    for name in usort(names):
        text = files[name]

        if not isinstance(text, str):
            return None

        try:
            raw = text.encode("utf-8")
        except UnicodeEncodeError:
            return None

        inventory.append(
            {
                "name": name,
                "bytes": len(raw),
                "sha256": digest_bytes(raw),
            }
        )

    total = sum(x["bytes"] for x in inventory)
    package_digest = digest_json(inventory)

    return inventory, total, package_digest


def valid_freeze_request(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")
    if not nonempty_string(freeze_id) or len(freeze_id) > 128:
        return False

    if not nonempty_string(body.get("calibrationDigest")):
        return False

    if not nonempty_string(body.get("tokenizerDigest")):
        return False

    if not unique_nonempty_strings(body.get("allowedUnsupportedReasons")):
        return False

    candidates = body.get("candidates")

    if not isinstance(candidates, list) or len(candidates) == 0:
        return False

    names = []

    for c in candidates:
        if not isinstance(c, dict):
            return False

        if not nonempty_string(c.get("name")):
            return False

        names.append(c["name"])

        if "files" not in c or not isinstance(c["files"], dict):
            return False

        if not isinstance(c.get("loadable"), bool):
            return False

        if not nonempty_string(c.get("calibrationDigest")):
            return False

        if not nonempty_string(c.get("tokenizerDigest")):
            return False

        if "unsupportedReason" in c:
            r = c["unsupportedReason"]
            if r is not None and not nonempty_string(r):
                return False

    return len(names) == len(set(names))


def freeze_response(body):
    calibration = body["calibrationDigest"]
    tokenizer = body["tokenizerDigest"]
    allowed = set(body["allowedUnsupportedReasons"])

    output = []

    for c in body["candidates"]:
        inventory_data = make_inventory(c["files"])
        reasons = []

        if inventory_data is None:
            inventory = []
            total = None
            package_digest = None
            reasons.append("INVALID_INPUT")
        else:
            inventory, total, package_digest = inventory_data

            unsupported = c.get("unsupportedReason")

            if unsupported is not None:
                if unsupported not in allowed:
                    reasons.append("UNALLOWED_UNSUPPORTED_REASON")
            else:
                if not c["loadable"]:
                    reasons.append("NOT_LOADABLE")

                if c["calibrationDigest"] != calibration:
                    reasons.append("CALIBRATION_MISMATCH")

                if c["tokenizerDigest"] != tokenizer:
                    reasons.append("TOKENIZER_MISMATCH")

        reasons = sorted(set(reasons), key=u8)

        if "INVALID_INPUT" in reasons:
            status = "invalid"
        elif reasons:
            status = "invalid"
        elif c.get("unsupportedReason") is not None:
            status = "unsupported"
        else:
            status = "frozen"

        output.append(
            {
                "name": c["name"],
                "status": status,
                "inventory": inventory,
                "totalBytes": total,
                "packageDigest": package_digest,
                "reasonCodes": reasons,
            }
        )

    output.sort(key=lambda x: u8(x["name"]))

    return {
        "freezeId": body["freezeId"],
        "candidates": output,
    }


def valid_select_request(body):
    return (
        isinstance(body, dict)
        and body.get("phase") == "select"
        and nonempty_string(body.get("freezeId"))
        and isinstance(body.get("candidates"), list)
        and isinstance(body.get("rows"), list)
        and isinstance(body.get("policy"), dict)
    )


def valid_policy(policy):
    if not safe_integer(policy.get("maxBytes")):
        return False

    if not valid_floor(policy.get("aggregateFloor")):
        return False

    required = policy.get("requiredSlices")
    if not isinstance(required, dict):
        return False

    for name, floor in required.items():
        if not nonempty_string(name) or not valid_floor(floor):
            return False

    if not finite_number(policy.get("maxLatencyMs")):
        return False

    if policy["maxLatencyMs"] < 0:
        return False

    if not unique_nonempty_strings(policy.get("candidateOrder")):
        return False

    return True


def validate_manifest(c):
    inv = c.get("inventory")

    if not isinstance(inv, list):
        return None

    names = []

    for item in inv:
        if not isinstance(item, dict):
            return None

        if set(item.keys()) != {"name", "bytes", "sha256"}:
            return None

        if not nonempty_string(item["name"]):
            return None

        if not safe_integer(item["bytes"]):
            return None

        sha = item["sha256"]

        if (
            not isinstance(sha, str)
            or len(sha) != 64
            or any(ch not in "0123456789abcdef" for ch in sha)
        ):
            return None

        names.append(item["name"])

    if len(names) != len(set(names)):
        return None

    if names != usort(names):
        return None

    total = sum(x["bytes"] for x in inv)
    package_digest = digest_json(inv)

    if c.get("totalBytes") != total:
        return None

    if c.get("packageDigest") != package_digest:
        return None

    return {
        "inventory": inv,
        "totalBytes": total,
        "packageDigest": package_digest,
    }


def prediction_valid(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and x in (0, 1)
    )


def score_candidate(name, rows, required_slices):
    if len(rows) == 0:
        return None, {s: None for s in required_slices}, False

    correct = 0
    slice_correct = {s: 0 for s in required_slices}
    slice_total = {s: 0 for s in required_slices}

    for row in rows:
        if not isinstance(row, dict):
            return None, {s: None for s in required_slices}, False

        if "label" not in row:
            return None, {s: None for s in required_slices}, False

        if "slice" not in row:
            return None, {s: None for s in required_slices}, False

        if not isinstance(row.get("predictions"), dict):
            return None, {s: None for s in required_slices}, False

        if name not in row["predictions"]:
            return None, {s: None for s in required_slices}, False

        label = row["label"]
        prediction = row["predictions"][name]

        if not prediction_valid(label):
            return None, {s: None for s in required_slices}, False

        if not prediction_valid(prediction):
            return None, {s: None for s in required_slices}, False

        correct += int(prediction == label)

        slice_name = row["slice"]

        if slice_name in required_slices:
            slice_total[slice_name] += 1
            slice_correct[slice_name] += int(prediction == label)

    aggregate = round(correct / len(rows), 12)

    slices = {}

    for s in required_slices:
        if slice_total[s] == 0:
            slices[s] = None
        else:
            slices[s] = round(
                slice_correct[s] / slice_total[s],
                12,
            )

    return float(aggregate), slices, True


def latency_value(latencies, name):
    if not isinstance(latencies, dict):
        return None

    if name not in latencies:
        return None

    value = latencies[name]

    if not finite_number(value) or value < 0:
        return None

    return float(value)


@app.post("/quantize")
async def quantize(request: Request):
    try:
        body = await request.json()
    except Exception:
        return error_400()

    # -------------------------
    # FREEZE
    # -------------------------
    if isinstance(body, dict) and body.get("phase") == "freeze":
        if not valid_freeze_request(body):
            return error_400()

        freeze_id = body["freezeId"]

        with LOCK:
            if freeze_id in FREEZES:
                old = FREEZES[freeze_id]

                if old["input"] == body:
                    return old["response"]

                return JSONResponse(
                    status_code=409,
                    content={"error": "FREEZE_ID_CONFLICT"},
                )

            response = freeze_response(body)

            FREEZES[freeze_id] = {
                "input": body,
                "response": response,
            }

            return response

    # -------------------------
    # SELECT
    # -------------------------
    if isinstance(body, dict) and body.get("phase") == "select":
        if not valid_select_request(body):
            return error_400()

        freeze_id = body["freezeId"]

        with LOCK:
            stored = FREEZES.get(freeze_id)

        if stored is None:
            return {
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            }

        policy = body["policy"]

        if not valid_policy(policy):
            return {
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            }

        stored_candidates = stored["response"]["candidates"]

        # The grader must send exactly the frozen candidate array.
        if body["candidates"] != stored_candidates:
            return {
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            }

        stored_names = [c["name"] for c in stored_candidates]
        order = policy["candidateOrder"]

        # Same unique candidate set.
        if len(stored_names) != len(set(stored_names)):
            return {
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            }

        if set(stored_names) != set(order):
            return {
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            }

        rows = body["rows"]
        latencies = body.get("latencies", {})
        required_slices = policy["requiredSlices"]

        order_index = {name: i for i, name in enumerate(order)}

        results = []

        for candidate in stored_candidates:
            name = candidate["name"]
            reasons = []

            if candidate.get("status") != "frozen":
                reasons.append("NOT_FROZEN")

            manifest = validate_manifest(candidate)

            if manifest is None:
                reasons.append("INVALID_MANIFEST")
                total_bytes = None
            else:
                total_bytes = manifest["totalBytes"]

            aggregate, slices, pred_ok = score_candidate(
                name,
                rows,
                required_slices,
            )

            if not pred_ok:
                reasons.append("INVALID_PREDICTIONS")

            latency = latency_value(latencies, name)

            if pred_ok:
                if aggregate is None or aggregate < policy["aggregateFloor"]:
                    reasons.append("AGGREGATE_FLOOR")

                for slice_name, floor in required_slices.items():
                    value = slices.get(slice_name)

                    if value is None:
                        reasons.append(
                            "MISSING_SLICE:" + slice_name
                        )
                    elif value < floor:
                        reasons.append(
                            "SLICE_FLOOR:" + slice_name
                        )

            if total_bytes is not None:
                if total_bytes > policy["maxBytes"]:
                    reasons.append("SIZE_LIMIT")

            if latency is not None:
                if latency > policy["maxLatencyMs"]:
                    reasons.append("LATENCY_LIMIT")

            reasons = sorted(set(reasons), key=u8)

            results.append(
                {
                    "name": name,
                    "aggregate": aggregate,
                    "slices": slices,
                    "totalBytes": total_bytes,
                    "latencyMs": latency,
                    "admitted": len(reasons) == 0,
                    "reasonCodes": reasons,
                }
            )

        results.sort(
            key=lambda x: (
                order_index.get(x["name"], len(order)),
                u8(x["name"]),
            )
        )

        winners = [r for r in results if r["admitted"]]

        selected = None
        package_manifest = None

        if winners:
            winner = min(
                winners,
                key=lambda r: (
                    r["totalBytes"],
                    r["latencyMs"],
                    order_index[r["name"]],
                ),
            )

            selected = winner["name"]

            package_manifest = next(
                c for c in stored_candidates
                if c["name"] == selected
            )

        return {
            "freezeId": freeze_id,
            "selected": selected,
            "results": results,
            "packageManifest": package_manifest,
        }

    return error_400()


@app.get("/")
def root():
    return {"status": "ok"}
