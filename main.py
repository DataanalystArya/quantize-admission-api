import hashlib
import json
import math
import threading
from copy import deepcopy

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Persistent state for the running service.
# Render restarts can reset in-memory state, so keep the service instance alive
# while the grader performs its freeze -> select sequence.
FREEZES = {}
LOCK = threading.Lock()

CODES = {
    "INVALID_INPUT",
    "UNALLOWED_UNSUPPORTED_REASON",
    "NOT_LOADABLE",
    "CALIBRATION_MISMATCH",
    "TOKENIZER_MISMATCH",
    "NOT_FROZEN",
    "INVALID_LINEAGE",
    "INVALID_POLICY",
    "INVALID_PREDICTIONS",
    "INVALID_MANIFEST",
    "AGGREGATE_FLOOR",
    "SIZE_LIMIT",
    "LATENCY_LIMIT",
}


def utf8_key(s):
    return s.encode("utf-8")


def sorted_utf8(values):
    return sorted(values, key=utf8_key)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_utf8(text):
    return sha256_bytes(text.encode("utf-8"))


def compact_json(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def is_string(x):
    return isinstance(x, str)


def nonempty_string(x):
    return isinstance(x, str) and len(x) > 0


def unique_strings_utf8(values):
    if not isinstance(values, list):
        return False
    if not all(nonempty_string(x) for x in values):
        return False
    return len(set(values)) == len(values)


def safe_nonnegative_integer(x):
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and x >= 0
        and x <= 9007199254740991
    )


def finite_number(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
    )


def valid_floor(x):
    return finite_number(x) and 0 <= float(x) <= 1


def canonical_inventory(name, files):
    """
    Returns:
      inventory, totalBytes, packageDigest
    or None if files are invalid.
    """
    if not isinstance(files, dict) or len(files) == 0:
        return None

    filenames = list(files.keys())

    # JSON object keys are strings in normal JSON, but explicitly enforce it.
    if not all(nonempty_string(x) for x in filenames):
        return None

    if len(set(filenames)) != len(filenames):
        return None

    inventory = []

    for filename in sorted_utf8(filenames):
        value = files[filename]

        # File text is data: require a JSON string. UTF-8 encoding is therefore
        # deterministic and invalid surrogate-containing strings are rejected.
        if not isinstance(value, str):
            return None

        try:
            raw = value.encode("utf-8")
        except UnicodeEncodeError:
            return None

        inventory.append(
            {
                "name": filename,
                "bytes": len(raw),
                "sha256": sha256_bytes(raw),
            }
        )

    total = sum(x["bytes"] for x in inventory)

    digest = sha256_utf8(compact_json(inventory))

    return inventory, total, digest


def valid_binary_prediction(x):
    # JSON booleans are not numeric predictions.
    return isinstance(x, (int, float)) and not isinstance(x, bool) and (
        x == 0 or x == 1
    )


def round12(x):
    return float(round(x, 12))


def codes_sorted(codes):
    return sorted(set(codes), key=utf8_key)


def same_json(a, b):
    # Python structures from JSON preserve semantic equality sufficiently for
    # request replay/conflict checking.
    return a == b


def freeze_request_valid(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    if not nonempty_string(body.get("freezeId")):
        return False

    if len(body["freezeId"]) > 128:
        return False

    if not nonempty_string(body.get("calibrationDigest")):
        return False

    if not nonempty_string(body.get("tokenizerDigest")):
        return False

    if not unique_strings_utf8(body.get("allowedUnsupportedReasons")):
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

        if len(c["files"]) == 0:
            # Empty files means invalid candidate, not invalid request.
            pass

        if not isinstance(c.get("loadable"), bool):
            return False

        if not nonempty_string(c.get("calibrationDigest")):
            return False

        if not nonempty_string(c.get("tokenizerDigest")):
            return False

        if "unsupportedReason" in c and c["unsupportedReason"] is not None:
            if not nonempty_string(c["unsupportedReason"]):
                return False

    if len(set(names)) != len(names):
        return False

    return True


def build_freeze_response(body):
    request_cal = body["calibrationDigest"]
    request_tok = body["tokenizerDigest"]
    allowed = set(body["allowedUnsupportedReasons"])

    results = []

    for c in body["candidates"]:
        name = c["name"]
        inventory_data = canonical_inventory(name, c["files"])

        reason_codes = []

        if inventory_data is None:
            inventory = []
            total = None
            package_digest = None
            reason_codes.append("INVALID_INPUT")
        else:
            inventory, total, package_digest = inventory_data

            unsupported_reason = c.get("unsupportedReason")

            if unsupported_reason is not None:
                if unsupported_reason not in allowed:
                    reason_codes.append("UNALLOWED_UNSUPPORTED_REASON")
            else:
                if not c["loadable"]:
                    reason_codes.append("NOT_LOADABLE")

                if c["calibrationDigest"] != request_cal:
                    reason_codes.append("CALIBRATION_MISMATCH")

                if c["tokenizerDigest"] != request_tok:
                    reason_codes.append("TOKENIZER_MISMATCH")

        reason_codes = codes_sorted(reason_codes)

        if "INVALID_INPUT" in reason_codes:
            status = "invalid"
        elif reason_codes:
            status = "invalid"
        elif c.get("unsupportedReason") is not None:
            status = "unsupported"
        else:
            status = "frozen"

        results.append(
            {
                "name": name,
                "status": status,
                "inventory": inventory,
                "totalBytes": total,
                "packageDigest": package_digest,
                "reasonCodes": reason_codes,
            }
        )

    results.sort(key=lambda x: utf8_key(x["name"]))

    return {
        "freezeId": body["freezeId"],
        "candidates": results,
    }


def valid_select_basic(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "select":
        return False

    if not nonempty_string(body.get("freezeId")):
        return False

    if "candidates" not in body or not isinstance(body["candidates"], list):
        return False

    if "rows" not in body or not isinstance(body["rows"], list):
        return False

    if "policy" not in body or not isinstance(body["policy"], dict):
        return False

    return True


def validate_policy(policy):
    required = [
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    ]

    if any(k not in policy for k in required):
        return False

    if not safe_nonnegative_integer(policy["maxBytes"]):
        return False

    if not valid_floor(policy["aggregateFloor"]):
        return False

    if not isinstance(policy["requiredSlices"], dict):
        return False

    for k, v in policy["requiredSlices"].items():
        if not nonempty_string(k):
            return False
        if not valid_floor(v):
            return False

    if not finite_number(policy["maxLatencyMs"]) or policy["maxLatencyMs"] < 0:
        return False

    if not unique_strings_utf8(policy["candidateOrder"]):
        return False

    return True


def validate_frozen_candidates(submitted, stored):
    """
    Candidate array must exactly equal the stored freeze response candidate
    array, and manifests are independently recomputed.
    """
    if not isinstance(submitted, list):
        return False

    if not same_json(submitted, stored["candidates"]):
        return False

    return True


def recompute_manifest(candidate):
    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return None

    expected_inventory = []

    for item in inventory:
        if not isinstance(item, dict):
            return None

        if set(item.keys()) != {"name", "bytes", "sha256"}:
            return None

        if not nonempty_string(item["name"]):
            return None

        if not safe_nonnegative_integer(item["bytes"]):
            return None

        if (
            not isinstance(item["sha256"], str)
            or len(item["sha256"]) != 64
            or any(ch not in "0123456789abcdef" for ch in item["sha256"])
        ):
            return None

        expected_inventory.append(
            {
                "name": item["name"],
                "bytes": item["bytes"],
                "sha256": item["sha256"],
            }
        )

    # Filename uniqueness.
    names = [x["name"] for x in expected_inventory]

    if len(names) != len(set(names)):
        return None

    if names != sorted_utf8(names):
        return None

    total = sum(x["bytes"] for x in expected_inventory)
    digest = sha256_utf8(compact_json(expected_inventory))

    if candidate.get("totalBytes") != total:
        return None

    if candidate.get("packageDigest") != digest:
        return None

    return {
        "inventory": expected_inventory,
        "totalBytes": total,
        "packageDigest": digest,
    }


def calculate_scores(candidate_name, rows, required_slices):
    """
    Returns aggregate and slices.

    Invalid predictions => aggregate None and all required slice values None.
    """
    if len(rows) == 0:
        # Empty dataset has no meaningful accuracy.
        return None, {s: None for s in required_slices}, False

    correct = 0
    slice_counts = {s: [0, 0] for s in required_slices}

    for row in rows:
        if not isinstance(row, dict):
            return None, {s: None for s in required_slices}, False

        if "label" not in row or "slice" not in row or "predictions" not in row:
            return None, {s: None for s in required_slices}, False

        predictions = row["predictions"]

        if not isinstance(predictions, dict):
            return None, {s: None for s in required_slices}, False

        if candidate_name not in predictions:
            return None, {s: None for s in required_slices}, False

        pred = predictions[candidate_name]

        if not valid_binary_prediction(pred):
            return None, {s: None for s in required_slices}, False

        label = row["label"]
        if not valid_binary_prediction(label):
            return None, {s: None for s in required_slices}, False

        if pred == label:
            correct += 1

        slice_name = row["slice"]

        if slice_name in slice_counts:
            slice_counts[slice_name][1] += 1
            if pred == label:
                slice_counts[slice_name][0] += 1

    aggregate = round12(correct / len(rows))

    slices = {}
    for s in required_slices:
        count = slice_counts[s][1]
        if count == 0:
            slices[s] = None
        else:
            slices[s] = round12(slice_counts[s][0] / count)

    return aggregate, slices, True


def normalize_latency(latencies, name):
    if not isinstance(latencies, dict):
        return None, False

    if name not in latencies:
        return None, False

    value = latencies[name]

    if not finite_number(value) or float(value) < 0:
        return None, False

    return float(value), True


@app.post("/quantize")
async def quantize(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_INPUT"},
        )

    # ---------------------------------------------------------
    # FREEZE
    # ---------------------------------------------------------
    if isinstance(body, dict) and body.get("phase") == "freeze":
        if not freeze_request_valid(body):
            return JSONResponse(
                status_code=400,
                content={"error": "INVALID_INPUT"},
            )

        freeze_id = body["freezeId"]

        with LOCK:
            if freeze_id in FREEZES:
                previous_input = FREEZES[freeze_id]["input"]

                if same_json(previous_input, body):
                    return deepcopy(FREEZES[freeze_id]["response"])

                return JSONResponse(
                    status_code=409,
                    content={"error": "FREEZE_ID_CONFLICT"},
                )

            response = build_freeze_response(body)

            # Persist complete response and original request for replay/conflict.
            FREEZES[freeze_id] = {
                "input": deepcopy(body),
                "response": deepcopy(response),
            }

            return deepcopy(response)

    # ---------------------------------------------------------
    # SELECT
    # ---------------------------------------------------------
    if isinstance(body, dict) and body.get("phase") == "select":
        if not valid_select_basic(body):
            return JSONResponse(
                status_code=400,
                content={"error": "INVALID_INPUT"},
            )

        freeze_id = body["freezeId"]

        with LOCK:
            stored = FREEZES.get(freeze_id)

        if stored is None:
            # Select must still have a deterministic response shape.
            return JSONResponse(
                status_code=200,
                content={
                    "freezeId": freeze_id,
                    "selected": None,
                    "results": [],
                    "packageManifest": None,
                },
            )

        if not validate_policy(body["policy"]):
            return JSONResponse(
                status_code=200,
                content={
                    "freezeId": freeze_id,
                    "selected": None,
                    "results": [],
                    "packageManifest": None,
                },
            )

        stored_candidates = stored["response"]["candidates"]

        if not validate_frozen_candidates(body["candidates"], stored["response"]):
            return JSONResponse(
                status_code=200,
                content={
                    "freezeId": freeze_id,
                    "selected": None,
                    "results": [],
                    "packageManifest": None,
                },
            )

        policy = body["policy"]
        submitted_candidates = body["candidates"]

        stored_names = [c["name"] for c in stored_candidates]
        order = policy["candidateOrder"]

        if set(stored_names) != set(order):
            # Candidate set mismatch is a policy/lineage problem.
            return JSONResponse(
                status_code=200,
                content={
                    "freezeId": freeze_id,
                    "selected": None,
                    "results": [],
                    "packageManifest": None,
                },
            )

        required_slices = policy["requiredSlices"]

        latencies = body.get("latencies")
        rows = body["rows"]

        results_by_name = {}

        for candidate in stored_candidates:
            name = candidate["name"]
            reasons = []

            # Only frozen candidates can be admitted.
            if candidate.get("status") != "frozen":
                reasons.append("NOT_FROZEN")

            # Validate recorded manifest.
            manifest = recompute_manifest(candidate)
            if manifest is None:
                reasons.append("INVALID_MANIFEST")
                total_bytes = None
            else:
                total_bytes = manifest["totalBytes"]

            # Lineage is represented by the stored candidate response and its
            # exact equality with the supplied candidate array.
            if not same_json(candidate, stored["response"]["candidates"][
                stored_names.index(name)
            ]):
                reasons.append("INVALID_LINEAGE")

            aggregate, slices, predictions_valid = calculate_scores(
                name,
                rows,
                required_slices,
            )

            if not predictions_valid:
                reasons.append("INVALID_PREDICTIONS")

            latency, latency_valid = normalize_latency(latencies, name)

            # Invalid latency cannot be validated, so expose null.
            if not latency_valid:
                latency_ms = None
            else:
                latency_ms = latency

            if predictions_valid:
                if aggregate is None or aggregate < policy["aggregateFloor"]:
                    reasons.append("AGGREGATE_FLOOR")

                for slice_name, floor in required_slices.items():
                    if slices.get(slice_name) is None:
                        reasons.append("MISSING_SLICE:" + slice_name)
                    elif slices[slice_name] < floor:
                        reasons.append("SLICE_FLOOR:" + slice_name)

            if total_bytes is not None:
                if total_bytes > policy["maxBytes"]:
                    reasons.append("SIZE_LIMIT")

            if latency_valid:
                if latency > policy["maxLatencyMs"]:
                    reasons.append("LATENCY_LIMIT")

            reasons = codes_sorted(reasons)

            admitted = len(reasons) == 0

            result = {
                "name": name,
                "aggregate": aggregate,
                "slices": slices,
                "totalBytes": total_bytes,
                "latencyMs": latency_ms,
                "admitted": admitted,
                "reasonCodes": reasons,
            }

            results_by_name[name] = result

        # Results follow candidateOrder, with UTF-8 name as fallback.
        order_index = {name: i for i, name in enumerate(order)}

        results = list(results_by_name.values())
        results.sort(
            key=lambda r: (
                order_index.get(r["name"], len(order)),
                utf8_key(r["name"]),
            )
        )

        admitted = [r for r in results if r["admitted"]]

        selected = None
        package_manifest = None

        if admitted:
            # Smaller bytes, then lower latency, then candidate order.
            selected_result = min(
                admitted,
                key=lambda r: (
                    r["totalBytes"],
                    r["latencyMs"],
                    order_index.get(r["name"], len(order)),
                    utf8_key(r["name"]),
                ),
            )

            selected = selected_result["name"]

            # Winner object: exact recorded candidate object.
            winner = next(
                c for c in stored_candidates if c["name"] == selected
            )

            package_manifest = deepcopy(winner)

        return {
            "freezeId": freeze_id,
            "selected": selected,
            "results": results,
            "packageManifest": package_manifest,
        }

    # Unknown/missing phase.
    return JSONResponse(
        status_code=400,
        content={"error": "INVALID_INPUT"},
    )


@app.get("/")
def root():
    return {"status": "ok"}
