const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '50mb' }));

// In-memory store for frozen sessions
// Maps freezeId -> { requestPayload, responsePayload, candidateMap }
const freezeStore = new Map();

// --- Helper Functions ---

function utf8ByteLength(str) {
  return Buffer.byteLength(str, 'utf8');
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex').toLowerCase();
}

function canonicalJsonStringify(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJsonStringify).join(',') + ']';
  }
  const keys = Object.keys(obj).sort((a, b) => Buffer.from(a).compare(Buffer.from(b)));
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJsonStringify(obj[k])).join(',') + '}';
}

function computePackageDigest(inventory) {
  const compactArray = inventory.map(item => ({
    name: item.name,
    bytes: item.bytes,
    sha256: item.sha256
  }));
  const compactJson = JSON.stringify(compactArray);
  return sha256Hex(compactJson);
}

function round12(num) {
  return Math.round((num + Number.EPSILON) * 1e12) / 1e12;
}

function sortAndDedupeCodes(codes) {
  const unique = Array.from(new Set(codes));
  return unique.sort((a, b) => Buffer.from(a, 'utf8').compare(Buffer.from(b, 'utf8')));
}

function isNonEmptyString(val) {
  return typeof val === 'string' && val.trim().length > 0;
}

// --- Handler: POST /quantize ---

app.post('/quantize', (req, res) => {
  const body = req.body;

  if (!body || typeof body !== 'object' || Array.isArray(body) || !isNonEmptyString(body.phase)) {
    return res.status(400).json({ error: 'INVALID_INPUT' });
  }

  if (body.phase === 'freeze') {
    return handleFreeze(req, res, body);
  } else if (body.phase === 'select') {
    return handleSelect(req, res, body);
  } else {
    return res.status(400).json({ error: 'INVALID_INPUT' });
  }
});

// --- Phase 1: Freeze ---

function handleFreeze(req, res, body) {
  const { freezeId, calibrationDigest, tokenizerDigest, allowedUnsupportedReasons, candidates } = body;

  // Top-level validation
  if (
    !isNonEmptyString(freezeId) ||
    freezeId.length > 128 ||
    !isNonEmptyString(calibrationDigest) ||
    !isNonEmptyString(tokenizerDigest) ||
    !Array.isArray(allowedUnsupportedReasons) ||
    !Array.isArray(candidates) ||
    candidates.length === 0
  ) {
    return res.status(400).json({ error: 'INVALID_INPUT' });
  }

  // Check allowedUnsupportedReasons validity and uniqueness
  const allowedReasonsSet = new Set();
  for (const reason of allowedUnsupportedReasons) {
    if (!isNonEmptyString(reason) || allowedReasonsSet.has(reason)) {
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }
    allowedReasonsSet.add(reason);
  }

  // Check candidate names uniqueness
  const candidateNamesSet = new Set();
  for (const c of candidates) {
    if (!c || typeof c !== 'object' || !isNonEmptyString(c.name) || candidateNamesSet.has(c.name)) {
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }
    candidateNamesSet.add(c.name);
  }

  // Check replay conflict
  const canonicalReq = canonicalJsonStringify(body);
  if (freezeStore.has(freezeId)) {
    const existing = freezeStore.get(freezeId);
    if (existing.canonicalReq === canonicalReq) {
      return res.status(200).json(existing.responsePayload);
    } else {
      return res.status(409).json({ error: 'FREEZE_ID_CONFLICT' });
    }
  }

  // Process candidates
  const processedCandidates = [];
  const candidateMap = new Map();

  for (const c of candidates) {
    const rawCodes = [];
    let inventory = [];
    let totalBytes = null;
    let packageDigest = null;
    let filesValid = true;

    // Validate files structure
    if (!c.files || typeof c.files !== 'object' || Array.isArray(c.files) || Object.keys(c.files).length === 0) {
      filesValid = false;
    } else {
      const filenames = Object.keys(c.files);
      for (const fn of filenames) {
        if (!isNonEmptyString(fn) || typeof c.files[fn] !== 'string') {
          filesValid = false;
          break;
        }
      }
    }

    if (!filesValid) {
      rawCodes.push('INVALID_INPUT');
      inventory = [];
      totalBytes = null;
      packageDigest = null;
    } else {
      const fnList = Object.keys(c.files).sort((a, b) => Buffer.from(a, 'utf8').compare(Buffer.from(b, 'utf8')));
      inventory = fnList.map(fn => {
        const content = c.files[fn];
        return {
          name: fn,
          bytes: utf8ByteLength(content),
          sha256: sha256Hex(content)
        };
      });

      totalBytes = inventory.reduce((acc, item) => acc + item.bytes, 0);
      packageDigest = computePackageDigest(inventory);
    }

    const hasUnsupportedReason = isNonEmptyString(c.unsupportedReason);
    const isUnsupportedAllowed = hasUnsupportedReason && allowedReasonsSet.has(c.unsupportedReason);

    if (hasUnsupportedReason && !isUnsupportedAllowed) {
      rawCodes.push('UNALLOWED_UNSUPPORTED_REASON');
    }

    if (!hasUnsupportedReason || !isUnsupportedAllowed) {
      if (c.loadable !== true) {
        rawCodes.push('NOT_LOADABLE');
      }
      if (c.calibrationDigest !== calibrationDigest) {
        rawCodes.push('CALIBRATION_MISMATCH');
      }
      if (c.tokenizerDigest !== tokenizerDigest) {
        rawCodes.push('TOKENIZER_MISMATCH');
      }
    }

    const reasonCodes = sortAndDedupeCodes(rawCodes);

    let status = 'invalid';
    if (reasonCodes.length === 0) {
      status = isUnsupportedAllowed ? 'unsupported' : 'frozen';
    }

    const processed = {
      name: c.name,
      status: status,
      inventory: inventory,
      totalBytes: totalBytes,
      packageDigest: packageDigest,
      reasonCodes: reasonCodes
    };

    processedCandidates.push(processed);
    candidateMap.set(c.name, processed);
  }

  // Sort candidates by UTF-8 name
  processedCandidates.sort((a, b) => Buffer.from(a.name, 'utf8').compare(Buffer.from(b.name, 'utf8')));

  const responsePayload = {
    freezeId: freezeId,
    candidates: processedCandidates
  };

  freezeStore.set(freezeId, {
    canonicalReq: canonicalReq,
    responsePayload: responsePayload,
    candidateMap: candidateMap
  });

  return res.status(200).json(responsePayload);
}

// --- Phase 2: Select ---

function handleSelect(req, res, body) {
  const { freezeId, candidates, policy, latencies, rows } = body;

  // Validation of top-level select structure
  if (
    !isNonEmptyString(freezeId) ||
    !Array.isArray(candidates) ||
    !Array.isArray(rows) ||
    !policy ||
    typeof policy !== 'object' ||
    Array.isArray(policy)
  ) {
    return res.status(400).json({ error: 'INVALID_INPUT' });
  }

  const storedSession = freezeStore.get(freezeId) || null;

  // Validate policy structure
  let policyValid = true;
  if (
    !Number.isSafeInteger(policy.maxBytes) ||
    policy.maxBytes < 0 ||
    typeof policy.aggregateFloor !== 'number' ||
    !isFinite(policy.aggregateFloor) ||
    policy.aggregateFloor < 0 ||
    policy.aggregateFloor > 1 ||
    !policy.requiredSlices ||
    typeof policy.requiredSlices !== 'object' ||
    Array.isArray(policy.requiredSlices) ||
    typeof policy.maxLatencyMs !== 'number' ||
    !isFinite(policy.maxLatencyMs) ||
    policy.maxLatencyMs < 0 ||
    !Array.isArray(policy.candidateOrder) ||
    !latencies ||
    typeof latencies !== 'object' ||
    Array.isArray(latencies)
  ) {
    policyValid = false;
  }

  // Validate policy.requiredSlices floors
  if (policyValid) {
    for (const [sName, sFloor] of Object.entries(policy.requiredSlices)) {
      if (!isNonEmptyString(sName) || typeof sFloor !== 'number' || !isFinite(sFloor) || sFloor < 0 || sFloor > 1) {
        policyValid = false;
        break;
      }
    }
  }

  // Check unique candidate names and match with candidateOrder
  const candidateNamesList = candidates.map(c => (c && typeof c === 'object' ? c.name : null));
  const candidateNamesSet = new Set(candidateNamesList);

  if (candidateNamesList.length !== candidates.length || candidateNamesSet.has(null) || candidateNamesSet.has(undefined)) {
    policyValid = false;
  } else {
    const orderSet = new Set(policy.candidateOrder);
    if (
      policy.candidateOrder.length !== orderSet.size ||
      candidateNamesSet.size !== orderSet.size ||
      ![...candidateNamesSet].every(name => orderSet.has(name))
    ) {
      policyValid = false;
    }
  }

  const results = [];

  for (const c of candidates) {
    const rawCodes = [];

    if (!policyValid) {
      rawCodes.push('INVALID_POLICY');
    }

    // Lineage check
    let storedCandidate = null;
    if (!storedSession) {
      rawCodes.push('NOT_FROZEN');
    } else {
      storedCandidate = storedSession.candidateMap.get(c.name) || null;
      if (!storedCandidate || storedCandidate.status !== 'frozen') {
        rawCodes.push('INVALID_LINEAGE');
      } else {
        // Must match stored candidate structure exactly
        if (canonicalJsonStringify(c) !== canonicalJsonStringify(storedCandidate)) {
          rawCodes.push('INVALID_LINEAGE');
        }
      }
    }

    // Manifest recomputation
    let recomputedBytes = null;
    let manifestValid = true;

    if (!c || !Array.isArray(c.inventory)) {
      manifestValid = false;
    } else {
      let sumBytes = 0;
      for (const item of c.inventory) {
        if (!item || !isNonEmptyString(item.name) || !Number.isSafeInteger(item.bytes) || item.bytes < 0 || !isNonEmptyString(item.sha256)) {
          manifestValid = false;
          break;
        }
        sumBytes += item.bytes;
      }
      if (manifestValid) {
        recomputedBytes = sumBytes;
        const calcDigest = computePackageDigest(c.inventory);
        if (recomputedBytes !== c.totalBytes || calcDigest !== c.packageDigest) {
          manifestValid = false;
        }
      }
    }

    if (!manifestValid) {
      rawCodes.push('INVALID_MANIFEST');
      recomputedBytes = null;
    }

    // Latency check
    let candidateLatency = null;
    const latVal = latencies ? latencies[c.name] : undefined;
    if (typeof latVal === 'number' && isFinite(latVal) && latVal >= 0) {
      candidateLatency = latVal;
    }

    // Predictions & Accuracy
    let aggregateAcc = null;
    let sliceAccs = null;
    let predictionsValid = true;

    if (rows.length === 0) {
      predictionsValid = false;
    } else {
      for (const r of rows) {
        if (
          !r ||
          typeof r !== 'object' ||
          (r.label !== 0 && r.label !== 1) ||
          !isNonEmptyString(r.slice) ||
          !r.predictions ||
          typeof r.predictions !== 'object'
        ) {
          predictionsValid = false;
          break;
        }
        const pred = r.predictions[c.name];
        if (pred !== 0 && pred !== 1) {
          predictionsValid = false;
          break;
        }
      }
    }

    if (!predictionsValid) {
      rawCodes.push('INVALID_PREDICTIONS');
    } else {
      let totalCorrect = 0;
      const sliceCounts = {};
      const sliceCorrect = {};

      for (const r of rows) {
        const isCorrect = r.predictions[c.name] === r.label ? 1 : 0;
        totalCorrect += isCorrect;

        sliceCounts[r.slice] = (sliceCounts[r.slice] || 0) + 1;
        sliceCorrect[r.slice] = (sliceCorrect[r.slice] || 0) + isCorrect;
      }

      aggregateAcc = round12(totalCorrect / rows.length);
      sliceAccs = {};
      for (const sName of Object.keys(sliceCounts)) {
        sliceAccs[sName] = round12(sliceCorrect[sName] / sliceCounts[sName]);
      }
    }

    // Floor and Limit evaluations
    if (policyValid && predictionsValid) {
      if (aggregateAcc !== null && aggregateAcc < policy.aggregateFloor) {
        rawCodes.push('AGGREGATE_FLOOR');
      }

      for (const [reqSlice, floorVal] of Object.entries(policy.requiredSlices)) {
        if (!sliceAccs || !(reqSlice in sliceAccs)) {
          rawCodes.push(`MISSING_SLICE:${reqSlice}`);
        } else if (sliceAccs[reqSlice] < floorVal) {
          rawCodes.push(`SLICE_FLOOR:${reqSlice}`);
        }
      }
    }

    if (policyValid) {
      if (recomputedBytes === null || recomputedBytes > policy.maxBytes) {
        rawCodes.push('SIZE_LIMIT');
      }
      if (candidateLatency === null || candidateLatency > policy.maxLatencyMs) {
        rawCodes.push('LATENCY_LIMIT');
      }
    }

    const reasonCodes = sortAndDedupeCodes(rawCodes);
    const admitted = reasonCodes.length === 0;

    results.push({
      name: c.name,
      aggregate: aggregateAcc,
      slices: sliceAccs,
      totalBytes: recomputedBytes,
      latencyMs: candidateLatency,
      admitted: admitted,
      reasonCodes: reasonCodes
    });
  }

  // Sort results by policy.candidateOrder
  const orderMap = new Map();
  if (policyValid && policy.candidateOrder) {
    policy.candidateOrder.forEach((name, idx) => orderMap.set(name, idx));
  }

  results.sort((a, b) => {
    const idxA = orderMap.has(a.name) ? orderMap.get(a.name) : Infinity;
    const idxB = orderMap.has(b.name) ? orderMap.get(b.name) : Infinity;
    if (idxA !== idxB) return idxA - idxB;
    return Buffer.from(a.name, 'utf8').compare(Buffer.from(b.name, 'utf8'));
  });

  // Select Winner among admitted candidates
  const admittedResults = results.filter(r => r.admitted);
  let selected = null;
  let packageManifest = null;

  if (admittedResults.length > 0) {
    admittedResults.sort((a, b) => {
      if (a.totalBytes !== b.totalBytes) return a.totalBytes - b.totalBytes;
      if (a.latencyMs !== b.latencyMs) return a.latencyMs - b.latencyMs;
      const idxA = orderMap.has(a.name) ? orderMap.get(a.name) : Infinity;
      const idxB = orderMap.has(b.name) ? orderMap.get(b.name) : Infinity;
      return idxA - idxB;
    });

    const winner = admittedResults[0];
    selected = winner.name;
    if (storedSession && storedSession.candidateMap.has(winner.name)) {
      packageManifest = storedSession.candidateMap.get(winner.name);
    }
  }

  return res.status(200).json({
    freezeId: freezeId,
    selected: selected,
    results: results,
    packageManifest: packageManifest
  });
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Quantize API listening on port ${PORT}`);
});
