const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

// Stateful in-memory store for frozen sessions: freezeId -> { canonicalReq, responsePayload, candidateMap }
const freezeStore = new Map();

function compareUtf8(a, b) {
  return Buffer.from(a, 'utf8').compare(Buffer.from(b, 'utf8'));
}

function utf8ByteLength(str) {
  return Buffer.byteLength(str, 'utf8');
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex').toLowerCase();
}

function canonicalJsonStringify(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJsonStringify).join(',') + ']';
  }
  const keys = Object.keys(obj).sort(compareUtf8);
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
  if (typeof num !== 'number' || isNaN(num)) return null;
  return Number(num.toFixed(12));
}

function sortAndDedupeCodes(codes) {
  const unique = Array.from(new Set(codes));
  return unique.sort(compareUtf8);
}

function isNonEmptyString(val) {
  return typeof val === 'string' && val.trim().length > 0;
}

function sendJson(res, statusCode, body) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

// --- Freeze Phase ---

function handleFreeze(body, res) {
  const { freezeId, calibrationDigest, tokenizerDigest, allowedUnsupportedReasons, candidates } = body;

  // Rule: empty or non-array freeze candidates list returns HTTP 400
  if (!isNonEmptyString(freezeId) || freezeId.length > 128 || !Array.isArray(candidates) || candidates.length === 0) {
    return sendJson(res, 400, { error: 'INVALID_INPUT' });
  }

  const allowedReasonsSet = new Set();
  if (Array.isArray(allowedUnsupportedReasons)) {
    for (const reason of allowedUnsupportedReasons) {
      if (isNonEmptyString(reason)) {
        allowedReasonsSet.add(reason);
      }
    }
  }

  // Replay check
  const canonicalReq = canonicalJsonStringify(body);
  if (freezeStore.has(freezeId)) {
    const existing = freezeStore.get(freezeId);
    if (existing.canonicalReq === canonicalReq) {
      return sendJson(res, 200, existing.responsePayload);
    } else {
      return sendJson(res, 409, { error: 'FREEZE_ID_CONFLICT' });
    }
  }

  const processedCandidates = [];
  const candidateMap = new Map();

  for (const c of candidates) {
    const rawCodes = [];
    let inventory = [];
    let totalBytes = null;
    let packageDigest = null;
    let filesValid = true;

    if (!c || typeof c !== 'object' || !isNonEmptyString(c.name)) {
      filesValid = false;
    } else if (!c.files || typeof c.files !== 'object' || Array.isArray(c.files) || Object.keys(c.files).length === 0) {
      filesValid = false;
    } else {
      for (const [fn, content] of Object.entries(c.files)) {
        if (!isNonEmptyString(fn) || typeof content !== 'string') {
          filesValid = false;
          break;
        }
      }
    }

    const candName = c && isNonEmptyString(c.name) ? c.name : 'unknown';

    if (!filesValid) {
      rawCodes.push('INVALID_INPUT');
      inventory = [];
      totalBytes = null;
      packageDigest = null;
    } else {
      const fnList = Object.keys(c.files).sort(compareUtf8);
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

    const hasUnsupportedReason = c && isNonEmptyString(c.unsupportedReason);
    const isUnsupportedAllowed = hasUnsupportedReason && allowedReasonsSet.has(c.unsupportedReason);

    if (hasUnsupportedReason && !isUnsupportedAllowed) {
      rawCodes.push('UNALLOWED_UNSUPPORTED_REASON');
    }

    if (!hasUnsupportedReason || !isUnsupportedAllowed) {
      if (!c || c.loadable !== true) {
        rawCodes.push('NOT_LOADABLE');
      }
      if (!c || c.calibrationDigest !== calibrationDigest) {
        rawCodes.push('CALIBRATION_MISMATCH');
      }
      if (!c || c.tokenizerDigest !== tokenizerDigest) {
        rawCodes.push('TOKENIZER_MISMATCH');
      }
    }

    const reasonCodes = sortAndDedupeCodes(rawCodes);

    let status = 'invalid';
    if (reasonCodes.length === 0) {
      status = isUnsupportedAllowed ? 'unsupported' : 'frozen';
    }

    const processed = {
      name: candName,
      status: status,
      inventory: inventory,
      totalBytes: totalBytes,
      packageDigest: packageDigest,
      reasonCodes: reasonCodes
    };

    processedCandidates.push(processed);
    candidateMap.set(candName, processed);
  }

  processedCandidates.sort((a, b) => compareUtf8(a.name, b.name));

  const responsePayload = {
    freezeId: freezeId,
    candidates: processedCandidates
  };

  freezeStore.set(freezeId, {
    canonicalReq: canonicalReq,
    responsePayload: responsePayload,
    candidateMap: candidateMap
  });

  return sendJson(res, 200, responsePayload);
}

// --- Select Phase ---

function handleSelect(body, res) {
  const { freezeId, candidates, policy, latencies, rows } = body;

  // Rule: missing candidates/rows array or policy object returns HTTP 400
  if (
    !isNonEmptyString(freezeId) ||
    !Array.isArray(candidates) ||
    !Array.isArray(rows) ||
    !policy ||
    typeof policy !== 'object' ||
    Array.isArray(policy)
  ) {
    return sendJson(res, 400, { error: 'INVALID_INPUT' });
  }

  const storedSession = freezeStore.get(freezeId) || null;

  // Validate policy
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
    !Array.isArray(policy.candidateOrder)
  ) {
    policyValid = false;
  }

  if (policyValid) {
    for (const [sName, sFloor] of Object.entries(policy.requiredSlices)) {
      if (!isNonEmptyString(sName) || typeof sFloor !== 'number' || !isFinite(sFloor) || sFloor < 0 || sFloor > 1) {
        policyValid = false;
        break;
      }
    }
  }

  const candidateNamesList = candidates.map(c => (c && typeof c === 'object' && isNonEmptyString(c.name) ? c.name : null));
  const candidateNamesSet = new Set(candidateNamesList);

  if (candidateNamesList.length !== candidates.length || candidateNamesSet.has(null)) {
    policyValid = false;
  } else if (policyValid) {
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
    const candName = c && isNonEmptyString(c.name) ? c.name : 'unknown';
    const rawCodes = [];

    if (!policyValid) {
      rawCodes.push('INVALID_POLICY');
    }

    // Lineage verification
    let storedCandidate = null;
    if (!storedSession) {
      rawCodes.push('NOT_FROZEN');
    } else {
      storedCandidate = storedSession.candidateMap.get(candName) || null;
      if (!storedCandidate || storedCandidate.status !== 'frozen') {
        rawCodes.push('INVALID_LINEAGE');
      } else {
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

    // Latency extraction
    let candidateLatency = null;
    const latVal = latencies && typeof latencies === 'object' ? latencies[candName] : undefined;
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
        const pred = r.predictions[candName];
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
        const isCorrect = r.predictions[candName] === r.label ? 1 : 0;
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

    // Floors & Limits
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
      name: candName,
      aggregate: aggregateAcc,
      slices: sliceAccs,
      totalBytes: recomputedBytes,
      latencyMs: candidateLatency,
      admitted: admitted,
      reasonCodes: reasonCodes
    });
  }

  // Sort results by candidateOrder
  const orderMap = new Map();
  if (policyValid && policy.candidateOrder) {
    policy.candidateOrder.forEach((name, idx) => orderMap.set(name, idx));
  }

  results.sort((a, b) => {
    const idxA = orderMap.has(a.name) ? orderMap.get(a.name) : Infinity;
    const idxB = orderMap.has(b.name) ? orderMap.get(b.name) : Infinity;
    if (idxA !== idxB) return idxA - idxB;
    return compareUtf8(a.name, b.name);
  });

  // Select Winner
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

  return sendJson(res, 200, {
    freezeId: freezeId,
    selected: selected,
    results: results,
    packageManifest: packageManifest
  });
}

// --- Server Routing ---

const server = http.createServer((req, res) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = reqUrl.pathname.replace(/\/$/, '') || '/';

  // Health check endpoint for Render probes
  if (req.method === 'GET' && (pathname === '/' || pathname === '/quantize')) {
    return sendJson(res, 200, { status: 'ok' });
  }

  if (req.method === 'POST' && pathname === '/quantize') {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));

    req.on('end', () => {
      let body;
      try {
        const rawString = Buffer.concat(chunks).toString('utf8');
        body = JSON.parse(rawString);
      } catch (e) {
        return sendJson(res, 400, { error: 'INVALID_INPUT' });
      }

      if (!body || typeof body !== 'object' || Array.isArray(body) || !isNonEmptyString(body.phase)) {
        return sendJson(res, 400, { error: 'INVALID_INPUT' });
      }

      if (body.phase === 'freeze') {
        return handleFreeze(body, res);
      } else if (body.phase === 'select') {
        return handleSelect(body, res);
      } else {
        return sendJson(res, 400, { error: 'INVALID_INPUT' });
      }
    });
  } else {
    sendJson(res, 404, { error: 'NOT_FOUND' });
  }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Quantize API listening on port ${PORT}`);
});
