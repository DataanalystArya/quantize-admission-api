# Quantize Admission API (`quantize-admission-api`)

A two-phase candidate admission service for quantized model artifacts.

## Endpoints

- `POST /quantize`
  - Accepts JSON with `"phase": "freeze"` or `"phase": "select"`.

## Local Run

```bash
npm install
npm start
