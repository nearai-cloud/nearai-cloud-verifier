# TypeScript Verifiers

TypeScript implementations of NEAR AI Cloud cryptographic verification tools.

## Installation

```bash
npm install
```

## Build

```bash
npm run build
```

## Usage

### Attestation Verification (No API Key)

```bash
npm run attestation -- --model deepseek-v3.1
```

### Signature Verification (Requires API Key)

```bash
export API_KEY=sk-your-api-key-here
npm run signature -- --model deepseek-v3.1
```

## Programmatic Usage

```typescript
import {
  fetchReport,
  checkTdxQuote,
  checkReportData,
  checkGpu,
  showSigstoreProvenance
} from 'nearai-cloud-verifier';

// Generate fresh nonce
const nonce = crypto.randomBytes(32).toString('hex');

// Fetch attestation
const attestation = await fetchReport('deepseek-v3.1', nonce);

// Verify all components
const intelResult = await checkTdxQuote(attestation);
checkReportData(attestation, nonce, intelResult);
await checkGpu(attestation, nonce);
await showSigstoreProvenance(attestation);
```

## Features

- 🔐 **TEE Attestation Verification** - Cryptographic proof of genuine hardware
- 🛡️ **GPU TEE Verification** - NVIDIA H100/H200 attestation via NRAS
- ✅ **Intel TDX Quote Validation** - Verify CPU TEE measurements
- 🔑 **ECDSA Signature Verification** - Validate signed AI responses
- 📦 **Sigstore Provenance** - Container supply chain verification
- 🌐 **Multi-Server Support** - Load balancer attestation aggregation
