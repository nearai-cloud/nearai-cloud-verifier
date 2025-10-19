# nearai-cloud-verifier
NEAR AI Cloud Verifier

**Cryptographic Verification Tools for NEAR AI Cloud TEE-Protected AI**

Python tools for validating NEAR AI Cloud attestation reports and response signatures. These verifiers provide cryptographic proof that your AI requests are processed in genuine Trusted Execution Environments (TEE) with hardware-enforced privacy.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)

## 🌟 Features

- 🔐 **TEE Attestation Verification** - Cryptographic proof of genuine hardware
- 🛡️ **GPU TEE Verification** - NVIDIA H100/H200 attestation via NRAS
- ✅ **Intel TDX Quote Validation** - Verify CPU TEE measurements
- 🔑 **ECDSA Signature Verification** - Validate signed AI responses
- 📦 **Sigstore Provenance** - Container supply chain verification
- 🌐 **Multi-Server Support** - Load balancer attestation aggregation

## 📋 Requirements

- Python 3.10+
- `requests`, `eth-account`
- NEAR AI Cloud API key from [cloud.near.ai](https://cloud.near.ai) (for signature verifier only)

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/nearai-cloud/nearai-cloud-verifier.git
cd nearai-cloud-verifier

# Install dependencies
pip install requests eth-account
```

### Attestation Verification (No API Key)

```bash
python3 attestation_verifier.py --model phala/deepseek-chat-v3-0324
```

### Signature Verification (Requires API Key)

```bash
export API_KEY=sk-your-api-key-here
python3 signature_verifier.py --model phala/deepseek-chat-v3-0324
```

## 🔐 Attestation Verifier

Generates a fresh nonce, requests a new attestation, and verifies:
- **GPU attestation**: Submits GPU evidence payload to NVIDIA NRAS and verifies the nonce matches
- **TDX report data**: Validates that report data binds the signing key (ECDSA or Ed25519) and nonce
- **Intel TDX quote**: Verifies TDX quote via NEAR AI Cloud's verification service
- **Compose manifest**: Displays Docker compose manifest and verifies it matches the mr_config measurement

### Usage

```bash
python3 attestation_verifier.py [--model MODEL_NAME]
```

**Default model**: `phala/deepseek-chat-v3-0324`

No API key required. The verifier fetches attestations from the public `/v1/attestation/report` endpoint.

### Example Output

```
Signing address: 0x1234...
Request nonce: abc123...

🔐 TDX report data
Signing algorithm: ecdsa
Report data binds signing address: True
Report data embeds request nonce: True

🔐 GPU attestation
GPU payload nonce matches request_nonce: True
NVIDIA attestation verdict: PASS

🔐 Intel TDX quote
Intel TDX quote verified: True

Docker compose manifest attested by the enclave:
version: '3.8'
services:
  model:
    image: phala/deepseek@sha256:77fbe5f...
    ...

Compose sha256: abc123...
mr_config (from verified quote): 0x01abc123...
mr_config matches compose hash: True

🔐 Sigstore provenance
Checking Sigstore accessibility for container images...
  ✓ https://search.sigstore.dev/?hash=sha256:77fbe5f... (HTTP 200)
```

### What It Verifies

✅ **GPU TEE Measurements** - Proves genuine NVIDIA H100/H200 TEE
✅ **Model Hash** - Verifies exact model version
✅ **Code Hash** - Confirms inference code integrity
✅ **Nonce Freshness** - Prevents replay attacks
✅ **Cryptographic Binding** - Signing key bound to hardware
✅ **Container Provenance** - Verifies build supply chain

## 🔑 Signature Verifier

Fetches chat completions (streaming and non-streaming), verifies ECDSA signatures, and validates attestations:

1. Sends chat completion request to `/v1/chat/completions`
2. Fetches signature from `/v1/signature/{chat_id}` endpoint
3. Verifies request hash and response hash match the signed hashes
4. Recovers ECDSA signing address from signature
5. Fetches fresh attestation with user-supplied nonce for the recovered signing address
6. Validates attestation using the same checks as attestation verifier

**Note**: The verifier supplies a fresh nonce when fetching attestation (step 5), which ensures attestation freshness but means the nonce/report_data won't match the original signing context. This is expected behavior - the verifier proves the signing key is bound to valid hardware, not that a specific attestation was used for signing.

### Setup

Set your API key as an environment variable:

```bash
export API_KEY=sk-your-api-key-here
```

Or create a `.env` file:

```bash
API_KEY=sk-your-api-key-here
```

Then run:

```bash
python3 signature_verifier.py [--model MODEL_NAME]
```

**Default model**: `phala/deepseek-chat-v3-0324`

### What It Verifies

✅ **Request Body Hash** - Matches server-computed hash
✅ **Response Text Hash** - Matches server-computed hash
✅ **ECDSA Signature** - Valid and recovers to claimed signing address
✅ **Signing Address Binding** - Bound to hardware via TDX report data
✅ **GPU Attestation** - Passes NVIDIA verification
✅ **Intel TDX Quote** - Valid CPU TEE measurements

## 📦 Sigstore Provenance

Both scripts automatically extract all container image digests from the Docker compose manifest (matching `@sha256:xxx` patterns) and verify Sigstore accessibility for each image. This allows you to:

1. Verify the container images were built from the expected source repository
2. Review the GitHub Actions workflow that built the images
3. Audit the build provenance and supply chain metadata

The verifiers check each Sigstore link with an HTTP HEAD request to ensure provenance data is available (not 404).

### Example Output

```
🔐 Sigstore provenance
Checking Sigstore accessibility for container images...
  ✓ https://search.sigstore.dev/?hash=sha256:77fbe5f... (HTTP 200)
  ✓ https://search.sigstore.dev/?hash=sha256:abc123... (HTTP 200)
```

If a link returns ✗, the provenance data may not be available in Sigstore (either the image wasn't signed or the digest is incorrect).

## 🌐 Multi-Server Load Balancer Setup

In production deployments with multiple backend servers behind a load balancer:

### Server Behavior

- Each server has its own unique signing key/address
- Attestation requests with `signing_address` parameter return 404 if the address doesn't match
- Response includes `all_attestations: [attestation]` (single-element array with this server's attestation)

### Load Balancer Requirements

When `/v1/attestation/report?signing_address={addr}&nonce={nonce}`:

1. **Broadcast** the request to all backend servers
2. Collect non-404 responses from servers matching the signing_address
3. Merge `all_attestations` arrays from all responses
4. Return combined response with all servers' attestations

### Verifier Flow

1. Get signature → extract `signing_address`
2. Request attestation with `signing_address` parameter
3. LB broadcasts → collect attestations from all servers
4. Verifier finds matching attestation by comparing `signing_address` in `all_attestations`

### Example Response (Multi-Server)

```json
{
  "signing_address": "0xServer1...",
  "intel_quote": "...",
  "all_attestations": [
    {"signing_address": "0xServer1...", "intel_quote": "...", ...},
    {"signing_address": "0xServer2...", "intel_quote": "...", ...}
  ]
}
```

The verifier filters `all_attestations` to find the entry matching the signature's `signing_address`.

## 🔬 Verification Architecture

### Two-Layer TEE Protection

**Layer 1: TEE-Protected Gateway (All Models)**
- Request processing in TEE (Intel TDX)
- Response handling in TEE
- Applies to all 250+ models
- Verified via attestation reports

**Layer 2: TEE-Protected Inference (Phala Models)**
- Model weights in GPU TEE (NVIDIA H100/H200)
- Inference computation in GPU secure enclaves
- Complete end-to-end protection
- Verified via GPU attestation + signature verification

## 🛡️ Trust Model

### You Must Trust

- ✅ NVIDIA GPU vendor (H100/H200 TEE correctness)
- ✅ Intel CPU vendor (TDX implementation)
- ✅ Phala Network (model deployment integrity)
- ✅ Open source code (auditable on GitHub)

### You Do NOT Need to Trust

- ❌ RedPill operators
- ❌ Cloud provider (AWS, GCP, Azure)
- ❌ System administrators
- ❌ Other users on same hardware

### Cryptographic Guarantees

✅ **Hardware-Enforced Privacy** - Data never leaves TEE in plaintext
✅ **Verifiable Execution** - Cryptographic proof of code integrity
✅ **Tamper-Proof** - Cannot be modified by operators or admins
✅ **Auditable** - Full attestation reports for every request

## 📖 Usage Examples

### Basic Attestation Verification

```bash
# Verify default Phala confidential model
python3 attestation_verifier.py

# Verify specific model
python3 attestation_verifier.py --model phala/qwen-2.5-7b-instruct
```

### Signature Verification with Custom Model

```bash
export API_KEY=sk-your-api-key-here
python3 signature_verifier.py --model phala/deepseek-chat-v3-0324
```

### Programmatic Usage

```python
from attestation_verifier import fetch_report, check_tdx_quote, check_gpu, check_report_data
import secrets

# Generate fresh nonce
nonce = secrets.token_hex(32)

# Fetch attestation
attestation = fetch_report("phala/deepseek-chat-v3-0324", nonce)

# Verify all components
intel_result = check_tdx_quote(attestation)
check_report_data(attestation, nonce, intel_result)
check_gpu(attestation, nonce)
```

## 🔗 Integration

### With NEAR AI Cloud Gateway

These verifiers work with [NEAR AI Cloud Gateway](https://github.com/nearai-cloud/nearai-cloud-gateway) attestation endpoints:

- `GET /v1/attestation/report` - Get TEE attestation
- `GET /v1/signature/{chat_id}` - Get response signature

### With NEAR AI Cloud Chat

[NEAR AI Cloud Chat](https://github.com/nearai-cloud/nearai-cloud-chat) uses these verification methods to display TEE status in the UI.

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test with both verifiers
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Attribution

Built with:
- [NVIDIA NRAS](https://nras.attestation.nvidia.com) - GPU TEE attestation service
- [Intel TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) - CPU TEE technology
- [Sigstore](https://www.sigstore.dev/) - Container supply chain verification

Powered by [NEAR AI Cloud Gateway](https://github.com/nearai-cloud/nearai-cloud-gateway) and [Phala Network](https://phala.network) TEE infrastructure.
