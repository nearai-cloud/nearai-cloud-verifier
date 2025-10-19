#!/usr/bin/env node
/**
 * TypeScript implementation of NEAR AI Cloud TEE Attestation Verifier
 * Straightforward walkthrough for checking a NEAR AI Cloud attestation.
 */

import * as crypto from 'crypto';

import {
  js_verify,
  js_get_collateral,
} from "../pkg/node/dcap-qvl-node";

const API_BASE = "https://925329ea381059053dde74a7325ad43ef35ee179-3000.dstack-pha-prod8.phala.network"; // "https://cloud-api.near.ai";
const GPU_VERIFIER_API = "https://nras.attestation.nvidia.com/v3/attest/gpu";
const PHALA_TDX_VERIFIER_API = "https://cloud-api.phala.network/api/v1/attestations/verify";
const SIGSTORE_SEARCH_BASE = "https://search.sigstore.dev/?hash=";

interface AttestationReport {
  signing_address: string;
  intel_quote: string;
  nvidia_payload: string;
  info: {
    tcb_info: string | {
      app_compose: string;
    };
  };
  signing_algo?: string;
  all_attestations?: AttestationReport[];
  model_attestations?: AttestationReport[];
  gateway_attestation?: AttestationReport;
}

interface IntelResult {
  quote: {
    body: {
      reportdata: string;
      mrconfig: string;
    };
    verified: boolean;
    message?: string;
  };
  message?: string;
}

interface NvidiaPayload {
  nonce: string;
}

interface NvidiaResponse {
  x_nvidia_overall_att_result: string;
}

interface ReportDataResult {
  binds_address: boolean;
  embeds_nonce: boolean;
}

interface GpuResult {
  nonce_matches: boolean;
  verdict: string;
}

/**
 * Make HTTP request and return JSON response
 */
async function makeRequest(url: string, options: any = {}): Promise<any> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.timeout || 30000);

  try {
    const response = await fetch(url, {
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.NEAR_AI_CLOUD_API_KEY}`,
        ...options.headers,
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    clearTimeout(timeoutId);
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error('Request timeout');
    }
    throw error;
  }
}

/**
 * Fetch attestation report from the API
 */
async function fetchReport(model: string, nonce: string): Promise<AttestationReport> {
  const url = `${API_BASE}/v1/attestation/report?model=${encodeURIComponent(model)}&nonce=${nonce}`;
  return await makeRequest(url);
}

/**
 * Submit GPU evidence to NVIDIA NRAS for verification
 */
async function fetchNvidiaVerification(payload: NvidiaPayload): Promise<any> {
  return await makeRequest(GPU_VERIFIER_API, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });
}

/**
 * Decode the payload section of a JWT token
 */
function base64urlDecodeJwtPayload(jwtToken: string): string {
  const payloadB64 = jwtToken.split('.')[1];
  const padded = payloadB64 + '='.repeat((4 - payloadB64.length % 4) % 4);
  return Buffer.from(padded, 'base64url').toString('utf-8');
}

/**
 * Verify that TDX report data binds the signing address and request nonce
 */
function checkReportData(attestation: AttestationReport, requestNonce: string, intelResult: IntelResult): ReportDataResult {
  const reportDataHex = intelResult.quote.body.reportdata;
  const reportData = Buffer.from(reportDataHex.replace('0x', ''), 'hex');
  const signingAddress = attestation.signing_address;
  const signingAlgo = (attestation.signing_algo || 'ecdsa').toLowerCase();

  // Parse signing address bytes based on algorithm
  let signingAddressBytes: Buffer;
  if (signingAlgo === 'ecdsa') {
    const addrHex = signingAddress.replace('0x', '');
    signingAddressBytes = Buffer.from(addrHex, 'hex');
  } else {
    signingAddressBytes = Buffer.from(signingAddress, 'hex');
  }

  const embeddedAddress = reportData.subarray(0, 32);
  const embeddedNonce = reportData.subarray(32);

  const bindsAddress = embeddedAddress.equals(Buffer.concat([signingAddressBytes, Buffer.alloc(32 - signingAddressBytes.length, 0)]));
  const embedsNonce = embeddedNonce.toString('hex') === requestNonce;

  console.log('Signing algorithm:', signingAlgo);
  console.log('Report data binds signing address:', bindsAddress);
  console.log('Report data embeds request nonce:', embedsNonce);

  return {
    binds_address: bindsAddress,
    embeds_nonce: embedsNonce
  };
}

/**
 * Verify GPU attestation evidence via NVIDIA NRAS
 */
async function checkGpu(attestation: AttestationReport, requestNonce: string): Promise<GpuResult> {
  const payload: NvidiaPayload = JSON.parse(attestation.nvidia_payload);

  // Verify GPU uses the same request_nonce
  const nonceMatches = payload.nonce.toLowerCase() === requestNonce.toLowerCase();
  console.log('GPU payload nonce matches request_nonce:', nonceMatches);

  const body = await fetchNvidiaVerification(payload);
  const jwtToken = body[0][1];
  const verdict = JSON.parse(base64urlDecodeJwtPayload(jwtToken))['x-nvidia-overall-att-result'];
  console.log('NVIDIA attestation verdict:', verdict);

  return {
    nonce_matches: nonceMatches,
    verdict: verdict
  };
}

/**
 * Verify Intel TDX quote via Phala's verification service
 */
async function checkTdxQuoteRemote(attestation: AttestationReport): Promise<IntelResult> {

  console.log('Checking Intel TDX quote via NEAR AI Cloud\'s verification service');
  console.log('Intel TDX quote:', attestation.intel_quote);

  const intelResult: IntelResult = await makeRequest(PHALA_TDX_VERIFIER_API, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ hex: attestation.intel_quote })
  });

  const payload = intelResult.quote || {};
  const verified = payload.verified;

  console.log('Intel TDX quote verified:', verified);
  const message = payload.message || intelResult.message;
  if (message) {
    console.log('Intel TDX verifier message:', message);
  }

  return intelResult;
}


async function checkTdxQuoteLocal(attestation: AttestationReport): Promise<IntelResult> {

  console.log('Checking Intel TDX quote via NEAR AI Cloud\'s verification service');
  console.log('Intel TDX quote:', attestation.intel_quote);

  // const intelResult: IntelResult = await makeRequest(PHALA_TDX_VERIFIER_API, {
  //   method: 'POST',
  //   headers: {
  //     'Content-Type': 'application/json'
  //   },
  //   body: JSON.stringify({ hex: attestation.intel_quote })
  // });

  // const payload = intelResult.quote || {};
  // const verified = payload.verified;

  // console.log('Intel TDX quote verified:', verified);
  // const message = payload.message || intelResult.message;
  // if (message) {
  //   console.log('Intel TDX verifier message:', message);
  // }

  // return intelResult;

  try {
    const rawQuote = Buffer.from(attestation.intel_quote, 'hex');
    // Current timestamp
    const now = BigInt(Math.floor(Date.now() / 1000));

    // Call the js_verify function
    let pccs_url = "https://pccs.phala.network/tdx/certification/v4";
    const quoteCollateral = await js_get_collateral(pccs_url, rawQuote);
    const intelResult = js_verify(rawQuote, quoteCollateral, now);
    console.log("Verification Result:", intelResult);

    const payload = intelResult.quote || {};
    const verified = payload.verified;

    console.log('Intel TDX quote verified:', verified);
    const message = payload.message || intelResult.message;
    if (message) {
      console.log('Intel TDX verifier message:', message);
    }
  
    return intelResult;
  } catch (error) {
    console.error("Verification failed:", error);
    throw error;
  }
}

const checkTdxQuote = checkTdxQuoteLocal;

/**
 * Extract all @sha256:xxx image digests and return Sigstore search links
 */
function extractSigstoreLinks(compose: string): string[] {
  if (!compose) {
    return [];
  }

  // Match @sha256:hexdigest pattern in Docker compose
  const pattern = /@sha256:([0-9a-f]{64})/g;
  const digests: string[] = [];
  let match;

  while ((match = pattern.exec(compose)) !== null) {
    digests.push(match[1]);
  }

  // Deduplicate digests while preserving order
  const seen = new Set<string>();
  const uniqueDigests: string[] = [];
  for (const digest of digests) {
    if (!seen.has(digest)) {
      seen.add(digest);
      uniqueDigests.push(digest);
    }
  }

  return uniqueDigests.map(digest => `${SIGSTORE_SEARCH_BASE}sha256:${digest}`);
}

/**
 * Check that Sigstore links are accessible (not 404)
 */
async function checkSigstoreLinks(links: string[]): Promise<Array<[string, boolean, number | string]>> {
  const results: Array<[string, boolean, number | string]> = [];
  
  for (const link of links) {
    try {
      const response = await makeRequest(link, { method: 'HEAD' });
      const accessible = response.status < 400;
      results.push([link, accessible, response.status]);
    } catch (error) {
      results.push([link, false, error instanceof Error ? error.message : String(error)]);
    }
  }
  
  return results;
}

/**
 * Extract and display Sigstore provenance links from attestation
 */
async function showSigstoreProvenance(attestation: AttestationReport): Promise<void> {
  let tcbInfo = attestation.info.tcb_info;
  if (typeof tcbInfo === 'string') {
    tcbInfo = JSON.parse(tcbInfo);
  }
  
  const compose = (tcbInfo as any).app_compose;
  if (!compose) {
    return;
  }

  const sigstoreLinks = extractSigstoreLinks(compose);
  if (sigstoreLinks.length === 0) {
    return;
  }

  console.log('\n🔐 Sigstore provenance');
  console.log('Checking Sigstore accessibility for container images...');
  const linkResults = await checkSigstoreLinks(sigstoreLinks);

  for (const [link, accessible, status] of linkResults) {
    if (accessible) {
      console.log(`  ✓ ${link} (HTTP ${status})`);
    } else {
      console.log(`  ✗ ${link} (HTTP ${status})`);
    }
  }
}

/**
 * Display the Docker compose manifest and verify against mr_config from verified quote
 */
function showCompose(attestation: AttestationReport, intelResult: IntelResult): void {
  let tcbInfo = attestation.info.tcb_info;
  if (typeof tcbInfo === 'string') {
    tcbInfo = JSON.parse(tcbInfo);
  }
  
  const appCompose = (tcbInfo as any).app_compose;
  if (!appCompose) {
    return;
  }
  
  const dockerCompose = JSON.parse(appCompose).docker_compose_file;
  
  console.log('\nDocker compose manifest attested by the enclave:');
  console.log(dockerCompose);

  const composeHash = crypto.createHash('sha256').update(appCompose).digest('hex');
  console.log('Compose sha256:', composeHash);

  const mrConfig = intelResult.quote.body.mrconfig;
  console.log('mr_config (from verified quote):', mrConfig);
  const expectedMrConfig = '0x01' + composeHash;
  console.log('mr_config matches compose hash:', mrConfig.toLowerCase().startsWith(expectedMrConfig.toLowerCase()));
}

/**
 * Main verification function
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const modelIndex = args.indexOf('--model');
  const model = modelIndex !== -1 && args[modelIndex + 1] ? args[modelIndex + 1] : 'gpt-oss-120b';


  if (!process.env.NEAR_AI_CLOUD_API_KEY) {
    console.log('Error: NEAR_AI_CLOUD_API_KEY environment variable is required');
    console.log('Set it with: export NEAR_AI_CLOUD_API_KEY=your-api-key');
    return;
  }

  const requestNonce = crypto.randomBytes(32).toString('hex');
  const report = await fetchReport(model, requestNonce);

  if (!report.model_attestations) {
    console.log('No model attestations found');
    return;
  }

  // Verify model attestations
  for (const modelAttestation of report.model_attestations) {
    console.log('\n🔐 Model attestation');
    const intelResultModel = await checkTdxQuoteLocal(modelAttestation);
    console.log('\n🔐 TDX report data');
    checkReportData(modelAttestation, requestNonce, intelResultModel);
    console.log('\n🔐 GPU attestation');
    await checkGpu(modelAttestation, requestNonce);
    showCompose(modelAttestation, intelResultModel);
    await showSigstoreProvenance(modelAttestation);
  }


  if (!report.gateway_attestation) {
    console.log('No gateway attestation found');
    return;
  }

  console.log('\n🔐 Gateway attestation');
  const intelResultGateway = await checkTdxQuoteLocal(report.gateway_attestation);
  console.log('\n🔐 TDX report data');
  checkReportData(report.gateway_attestation, requestNonce, intelResultGateway);
  console.log('\n🔐 GPU attestation');
  await checkGpu(report.gateway_attestation, requestNonce);
  showCompose(report.gateway_attestation, intelResultGateway);
  await showSigstoreProvenance(report.gateway_attestation);


  // // Handle both single attestation and multi-node response formats
  // const attestation = report.all_attestations ? report.all_attestations[0] : report;

  // console.log('\nSigning address:', attestation.signing_address);
  // console.log('Request nonce:', requestNonce);

  // console.log('\n🔐 Intel TDX quote');
  // const intelResult = await checkTdxQuoteLocal(attestation);

  // console.log('\n🔐 TDX report data');
  // checkReportData(attestation, requestNonce, intelResult);

  // console.log('\n🔐 GPU attestation');
  // await checkGpu(attestation, requestNonce);

  // showCompose(attestation, intelResult);
  // await showSigstoreProvenance(attestation);
}

// Run the main function if this file is executed directly
if (require.main === module) {
  main().catch(console.error);
}

export {
  fetchReport,
  checkTdxQuote,
  checkReportData,
  checkGpu,
  showSigstoreProvenance,
  showCompose,
  AttestationReport,
  IntelResult,
  ReportDataResult,
  GpuResult
};
