// src/pages/api/r2-proxy.js

import { getSecret } from "astro:env/server";

export async function GET(context) {
  // Get credentials from environment variables

  // const {env} = context.locals.runtime;
  // eslint-disable-next-line no-undef
  // const { env } = Astro.locals.runtime;

  // eslint-disable-next-line no-undef
  // const AWS_ACCESS_KEY = import.meta.env.AWS_ACCESS_KEY || env.AWS_ACCESS_KEY;
  // const AWS_SECRET_KEY = import.meta.env.AWS_SECRET_KEY || env.AWS_SECRET_KEY;
  const AWS_ACCESS_KEY = getSecret('AWS_ACCESS_KEY');
  const AWS_SECRET_KEY = getSecret('AWS_SECRET_KEY');
  const AWS_REGION = 'auto'; // Cloudflare R2 uses 'auto'
  const SERVICE = 's3';
  const BUCKET_URL = 'https://237a43809f6504a9698c74f7644dfcc8.r2.cloudflarestorage.com/luan-assets';

  if (!AWS_ACCESS_KEY || !AWS_SECRET_KEY) {
    return new Response('Missing AWS credentials in environment variables', { status: 500 });
  }

  try {
    // Create AWS Signature Version 4
    const authHeaders = await createAwsSignature({
      method: 'GET',
      url: BUCKET_URL,
      accessKey: AWS_ACCESS_KEY,
      secretKey: AWS_SECRET_KEY,
      region: AWS_REGION,
      service: SERVICE
    });

    // Make authenticated request to R2
    const response = await fetch(BUCKET_URL, {
      method: 'GET',
      headers: authHeaders
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('R2 Response Error:', response.status, errorText);
      return new Response(`R2 Error: ${response.status} - ${errorText}`, { status: response.status });
    }

    const xmlText = await response.text();

    // Return XML with CORS headers
    return new Response(xmlText, {
      status: 200,
      headers: {
        'Content-Type': 'application/xml',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET',
        'Access-Control-Allow-Headers': 'Content-Type'
      }
    });

  } catch (error) {
    console.error('R2 Proxy Error:', error);
    return new Response(`Server Error: ${error.message}`, { status: 500 });
  }
}

// Improved AWS Signature Version 4 implementation
async function createAwsSignature({ method, url, accessKey, secretKey, region, service }) {
  const urlObj = new URL(url);
  const host = urlObj.host;
  const path = urlObj.pathname || '/';
  const query = urlObj.search.slice(1) || '';

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);

  // Step 1: Create canonical request
  const canonicalUri = encodeURI(path).replace(/\+/g, '%20');
  const canonicalQueryString = query;
  const payloadHash = await sha256('');
  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash
  ].join('\n');

  // Step 2: Create string to sign
  const algorithm = 'AWS4-HMAC-SHA256';
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    await sha256(canonicalRequest)
  ].join('\n');

  // Step 3: Calculate signature
  const signingKey = await getSignatureKey(secretKey, dateStamp, region, service);
  const signature = await hmacSha256Hex(signingKey, stringToSign);

  // Step 4: Create authorization header
  const authorizationHeader = `${algorithm} Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    'Authorization': authorizationHeader,
    'X-Amz-Date': amzDate,
    'X-Amz-Content-Sha256': await sha256(''),
    'Host': host
  };
}

// Crypto helper functions
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hmacSha256(key, message) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(message));
  return new Uint8Array(signature);
}

async function hmacSha256Hex(key, message) {
  const signature = await hmacSha256(key, message);
  return Array.from(signature)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function getSignatureKey(key, dateStamp, regionName, serviceName) {
  const kDate = await hmacSha256(new TextEncoder().encode('AWS4' + key), dateStamp);
  const kRegion = await hmacSha256(kDate, regionName);
  const kService = await hmacSha256(kRegion, serviceName);
  const kSigning = await hmacSha256(kService, 'aws4_request');
  return kSigning;
}