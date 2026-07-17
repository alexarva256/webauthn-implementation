const http = require('http');
const fs = require('fs').promises;
const path = require('path');
const cbor = require('cbor');
const crypto = require('crypto');

let memoryCache = { data: null, serialNumber: null };

/*
Helper functions for converting between ArrayBuffer and Base64URL strings,
as well as formatting certificates as PEM.
*/
const BLOB_LOCAL_PATH = path.join(__dirname, 'blob.jwt');
const JSON_LOCAL_PATH = path.join(__dirname, 'cache.json');
const FIDO_MDS_URL = 'http://localhost:8080/'; // Local MDS server URL for testing
const TWO_WEEKS_MS = 14 * 24 * 60 * 60 * 1000;


function formatAsPEM(buffer) {
	let binary = '';
	const bytes = new Uint8Array(buffer);
	for (let i = 0; i < bytes.byteLength; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	const base64 = window.btoa(binary);
	const formattedB64 = base64.match(/.{1,64}/g).join('\n');
	return `-----BEGIN CERTIFICATE-----\n${formattedB64}\n-----END CERTIFICATE-----`;
}

function bufferToBase64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
	.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64URLStringToBuffer(base64URLString) {
	const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
	const padLen = (4 - (base64.length % 4)) % 4;
	const padded = base64.padEnd(base64.length + padLen, '=');
	const binary = atob(padded);
	const buffer = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		buffer[i] = binary.charCodeAt(i);
	}
	return buffer;
}

function decodeFidoBlob(rawBlob) {
	const parts = rawBlob.trim().split('.');
	if (parts.length !== 3) throw new Error("Invalid BLOB format.");
	return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
}


async function refreshFidoMdsCache() {
	const fetchOptions = { method: 'GET', headers: {} };

	if (memoryCache.serialNumber) fetchOptions.headers['If-None-Match'] = memoryCache.serialNumber;

	try {

		const response = await fetch(FIDO_MDS_URL, fetchOptions);
		if (response.status === 304) return;
		if (!response.ok) throw new Error(`MDS responded with HTTP ${response.status}`);
		const rawBlob = await response.text();
		const etag = response.headers.get('ETag');
		const parsedJwt = decodeFidoBlob(rawBlob);

		memoryCache.data = parsedJwt.entries;
		memoryCache.serialNumber = etag ? etag.replace(/"/g, '') : null;


		await fs.writeFile(BLOB_LOCAL_PATH, rawBlob, 'utf8');
		await fs.writeFile(JSON_LOCAL_PATH, JSON.stringify({serialNumber: memoryCache.serialNumber, nextFetchDue: Date.now() + TWO_WEEKS_MS}), 'utf8');
	
	} catch (error) {

	if (!memoryCache.data) await tryLoadingFromDiskBackup();

	}
}


async function tryLoadingFromDiskBackup() {

	try {

		const rawBlob = await fs.readFile(BLOB_LOCAL_PATH, 'utf8');
		const rawConfig = await fs.readFile(JSON_LOCAL_PATH, 'utf8');
		memoryCache.data = decodeFidoBlob(rawBlob).entries;
		memoryCache.serialNumber = JSON.parse(rawConfig).serialNumber;

	}
	catch (err) { console.log("First initialization run required."); }

}


async function initializeFidoBackendStore() {

	let nextFetchDue = 0;

	try { nextFetchDue = JSON.parse(await fs.readFile(JSON_LOCAL_PATH, 'utf8')).nextFetchDue || 0; } catch (e) {}

	await tryLoadingFromDiskBackup();

	if (Date.now() >= nextFetchDue || !memoryCache.data) {

		await refreshFidoMdsCache();

	}

}

function validateDeviceAttestationChain(deviceX5cBase64Array, mdsRootsBase64Array) {
    if (!deviceX5cBase64Array || deviceX5cBase64Array.length === 0) {
        throw new Error("No x5c chain provided by the device.");
    }

    if (!mdsRootsBase64Array || mdsRootsBase64Array.length === 0) {
        throw new Error("No MDS root certificates available for this AAGUID.");
    }

    const deviceChain = deviceX5cBase64Array.map(certStr => {
        return new crypto.X509Certificate(Buffer.from(certStr, 'base64'));
    });
    
    const leafCert = deviceChain[0];
    const now = Date.now();

    let chainVerified = false;
    let lastError = null;

    for (const mdsRootStr of mdsRootsBase64Array) {
        try {
            const trustedRoot = new crypto.X509Certificate(Buffer.from(mdsRootStr, 'base64'));
            
            const testChain = [...deviceChain, trustedRoot];

            for (const cert of testChain) {
                if (now < new Date(cert.validFrom).getTime() || now > new Date(cert.validTo).getTime()) {
                    throw new Error(`Certificate expired or not yet valid: ${cert.subject}`);
                }
            }

            for (let i = 0; i < testChain.length - 1; i++) {
                const currentCert = testChain[i];
                const issuerCert = testChain[i + 1];

                if (currentCert.issuer !== issuerCert.subject) {
                    throw new Error(`Chain broken: ${currentCert.subject} was not issued by ${issuerCert.subject}`);
                }

                if (!currentCert.verify(issuerCert.publicKey)) {
                    throw new Error(`Signature validation failed for: ${currentCert.subject}`);
                }
            }

            chainVerified = true;
            break; 

        } catch (err) {
            lastError = err;
            continue; 
        }
    }

    if (!chainVerified) {
        throw new Error(`Device certificate chain rejected by MDS roots. Last error: ${lastError.message}`);
    }

    return leafCert;
}


initializeFidoBackendStore();

const server = http.createServer(async (req, res) => {

	res.setHeader('Access-Control-Allow-Origin', '*');
	res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
	res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, POST');

	if (req.method === 'OPTIONS') {

		res.writeHead(200);
		return res.end();
	}

	if (req.method === 'POST' && req.url === '/api/register') {
	    let body = '';
	    req.on('data', chunk => { body += chunk; });
	    req.on('end', () => {
	        try {
	            const { username, credentialId, x5c, aaguid, clientDataJSON, attestationObject } = JSON.parse(body);
			
	            if (!memoryCache.data) {
	                res.writeHead(500, { 'Content-Type': 'application/json' });
	                return res.end(JSON.stringify({ error: 'MDS Store uninitialized' }));
	            }

	            const mdsEntry = memoryCache.data[aaguid] || memoryCache.data.find(entry => entry.aaguid === aaguid);

	            if (!mdsEntry || !mdsEntry.metadataStatement) {
	                throw new Error("AAGUID not found in FIDO MDS. Device is unverified or non-compliant.");
	            }

	            const mdsStatement = mdsEntry.metadataStatement;
	            const mdsRoots = mdsStatement.attestationRootCertificates;
	            const deviceName = mdsStatement.description || "Unknown Legitimate Authenticator";

	            const leafCertificate = validateDeviceAttestationChain(x5c, mdsRoots);

				const clientDataBuffer = Buffer.from(clientDataJSON, 'base64url');
				const attObjBuffer = Buffer.from(attestationObject, 'base64url');

				const clientDataHash = crypto.createHash('sha256').update(clientDataBuffer).digest();

				const decodedAttObj = cbor.decodeFirstSync(attObjBuffer);
				const authData = decodedAttObj.authData;
				const attStmt = decodedAttObj.attStmt;

				if (!attStmt.sig) {
				    throw new Error("No signature found in attestation statement.");
				}

				const signedData = Buffer.concat([authData, clientDataHash]);

				let hashAlg;
				if (attStmt.alg === -7) {
				    hashAlg = 'SHA256';
				} else if (attStmt.alg === -257) {
				    hashAlg = 'SHA256'; 
				} else {
				    hashAlg = 'SHA256'; 
				}

				const isValidSignature = crypto.verify(
				    hashAlg,
				    signedData,
				    leafCertificate.publicKey,
				    attStmt.sig
				);

				if (!isValidSignature) {
				    throw new Error("SECURITY ALERT: Attestation signature verification failed. Possible tampering or cloned device.");
				}

				console.log("Proof of Possession verified! The device genuinely holds the private key.");
			
	            res.writeHead(200, { 'Content-Type': 'application/json' });
	            res.end(JSON.stringify({ 
	                success: true,
	                message: `Successfully verified genuine device: ${deviceName}` 
	            }));

	    	} catch (err) {
	    	    console.log("Attestation failure:", err.message);
	    	    res.writeHead(400, { 'Content-Type': 'application/json' });
	    	    res.end(JSON.stringify({ error: err.message }));
	    	}
	    });

	}

});

server.listen(4000, () => console.log('Backend listening on http://localhost:4000'));