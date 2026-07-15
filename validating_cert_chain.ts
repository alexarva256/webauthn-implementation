
import { X509Certificate } from 'node:crypto';

/**
 * Validates an x5c certificate chain against a trusted root.
 * * @param x5cArray Array of base64 encoded strings from the JWT header
 * @param rootPem The trusted root certificate in PEM format
 * @returns The leaf certificate if valid, throws an error if invalid
 */
export function validateFidoMdsChain(x5cArray: string[], rootPem: string): X509Certificate {
    if (!x5cArray || x5cArray.length === 0) {
        throw new Error("x5c chain is empty or missing.");
    }

    // 1. Parse the certificates
    // x5c is base64 encoded DER. We convert it to a buffer for X509Certificate.
    const chain = x5cArray.map(certStr => {
        const derBuffer = Buffer.from(certStr, 'base64');
        return new X509Certificate(derBuffer);
    });

    const trustedRoot = new X509Certificate(rootPem);
    
    // Add the trusted root to the end of our working chain for validation
    chain.push(trustedRoot);

    // 2. Validate the chain from Leaf (0) up to the Root (n)
    for (let i = 0; i < chain.length - 1; i++) {
        const currentCert = chain[i];
        const issuerCert = chain[i + 1];

        // Check if the current cert is currently valid (dates)
        const now = new Date().getTime();
        const validFrom = new Date(currentCert.validFrom).getTime();
        const validTo = new Date(currentCert.validTo).getTime();

        if (now < validFrom || now > validTo) {
            throw new Error(`Certificate expired or not yet valid: ${currentCert.subject}`);
        }

        // Verify the cryptographic signature of the current cert using the issuer's public key
        if (!currentCert.verify(issuerCert.publicKey)) {
            throw new Error(`Signature validation failed between ${currentCert.subject} and ${issuerCert.subject}`);
        }

        // If we are looking at an intermediate (not the leaf), ensure it is allowed to act as a CA
        // FIDO rules: The leaf (i=0) is not a CA. Intermediates (i>0) must be CAs.
        if (i > 0 && !currentCert.ca) {
            throw new Error(`Intermediate certificate is not a valid CA: ${currentCert.subject}`);
        }
    }

    // 3. Verify the final issuer matches our trusted root exactly
    const lastCertInChain = chain[chain.length - 1];
    if (lastCertInChain.fingerprint256 !== trustedRoot.fingerprint256) {
        throw new Error("The chain does not terminate at the expected GlobalSign Trusted Root.");
    }

    // Return the leaf certificate so you can extract its public key to verify the JWT payload
    return chain[0]; 
}