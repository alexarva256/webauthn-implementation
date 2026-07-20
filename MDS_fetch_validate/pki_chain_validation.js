import * as pkijs from "pkijs";

/**
 * Verifies an x5c certificate chain against a trusted root.
 * 
 * @param {Object} params - The certificate chain components.
 * @param {ArrayBuffer} params.trustedRoot - The root CA certificate in BER/DER format.
 * @param {ArrayBuffer} params.leaf - The end-entity certificate in BER/DER format.
 * @param {ArrayBuffer[]} [params.intermediates=[]] - Array of intermediate certificates in BER/DER format.
 * @returns {Promise<boolean>} True if the chain is valid, false otherwise.
 * 
 */

export async function verifyCertificateChain({ trustedRoot, leaf, intermediates = [] }) {
  try {
  
    const rootCa = pkijs.Certificate.fromBER(trustedRoot);
    const leafCert = pkijs.Certificate.fromBER(leaf);
    const intermediateCerts = intermediates.map(cert => pkijs.Certificate.fromBER(cert));

    const chainEngine = new pkijs.CertificateChainValidationEngine({
      trustedCerts: [rootCa],
      certs: [rootCa, ...intermediateCerts, leafCert],
      checkDate: new Date(),
    });

    const verification = await chainEngine.verify();

    return verification.result === true;

  } catch (error) {
    console.error("Certificate verification error:", error.message);
    return false;
  }
}