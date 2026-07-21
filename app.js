/**
 * UTILITIES AND FORMATTING
*/
const Utils = {
	bufferToBase64url(buffer) {
		return btoa(String.fromCharCode(...new Uint8Array(buffer)))
			.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
	},

	base64URLStringToBuffer(base64URLString) {
		const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
		const padLen = (4 - (base64.length % 4)) % 4;
		const padded = base64.padEnd(base64.length + padLen, '=');
		const binary = atob(padded);
		return Uint8Array.from(binary, c => c.charCodeAt(0)).buffer;
	},

	generateChallenge() {
		return window.crypto.getRandomValues(new Uint8Array(32));
	},

	log(id, text, clear = false) {
		const output = document.getElementById(id);
		if (!output) return;
		if (clear) output.innerText = "";
		output.innerText += text + "\n";
	}
};

function clearLogs(logId) {
    const logElement = document.getElementById(logId);
    if (logElement) logElement.innerHTML = '';
}

/**
*  BACKEND API CALLS
*/

const BackendAPI = {
	/**
	 * Sends the authenticator payload to the server for MDS verification.
	 */

	async verifyRegistration(payload) {
		const response = await fetch('http://localhost:4000/api/register', {
			method: 'POST',
			cors: 'no-cors',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload)
		});

		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(`Backend validation failed: ${errorText}`);
		}
		return await response.json();
	}
};

/**
*  WEBAUTHN REGISTRATION 
*/

async function handleRegistration(username) {

	const logId = 'reg-output';
	clearLogs(logId);
	Utils.log(logId, "Starting Registration...");

	const encryptionSalt = Utils.generateChallenge();

	const publicKey = {
		rp: { name: "Alex made an app", id: window.location.hostname },
		user: {
			id: new TextEncoder().encode(username),
			name: username,
			displayName: username,
		},
		challenge: Utils.generateChallenge(),
		pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
		authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
		timeout: 60000,
		attestation: "direct",
		extensions: { prf: { eval: { first: encryptionSalt } } }
	};

	Utils.log(logId, "Tap your YubiKey...");
	const credential = await navigator.credentials.create({ publicKey });

    Utils.log(logId, "Sending raw attestation data to backend for secure decoding and validation...");
    
    const backendResponse = await BackendAPI.verifyRegistration({
        username,
        credentialId: credential.id,
        clientDataJSON: Utils.bufferToBase64url(credential.response.clientDataJSON),
        attestationObject: Utils.bufferToBase64url(credential.response.attestationObject)
    });
    
    Utils.log(logId, `Backend: ${backendResponse.message}`);

}

/**
 *  UI EVENT LISTENERS
*/

document.getElementById('registerBtn').addEventListener('click', async () => {
	const username = document.getElementById('reg-username').value.trim();
	if (!username) return alert("Enter a username to register.");

	try {
		await handleRegistration(username);
	} catch (err) {
		Utils.log('reg-output', `\nError: ${err.message}`);
		console.error(err);
	}
});