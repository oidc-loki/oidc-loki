import { describe, expect, it } from "vitest";
import { createToken, parseToken, signWithKeyConfusion } from "../../src/core/token-forge.js";

describe("TokenForge", () => {
	// Sample JWT (RS256 signed, but we're just testing parsing)
	const sampleJwt =
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA";

	describe("parseToken", () => {
		it("should parse a JWT into header and claims", () => {
			const token = parseToken(sampleJwt);

			expect(token.header.alg).toBe("RS256");
			expect(token.header.typ).toBe("JWT");
			expect(token.claims.sub).toBe("1234567890");
			expect(token.claims.name).toBe("John Doe");
			expect(token.claims.admin).toBe(true);
			expect(token.claims.iat).toBe(1516239022);
		});

		it("should preserve original JWT", () => {
			const token = parseToken(sampleJwt);
			expect(token.original).toBe(sampleJwt);
		});

		it("should allow header modification", () => {
			const token = parseToken(sampleJwt);
			token.header.alg = "none";
			expect(token.header.alg).toBe("none");
		});

		it("should allow claims modification", () => {
			const token = parseToken(sampleJwt);
			token.claims.exp = 0;
			expect(token.claims.exp).toBe(0);
		});
	});

	describe("alg:none attack", () => {
		it("should create unsigned token with alg:none", async () => {
			const token = parseToken(sampleJwt);

			token.header.alg = "none";
			token.signature = "";

			const result = token.build();
			const parts = result.split(".");

			expect(parts).toHaveLength(3);
			expect(parts[2]).toBe(""); // Empty signature

			// Parse the header to verify
			const header = JSON.parse(atob(parts[0]?.replace(/-/g, "+").replace(/_/g, "/")));
			expect(header.alg).toBe("none");
		});

		it("should use sign method for alg:none", async () => {
			const token = parseToken(sampleJwt);

			await token.sign("none", "");

			expect(token.header.alg).toBe("none");
			expect(token.signature).toBe("");
		});
	});

	describe("createToken", () => {
		it("should create a new token from scratch", () => {
			const token = createToken(
				{ alg: "RS256", typ: "JWT" },
				{ sub: "user123", iss: "loki", exp: 9999999999 },
			);

			expect(token.header.alg).toBe("RS256");
			expect(token.claims.sub).toBe("user123");
			expect(token.claims.iss).toBe("loki");
		});
	});

	describe("temporal tampering", () => {
		it("should allow setting expired token", () => {
			const token = parseToken(sampleJwt);
			const pastTime = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago

			token.claims.exp = pastTime;

			expect(token.claims.exp).toBe(pastTime);
			expect(token.claims.exp).toBeLessThan(Math.floor(Date.now() / 1000));
		});

		it("should allow setting future nbf", () => {
			const token = parseToken(sampleJwt);
			const futureTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now

			token.claims.nbf = futureTime;

			expect(token.claims.nbf).toBe(futureTime);
			expect(token.claims.nbf).toBeGreaterThan(Math.floor(Date.now() / 1000));
		});
	});

	describe("HMAC signing", () => {
		it("should sign with HS256", async () => {
			const token = createToken({ alg: "HS256", typ: "JWT" }, { sub: "test", iat: 1234567890 });

			await token.sign("HS256", "my-secret-key");

			const result = token.build();
			const parts = result.split(".");

			expect(parts).toHaveLength(3);
			expect(parts[2]).not.toBe(""); // Has signature
			expect(token.header.alg).toBe("HS256");
		});
	});

	describe("key confusion attack", () => {
		it("should sign with public key as HMAC secret", async () => {
			const publicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWyf8PgELY
-----END PUBLIC KEY-----`;

			const token = parseToken(sampleJwt, publicKeyPem);

			await signWithKeyConfusion(token, publicKeyPem);

			expect(token.header.alg).toBe("HS256");
			expect(token.signature).not.toBe("");

			const result = token.build();
			const parts = result.split(".");
			expect(parts).toHaveLength(3);
		});
	});
});
