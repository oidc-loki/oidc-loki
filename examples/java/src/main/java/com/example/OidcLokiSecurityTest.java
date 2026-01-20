package com.example;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * OIDC-Loki Java Client Example
 *
 * This example demonstrates how to test a Java OIDC client against
 * OIDC-Loki's malicious tokens.
 *
 * Run: ./gradlew run (or mvn exec:java)
 * Prerequisites: OIDC-Loki running on http://localhost:9000
 */
public class OidcLokiSecurityTest {

    private static final String LOKI_URL = "http://localhost:9000";
    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "test-secret";

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public OidcLokiSecurityTest() {
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
    }

    record TestResult(String name, boolean passed, String message) {}

    public static void main(String[] args) {
        System.out.println("=".repeat(50));
        System.out.println("OIDC-Loki Java Client Security Tests");
        System.out.println("=".repeat(50));

        OidcLokiSecurityTest tester = new OidcLokiSecurityTest();
        List<TestResult> results = new ArrayList<>();

        results.add(tester.testAlgNone());
        results.add(tester.testKeyConfusion());
        results.add(tester.testTemporalTampering());
        results.add(tester.testIssuerConfusion());
        results.add(tester.testValidToken());

        // Summary
        System.out.println();
        System.out.println("=".repeat(50));
        System.out.println("Summary");
        System.out.println("=".repeat(50));

        long passed = results.stream().filter(TestResult::passed).count();
        int total = results.size();
        System.out.printf("Passed: %d/%d%n", passed, total);

        for (TestResult result : results) {
            String status = result.passed() ? "PASS" : "FAIL";
            System.out.printf("  [%s] %s: %s%n", status, result.name(), result.message());
        }

        System.exit(passed == total ? 0 : 1);
    }

    /**
     * Create a mischief session with Loki.
     */
    private String createSession(String name, String... mischief) {
        try {
            ObjectNode payload = objectMapper.createObjectNode();
            payload.put("name", name);
            payload.put("mode", "explicit");
            payload.putArray("mischief").add(mischief[0]);
            for (int i = 1; i < mischief.length; i++) {
                payload.withArray("mischief").add(mischief[i]);
            }

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(LOKI_URL + "/admin/sessions"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload.toString()))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200 || response.statusCode() == 201) {
                JsonNode json = objectMapper.readTree(response.body());
                return json.get("sessionId").asText();
            }
            System.out.println("  SKIP: Session creation failed: " + response.statusCode());
            return null;
        } catch (Exception e) {
            System.out.println("  SKIP: Could not create session: " + e.getMessage());
            return null;
        }
    }

    /**
     * Request a token from Loki with an optional session ID.
     */
    private String getToken(String sessionId) {
        try {
            String auth = Base64.getEncoder().encodeToString(
                    (CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));

            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(LOKI_URL + "/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Authorization", "Basic " + auth)
                    .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials"));

            if (sessionId != null) {
                requestBuilder.header("X-Loki-Session", sessionId);
            }

            HttpResponse<String> response = httpClient.send(requestBuilder.build(),
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode json = objectMapper.readTree(response.body());
                return json.get("access_token").asText();
            }
            System.out.println("  SKIP: Token request failed: " + response.statusCode());
            return null;
        } catch (Exception e) {
            System.out.println("  SKIP: Could not get token: " + e.getMessage());
            return null;
        }
    }

    /**
     * Validate a token with security checks.
     *
     * In production, use a proper OIDC library like Nimbus JOSE+JWT.
     * This example demonstrates the security checks your client should perform.
     */
    private void validateToken(String token) throws SecurityException {
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            throw new SecurityException("Invalid token structure");
        }

        // Decode header
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);

        try {
            JsonNode header = objectMapper.readTree(headerJson);
            JsonNode claims = objectMapper.readTree(payloadJson);

            String alg = header.has("alg") ? header.get("alg").asText().toLowerCase() : "";

            // Security Check 1: Reject alg:none
            if ("none".equals(alg)) {
                throw new SecurityException("SECURITY: token uses alg:none - unsigned tokens not allowed");
            }

            // Security Check 2: Reject symmetric algorithms (key confusion defense)
            if (alg.equals("hs256") || alg.equals("hs384") || alg.equals("hs512")) {
                throw new SecurityException(String.format(
                        "SECURITY: symmetric algorithm %s not allowed - possible key confusion attack",
                        alg.toUpperCase()));
            }

            // Security Check 3: Validate expiration
            if (claims.has("exp")) {
                long exp = claims.get("exp").asLong();
                if (exp < Instant.now().getEpochSecond()) {
                    throw new SecurityException("SECURITY: token is expired");
                }
            }

            // Security Check 4: Validate issuer
            if (claims.has("iss")) {
                String iss = claims.get("iss").asText();
                if (!LOKI_URL.equals(iss)) {
                    throw new SecurityException("SECURITY: unexpected issuer: " + iss);
                }
            }

        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new SecurityException("Invalid token: " + e.getMessage());
        }
    }

    private TestResult testAlgNone() {
        System.out.println("\nTest 1: Algorithm None Attack");
        System.out.println("-".repeat(40));

        String sessionId = createSession("java-alg-none-test", "alg-none");
        if (sessionId == null) {
            return new TestResult("alg-none", false, "Could not create session");
        }

        String token = getToken(sessionId);
        if (token == null) {
            return new TestResult("alg-none", false, "Could not get token");
        }

        try {
            validateToken(token);
            System.out.println("  FAIL: Client accepted alg:none token!");
            return new TestResult("alg-none", false, "Client accepted unsigned token");
        } catch (SecurityException e) {
            if (e.getMessage().contains("alg:none")) {
                System.out.println("  PASS: Client correctly rejected alg:none token");
                System.out.println("  Error: " + e.getMessage());
                return new TestResult("alg-none", true, e.getMessage());
            }
            System.out.println("  PASS: Client rejected token: " + e.getMessage());
            return new TestResult("alg-none", true, e.getMessage());
        }
    }

    private TestResult testKeyConfusion() {
        System.out.println("\nTest 2: Key Confusion Attack");
        System.out.println("-".repeat(40));

        String sessionId = createSession("java-key-confusion-test", "key-confusion");
        if (sessionId == null) {
            return new TestResult("key-confusion", false, "Could not create session");
        }

        String token = getToken(sessionId);
        if (token == null) {
            return new TestResult("key-confusion", false, "Could not get token");
        }

        try {
            validateToken(token);
            System.out.println("  FAIL: Client accepted key confusion token!");
            return new TestResult("key-confusion", false, "Client accepted HS256 token");
        } catch (SecurityException e) {
            String msg = e.getMessage().toLowerCase();
            if (msg.contains("key confusion") || msg.contains("symmetric")) {
                System.out.println("  PASS: Client correctly rejected HS256 token");
                System.out.println("  Error: " + e.getMessage());
                return new TestResult("key-confusion", true, e.getMessage());
            }
            System.out.println("  PASS: Client rejected token: " + e.getMessage());
            return new TestResult("key-confusion", true, e.getMessage());
        }
    }

    private TestResult testTemporalTampering() {
        System.out.println("\nTest 3: Temporal Tampering (Expired Token)");
        System.out.println("-".repeat(40));

        String sessionId = createSession("java-temporal-test", "temporal-tampering");
        if (sessionId == null) {
            return new TestResult("temporal-tampering", false, "Could not create session");
        }

        String token = getToken(sessionId);
        if (token == null) {
            return new TestResult("temporal-tampering", false, "Could not get token");
        }

        try {
            validateToken(token);
            System.out.println("  FAIL: Client accepted expired token!");
            return new TestResult("temporal-tampering", false, "Client accepted expired token");
        } catch (SecurityException e) {
            if (e.getMessage().toLowerCase().contains("expired")) {
                System.out.println("  PASS: Client correctly rejected expired token");
                System.out.println("  Error: " + e.getMessage());
                return new TestResult("temporal-tampering", true, e.getMessage());
            }
            System.out.println("  PASS: Client rejected token: " + e.getMessage());
            return new TestResult("temporal-tampering", true, e.getMessage());
        }
    }

    private TestResult testIssuerConfusion() {
        System.out.println("\nTest 4: Issuer Confusion Attack");
        System.out.println("-".repeat(40));

        String sessionId = createSession("java-issuer-test", "issuer-confusion");
        if (sessionId == null) {
            return new TestResult("issuer-confusion", false, "Could not create session");
        }

        String token = getToken(sessionId);
        if (token == null) {
            return new TestResult("issuer-confusion", false, "Could not get token");
        }

        try {
            validateToken(token);
            System.out.println("  FAIL: Client accepted token with wrong issuer!");
            return new TestResult("issuer-confusion", false, "Client accepted wrong issuer");
        } catch (SecurityException e) {
            if (e.getMessage().toLowerCase().contains("issuer")) {
                System.out.println("  PASS: Client correctly rejected wrong issuer");
                System.out.println("  Error: " + e.getMessage());
                return new TestResult("issuer-confusion", true, e.getMessage());
            }
            System.out.println("  PASS: Client rejected token: " + e.getMessage());
            return new TestResult("issuer-confusion", true, e.getMessage());
        }
    }

    private TestResult testValidToken() {
        System.out.println("\nTest 5: Valid Token (No Mischief)");
        System.out.println("-".repeat(40));

        // No session ID = no mischief
        String token = getToken(null);
        if (token == null) {
            return new TestResult("valid-token", false, "Could not get token");
        }

        try {
            String[] parts = token.split("\\.");
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            JsonNode header = objectMapper.readTree(headerJson);
            String alg = header.has("alg") ? header.get("alg").asText() : "unknown";

            if ("RS256".equals(alg) || "ES256".equals(alg)) {
                System.out.println("  PASS: Token uses proper algorithm: " + alg);
                return new TestResult("valid-token", true, "Algorithm: " + alg);
            } else {
                System.out.println("  INFO: Token uses algorithm: " + alg);
                return new TestResult("valid-token", true, "Algorithm: " + alg);
            }
        } catch (Exception e) {
            System.out.println("  FAIL: Could not parse token: " + e.getMessage());
            return new TestResult("valid-token", false, e.getMessage());
        }
    }
}
