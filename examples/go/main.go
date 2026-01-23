// OIDC-Loki Go Client Example
//
// This example demonstrates how to test a Go OIDC client against
// OIDC-Loki's malicious tokens.
//
// Run: go run main.go
// Prerequisites: OIDC-Loki running on http://localhost:9000

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	lokiURL      = "http://localhost:9000"
	clientID     = "test-client"
	clientSecret = "test-secret"
)

// LokiSession represents a mischief session
type LokiSession struct {
	SessionID string `json:"sessionId"`
}

// TokenResponse represents the OIDC token response
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func main() {
	fmt.Println("=== OIDC-Loki Go Client Security Tests ===\n")

	// Test 1: Algorithm None Attack
	testAlgNone()

	// Test 2: Key Confusion Attack
	testKeyConfusion()

	// Test 3: Temporal Tampering
	testTemporalTampering()

	// Test 4: Valid Token (should pass)
	testValidToken()
}

// createSession creates a mischief session with Loki
func createSession(name string, mischief []string) (*LokiSession, error) {
	payload := map[string]interface{}{
		"name":     name,
		"mode":     "explicit",
		"mischief": mischief,
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(lokiURL+"/admin/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	defer resp.Body.Close()

	var session LokiSession
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return nil, fmt.Errorf("failed to decode session: %w", err)
	}
	return &session, nil
}

// getToken requests a token from Loki with an optional session ID
func getToken(sessionID string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	req, _ := http.NewRequest("POST", lokiURL+"/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(clientID+":"+clientSecret)))

	if sessionID != "" {
		req.Header.Set("X-Loki-Session", sessionID)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, body)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}
	return &tokenResp, nil
}

// validateToken demonstrates secure token validation
// In production, use a proper OIDC library like coreos/go-oidc
func validateToken(tokenString string) error {
	// Parse without validation to inspect claims
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	// Security Check 1: Reject alg:none
	if token.Method.Alg() == "none" {
		return fmt.Errorf("SECURITY: token uses alg:none - unsigned tokens not allowed")
	}

	// Security Check 2: Reject symmetric algorithms (key confusion defense)
	alg := token.Method.Alg()
	if alg == "HS256" || alg == "HS384" || alg == "HS512" {
		return fmt.Errorf("SECURITY: symmetric algorithm %s not allowed - possible key confusion attack", alg)
	}

	// Security Check 3: Validate timestamps
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid claims format")
	}

	// Note: In production, use proper JWKS validation with go-oidc
	// This example focuses on demonstrating the security checks

	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return fmt.Errorf("SECURITY: token is expired")
		}
	}

	return nil
}

func testAlgNone() {
	fmt.Println("Test 1: Algorithm None Attack")
	fmt.Println("-----------------------------")

	session, err := createSession("go-alg-none-test", []string{"alg-none"})
	if err != nil {
		log.Printf("  SKIP: Could not create session: %v\n\n", err)
		return
	}

	tokenResp, err := getToken(session.SessionID)
	if err != nil {
		log.Printf("  SKIP: Could not get token: %v\n\n", err)
		return
	}

	err = validateToken(tokenResp.AccessToken)
	if err != nil && strings.Contains(err.Error(), "alg:none") {
		fmt.Printf("  PASS: Client correctly rejected alg:none token\n")
		fmt.Printf("  Error: %v\n\n", err)
	} else if err != nil {
		fmt.Printf("  PASS: Client rejected token: %v\n\n", err)
	} else {
		fmt.Printf("  FAIL: Client accepted alg:none token!\n\n")
	}
}

func testKeyConfusion() {
	fmt.Println("Test 2: Key Confusion Attack")
	fmt.Println("----------------------------")

	session, err := createSession("go-key-confusion-test", []string{"key-confusion"})
	if err != nil {
		log.Printf("  SKIP: Could not create session: %v\n\n", err)
		return
	}

	tokenResp, err := getToken(session.SessionID)
	if err != nil {
		log.Printf("  SKIP: Could not get token: %v\n\n", err)
		return
	}

	err = validateToken(tokenResp.AccessToken)
	if err != nil && strings.Contains(err.Error(), "key confusion") {
		fmt.Printf("  PASS: Client correctly rejected HS256 token\n")
		fmt.Printf("  Error: %v\n\n", err)
	} else if err != nil {
		fmt.Printf("  PASS: Client rejected token: %v\n\n", err)
	} else {
		fmt.Printf("  FAIL: Client accepted key confusion token!\n\n")
	}
}

func testTemporalTampering() {
	fmt.Println("Test 3: Temporal Tampering (Expired Token)")
	fmt.Println("------------------------------------------")

	session, err := createSession("go-temporal-test", []string{"temporal-tampering"})
	if err != nil {
		log.Printf("  SKIP: Could not create session: %v\n\n", err)
		return
	}

	tokenResp, err := getToken(session.SessionID)
	if err != nil {
		log.Printf("  SKIP: Could not get token: %v\n\n", err)
		return
	}

	err = validateToken(tokenResp.AccessToken)
	if err != nil && strings.Contains(err.Error(), "expired") {
		fmt.Printf("  PASS: Client correctly rejected expired token\n")
		fmt.Printf("  Error: %v\n\n", err)
	} else if err != nil {
		fmt.Printf("  PASS: Client rejected token: %v\n\n", err)
	} else {
		fmt.Printf("  FAIL: Client accepted expired token!\n\n")
	}
}

func testValidToken() {
	fmt.Println("Test 4: Valid Token (No Mischief)")
	fmt.Println("---------------------------------")

	// No session ID = no mischief
	tokenResp, err := getToken("")
	if err != nil {
		log.Printf("  SKIP: Could not get token: %v\n\n", err)
		return
	}

	// For a truly valid token, we'd need to verify with JWKS
	// This test just confirms no obvious issues
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenResp.AccessToken, jwt.MapClaims{})
	if err != nil {
		fmt.Printf("  FAIL: Could not parse token: %v\n\n", err)
		return
	}

	// Valid tokens should use RS256
	if token.Method.Alg() == "RS256" || token.Method.Alg() == "ES256" {
		fmt.Printf("  PASS: Token uses proper algorithm: %s\n\n", token.Method.Alg())
	} else {
		fmt.Printf("  INFO: Token uses algorithm: %s\n\n", token.Method.Alg())
	}
}
