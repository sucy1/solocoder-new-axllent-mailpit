package dkim

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

type VerifyResult struct {
	Status   string
	Detail   string
	Domain   string
	Selector string
}

const (
	StatusNone      = "none"
	StatusPass      = "pass"
	StatusFail      = "fail"
	StatusTempError = "temperror"
	StatusPermError = "permerror"
)

func Verify(rawMsg []byte) VerifyResult {
	headers := extractDKIMHeaders(rawMsg)
	if len(headers) == 0 {
		return VerifyResult{Status: StatusNone, Detail: "no DKIM-Signature header found"}
	}

	lastSig := headers[len(headers)-1]
	return verifySignature(rawMsg, lastSig)
}

func extractDKIMHeaders(rawMsg []byte) []string {
	var signatures []string
	lines := strings.Split(string(rawMsg), "\n")

	var currentSig strings.Builder
	inSig := false

	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToLower(trimmed), "dkim-signature:") {
			if inSig && currentSig.Len() > 0 {
				signatures = append(signatures, currentSig.String())
			}
			currentSig.Reset()
			inSig = true
			currentSig.WriteString(trimmed)
		} else if inSig {
			if strings.HasPrefix(trimmed, " ") || strings.HasPrefix(trimmed, "\t") {
				currentSig.WriteString(trimmed[1:])
			} else {
				signatures = append(signatures, currentSig.String())
				currentSig.Reset()
				inSig = false
			}
		}
	}

	if inSig && currentSig.Len() > 0 {
		signatures = append(signatures, currentSig.String())
	}

	return signatures
}

func verifySignature(rawMsg []byte, sigHeader string) VerifyResult {
	result := VerifyResult{}

	tagStr := sigHeader
	if idx := strings.Index(sigHeader, ":"); idx != -1 {
		tagStr = strings.TrimSpace(sigHeader[idx+1:])
	}

	tags := parseTags(tagStr)

	domain, ok := tags["d"]
	if !ok || domain == "" {
		return VerifyResult{Status: StatusPermError, Detail: "missing d= tag in DKIM-Signature"}
	}
	result.Domain = domain

	selector, ok := tags["s"]
	if !ok || selector == "" {
		return VerifyResult{Status: StatusPermError, Detail: "missing s= tag in DKIM-Signature"}
	}
	result.Selector = selector

	bTag, ok := tags["b"]
	if !ok || bTag == "" {
		return VerifyResult{Status: StatusPermError, Detail: "missing b= tag in DKIM-Signature"}
	}

	bhTag, ok := tags["bh"]
	if !ok || bhTag == "" {
		return VerifyResult{Status: StatusPermError, Detail: "missing bh= tag in DKIM-Signature"}
	}

	algo := "rsa-sha256"
	if a, ok := tags["a"]; ok && a != "" {
		algo = strings.ToLower(a)
	}

	canonicalHeader := "simple"
	canonicalBody := "simple"
	if c, ok := tags["c"]; ok && c != "" {
		parts := strings.Split(strings.ToLower(c), "/")
		if len(parts) > 0 && parts[0] != "" {
			canonicalHeader = parts[0]
		}
		if len(parts) > 1 && parts[1] != "" {
			canonicalBody = parts[1]
		}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(cleanBase64(bTag))
	if err != nil {
		return VerifyResult{Status: StatusPermError, Detail: "invalid base64 in b= tag", Domain: domain, Selector: selector}
	}

	bodyHash, err := base64.StdEncoding.DecodeString(cleanBase64(bhTag))
	if err != nil {
		return VerifyResult{Status: StatusPermError, Detail: "invalid base64 in bh= tag", Domain: domain, Selector: selector}
	}

	pubKey, err := getPublicKey(selector, domain)
	if err != nil {
		return VerifyResult{Status: StatusTempError, Detail: fmt.Sprintf("DNS lookup failed: %s", err.Error()), Domain: domain, Selector: selector}
	}
	if pubKey == nil {
		return VerifyResult{Status: StatusFail, Detail: "public key not found in DNS", Domain: domain, Selector: selector}
	}

	canonicalBodyData := canonicalizeBody(rawMsg, canonicalBody)

	var computedHash []byte
	switch algo {
	case "rsa-sha256":
		h := sha256.Sum256(canonicalBodyData)
		computedHash = h[:]
	case "rsa-sha512":
		h := sha512.Sum512(canonicalBodyData)
		computedHash = h[:]
	default:
		return VerifyResult{Status: StatusPermError, Detail: fmt.Sprintf("unsupported algorithm: %s", algo), Domain: domain, Selector: selector}
	}

	if !hashEqual(computedHash, bodyHash) {
		return VerifyResult{Status: StatusFail, Detail: "body hash does not match", Domain: domain, Selector: selector}
	}

	signedHeaderData := computeSignedData(rawMsg, sigHeader, tags, canonicalHeader)

	var hashAlg crypto.Hash
	switch algo {
	case "rsa-sha256":
		hashAlg = crypto.SHA256
	case "rsa-sha512":
		hashAlg = crypto.SHA512
	default:
		return VerifyResult{Status: StatusPermError, Detail: fmt.Sprintf("unsupported algorithm: %s", algo), Domain: domain, Selector: selector}
	}

	h := hashAlg.New()
	h.Write(signedHeaderData)
	hashed := h.Sum(nil)

	err = rsa.VerifyPKCS1v15(pubKey, hashAlg, hashed, sigBytes)
	if err != nil {
		return VerifyResult{Status: StatusFail, Detail: "signature verification failed", Domain: domain, Selector: selector}
	}

	result.Status = StatusPass
	result.Detail = "DKIM signature verified successfully"
	return result
}

func parseTags(s string) map[string]string {
	tags := make(map[string]string)
	parts := strings.Split(s, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			val := strings.TrimSpace(kv[1])
			tags[key] = val
		}
	}
	return tags
}

func getPublicKey(selector, domain string) (*rsa.PublicKey, error) {
	txtName := fmt.Sprintf("%s._domainkey.%s", selector, domain)

	txtRecords, err := net.LookupTXT(txtName)
	if err != nil {
		return nil, fmt.Errorf("DNS TXT lookup error: %w", err)
	}

	for _, txt := range txtRecords {
		if key, err := parsePublicKey(txt); err == nil && key != nil {
			return key, nil
		}
	}

	return nil, nil
}

func parsePublicKey(txt string) (*rsa.PublicKey, error) {
	tags := parseTags(txt)

	pStr, ok := tags["p"]
	if !ok || pStr == "" {
		return nil, fmt.Errorf("missing p= tag")
	}

	keyType := "rsa"
	if k, ok := tags["k"]; ok && k != "" {
		keyType = strings.ToLower(k)
	}

	if keyType != "rsa" {
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(cleanBase64(pStr))
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %w", err)
	}

	pub, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("PKIX parse error: %w", err)
	}

	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaKey, nil
}

func cleanBase64(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\t", "")
	return s
}

func canonicalizeBody(rawMsg []byte, algo string) []byte {
	parts := strings.SplitN(string(rawMsg), "\r\n\r\n", 2)
	body := ""
	if len(parts) == 2 {
		body = parts[1]
	}

	if algo == "relaxed" {
		body = strings.ReplaceAll(body, "\r\n\t", " ")
		body = strings.ReplaceAll(body, "\r\n ", " ")
		for strings.Contains(body, "  ") {
			body = strings.ReplaceAll(body, "  ", " ")
		}
		body = strings.TrimSpace(body)
		body += "\r\n"
	} else {
		if strings.HasSuffix(body, "\r\n\r\n") {
			for strings.HasSuffix(body, "\r\n\r\n") {
				body = body[:len(body)-2]
			}
			body += "\r\n"
		} else if !strings.HasSuffix(body, "\r\n") {
			body += "\r\n"
		}
	}

	return []byte(body)
}

func computeSignedData(rawMsg []byte, sigHeader string, tags map[string]string, canonicalAlgo string) []byte {
	signedHeaders := []string{}
	if h, ok := tags["h"]; ok {
		signedHeaders = strings.Split(strings.ToLower(h), ":")
		for i := range signedHeaders {
			signedHeaders[i] = strings.TrimSpace(signedHeaders[i])
		}
	}

	lines := strings.Split(string(rawMsg), "\n")
	var headerLines []string
	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if trimmed == "" {
			break
		}
		if strings.Contains(trimmed, ":") && !strings.HasPrefix(trimmed, " ") && !strings.HasPrefix(trimmed, "\t") {
			headerLines = append(headerLines, trimmed)
		} else if (strings.HasPrefix(trimmed, " ") || strings.HasPrefix(trimmed, "\t")) && len(headerLines) > 0 {
			headerLines[len(headerLines)-1] += trimmed[1:]
		}
	}

	var result strings.Builder
	for _, h := range signedHeaders {
		for i := len(headerLines) - 1; i >= 0; i-- {
			colonIdx := strings.Index(headerLines[i], ":")
			if colonIdx == -1 {
				continue
			}
			headerName := strings.TrimSpace(headerLines[i][:colonIdx])
			if strings.EqualFold(headerName, h) {
				var headerVal string
				if canonicalAlgo == "relaxed" {
					headerVal = strings.ToLower(strings.TrimSpace(headerLines[i][colonIdx+1:]))
					for strings.Contains(headerVal, "  ") {
						headerVal = strings.ReplaceAll(headerVal, "  ", " ")
					}
				} else {
					headerVal = headerLines[i][colonIdx+1:]
				}
				result.WriteString(h)
				result.WriteString(":")
				result.WriteString(headerVal)
				result.WriteString("\r\n")
				break
			}
		}
	}

	sigValue := sigHeader
	if idx := strings.Index(sigValue, ":"); idx != -1 {
		sigValue = sigValue[idx+1:]
	}
	if canonicalAlgo == "relaxed" {
		sigValue = strings.ToLower(strings.TrimSpace(sigValue))
		for strings.Contains(sigValue, "  ") {
			sigValue = strings.ReplaceAll(sigValue, "  ", " ")
		}
	}

	bValue := tags["b"]
	sigValueForVerify := redactBTag(sigValue, bValue)

	result.WriteString("dkim-signature:")
	result.WriteString(sigValueForVerify)
	result.WriteString("\r\n")

	return []byte(result.String())
}

func redactBTag(sigValue, bValue string) string {
	bClean := cleanBase64(bValue)
	sigClean := cleanBase64(sigValue)

	if strings.Contains(sigClean, "b="+bClean) {
		return strings.Replace(sigClean, "b="+bClean, "b=", 1)
	}

	return sigValue
}

func hashEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
