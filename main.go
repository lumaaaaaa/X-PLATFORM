package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	AndroidID  = "aaaaaaaaaaaaaaaa"
	AppVersion = "23.12.20"
	ClientType = "android"
	UserAgent  = "Bby-Android/23.12.20 APPSTORE Mozilla/5.0 (Linux; Android 11; WayDroid x86_64 Device Build/RQ3A.211001.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/115.0.5790.136 Safari/537.36"
	PKUrl      = "https://www.bestbuy.com/api/csiservice/v2/key/DEVICE-METADATA"
)

var (
	client = http.Client{}
)

func main() {
	req, _ := http.NewRequest("GET", "https://app.bestbuy.com/si/v4/product/detail/sku/6521430", nil)
	req.Header.Add("X-Platform", generateXPlatform())
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Add("X-App-Version", AppVersion)
	req.Header.Add("X-Client-Type", ClientType)
	req.Header.Add("X-Si-Api-Version", "4.0")
	req.Header.Set("Accept", "application/json;charset=UTF-8")

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	body, err := io.ReadAll(resp.Body)
	fmt.Println("\nResponse:\n" + string(body))
}

func generateXPlatform() string {
	// Fetch the public key from the server
	publicKey := fetchPublicKey()
	if strings.Contains(publicKey, "-----BEGIN PUBLIC KEY-----") {
		fmt.Println("Fetched public key: \n" + publicKey)
	} else {
		panic("Failed to fetch public key: " + publicKey)
	}

	// Create the payload
	payload := createPayload()
	fmt.Println("Created payload:", payload)

	// Encrypt the payload
	encryptedPayload := encryptPayload(payload, publicKey)
	fmt.Println("Encrypted payload:", encryptedPayload)

	// B64 encode the encrypted payload
	xPlatform := b64Encode(encryptedPayload)
	fmt.Println("X-Platform:", xPlatform)

	return xPlatform
}

func b64Encode(payload []byte) string {
	return base64.StdEncoding.EncodeToString(payload)
}

func encryptPayload(payload string, publicKey string) []byte {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		panic("Failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	var rsaPK *rsa.PublicKey
	var ok bool
	if rsaPK, ok = pub.(*rsa.PublicKey); !ok {
		panic("Failed to parse RSA public key")
	}

	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPK, []byte(payload), nil)
	if err != nil {
		panic(err)
	}

	return ciphertext
}

func createPayload() string {
	return fmt.Sprintf("{\"identifierForVendor\": \"%s\",\"channel\": \"AndroidTablet\",\"expirationTime\": \"%d000000\"}", AndroidID, time.Now().UnixMilli()+900000)
}

func fetchPublicKey() string {
	req, _ := http.NewRequest("GET", PKUrl, nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("X-App-Version", AppVersion)
	req.Header.Set("X-Client-Type", ClientType)

	resp, err := client.Do(req)
	if err != nil {
		return err.Error()
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err.Error()
	}

	var pkResponse PKResponse
	err = json.Unmarshal(body, &pkResponse)
	if err != nil {
		return err.Error()
	}

	return pkResponse.PublicKey
}
