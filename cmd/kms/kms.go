package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"strings"

	kms "github.com/sporkins/kms-go"
)

var rawStdEncoding = base64.StdEncoding

func usage() {
	flag.PrintDefaults()
}

func main() {
	plaintext := flag.String("plaintext", "", "plain text to encrypt")
	kmsResourceID := flag.String("kms-resource-id", "", "kms resource used to encrypt key data, if not passed, will print raw data")
	kmsVersionID := flag.Int("kms-key-version", 1, "The version of the key to use, default 1 (used on ly if kms-resource-id is passed)")
	flag.Parse()

	var cleaned = strings.TrimSpace(*plaintext)
	cleaned = strings.TrimSuffix(cleaned, "\n")
	kmsEncData := kmsEncrypt(cleaned, *kmsResourceID, *kmsVersionID)

	fmt.Printf("\nKMS encrypted key data:\n\n%s\n", kmsEncData)
}

func base64Encode(b []byte) []byte {
	return []byte(rawStdEncoding.EncodeToString(b))
}

func kmsEncrypt(plaintext string, kmsResourceID string, kmsVersion int) string {
	cipher := kmsClient(kmsResourceID, kmsVersion).Encrypt([]byte(plaintext))
	println(string(cipher))
	println(len(cipher))
	cipherBase64 := base64Encode(cipher)
	return string(cipherBase64)
}

func kmsClient(kmsResourceID string, kmsVersion int) kms.KMSClient {
	return kms.NewKMSClient(fmt.Sprintf("%s/cryptoKeyVersions/%d", kmsResourceID, kmsVersion))
}
