package packages

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// GenerateKeyPairRSA generates a new RSA key pair
func GenerateKeyPairRSA(key_size int) (string, string, error) {
	private_key, err := rsa.GenerateKey(rand.Reader, key_size)
	if err != nil {
		return "", "", err
	}

	// Encode private key to PEM format
	private_key_bytes, err := x509.MarshalPKCS8PrivateKey(private_key)
	if err != nil {
		return "", "", err
	}
	var private_key_PEM []byte = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: private_key_bytes,
	})

	// Encode public key to PEM format
	public_key_bytes, err := x509.MarshalPKIXPublicKey(&private_key.PublicKey)
	if err != nil {
		return "", "", err
	}
	var public_key_PEM []byte = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: public_key_bytes,
	})

	return string(private_key_PEM), string(public_key_PEM), nil
}

// EncryptMessageRSA encrypts a message using RSA public key
func EncryptMessageRSA(message string, public_key_PEM string) (string, error) {
	block, _ := pem.Decode([]byte(public_key_PEM))
	if block == nil {
		return "", errors.New("failed to decode public key PEM")
	}
	public_key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	var RSA_public_key *rsa.PublicKey = public_key.(*rsa.PublicKey)

	// Encrypt the message
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		RSA_public_key,
		[]byte(message),
		nil,
	)
	if err != nil {
		return "", err
	}

	// Encode ciphertext to base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptMessageRSA decrypts an encrypted message using RSA private key
func DecryptMessageRSA(ciphertext_Base64 string, private_key_PEM string) (string, error) {
	block, _ := pem.Decode([]byte(private_key_PEM))
	if block == nil {
		return "", errors.New("failed to decode private key PEM")
	}
	private_key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	RSA_private_key, ok := private_key.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("invalid private key type")
	}

	// Decode ciphertext from base64
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertext_Base64)
	if err != nil {
		return "", err
	}

	// Decrypt the ciphertext
	plaintext, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		RSA_private_key,
		ciphertext,
		nil,
	)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
