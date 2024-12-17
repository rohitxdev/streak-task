// Package cryptoutil provides utility functions for encryption and decryption.
package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/argon2"
)

func padKey(key []byte) []byte {
	keyLen := len(key)
	padDiff := keyLen % 16
	if padDiff == 0 {
		return key
	}
	padLen := 16 - padDiff
	pad := make([]byte, padLen)
	for i := 0; i < padLen; i++ {
		pad[i] = byte(padLen)
	}
	return append(key, pad...)
}

// Encrypts data using AES algorithm. The key should be 16, 24, or 32 for 128, 192, or 256 bit encryption respectively.
func EncryptAES(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(padKey(key))
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}
	//Append cipher to nonce and return nonce + cipher
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Decrypts data using AES algorithm. The key should be same key that was used to encrypt the data.
func DecryptAES(encryptedData []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(padKey(key))
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()

	//Get nonce from encrypted data
	nonce, cipher := encryptedData[:nonceSize], encryptedData[nonceSize:]
	data, err := gcm.Open(nil, nonce, cipher, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return data, nil
}

func RandomString(size uint) string {
	var buf = make([]byte, size)
	_, _ = rand.Read(buf)
	return bufToBase62(buf)
}

func bufToBase62(buf []byte) string {
	var i big.Int
	i.SetBytes(buf)
	return i.Text(62)
}

func Base62Hash(text string) string {
	hasher := sha256.New()
	buf := hasher.Sum([]byte(text))
	return bufToBase62(buf)
}

func Base32Hash(text string) string {
	hasher := sha256.New()
	buf := hasher.Sum([]byte(text))
	return base32.StdEncoding.EncodeToString(buf)
}

func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// Generates a secure hash of the provided text using Argon2 algorithm.
func HashSecure(text string) (string, error) {
	const (
		time    = 1         // number of iterations
		memory  = 64 * 1024 // memory in KiB
		threads = 4         // parallelism
		keyLen  = 32        // length of the generated key
	)

	salt, err := generateSalt(16)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(text), salt, time, memory, threads, keyLen)
	fullHash := append(salt, hash...)
	encodedHash := base64.RawStdEncoding.EncodeToString(fullHash)

	return encodedHash, nil
}

// Verifies the provided hash against the provided text using Argon2 algorithm.
func VerifyHashSecure(text string, fullHash string) bool {
	data, err := base64.RawStdEncoding.DecodeString(fullHash)
	if err != nil {
		return false
	}

	salt := data[:16]
	hash := data[16:]
	newHash := argon2.IDKey([]byte(text), salt, 1, 64*1024, 4, 32)

	return subtle.ConstantTimeCompare(hash, newHash) == 1
}

func GenerateJWT[T any](data T, expiresIn time.Duration, secret string) (string, error) {
	t := time.Now()
	claims := jwt.MapClaims{
		"data": data,
		"iat":  t.Unix(),
		"nbf":  t.Unix(),
		"exp":  t.Add(expiresIn).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return tokenStr, nil
}

// The type of claims may not be the same as the type given during the token creation. For example, non-float numbers get converted to float when parsed due to how JWT processes data. Be cautious and don't put non-primitive types in claims.
func verifyJWTUnsafe[T any](tokenStr string, secret string) (T, error) {
	var data T
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return data, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if err = claims.Valid(); err != nil {
			return data, err
		}
		if data, ok = claims["data"].(T); ok {
			return data, nil
		}
		return data, fmt.Errorf("expected data to have type %T, but got %T", data, claims["data"])
	}
	return data, errors.New("invalid token")
}

func convertToType[T any](data any) (T, bool) {
	var zero T
	targetType := reflect.TypeOf(zero)

	// Special handling for maps
	if targetType.Kind() == reflect.Map {
		dataValue := reflect.ValueOf(data)
		if dataValue.Kind() == reflect.Map {
			// Create a new map of the target type
			newMap := reflect.MakeMap(targetType)

			// Iterate through source map and convert each key-value pair
			iter := dataValue.MapRange()
			for iter.Next() {
				k := iter.Key()
				v := iter.Value()

				// Ensure correct type conversion for keys and values
				convertedK := k.Interface()
				convertedV := v.Interface()

				newMap.SetMapIndex(reflect.ValueOf(convertedK), reflect.ValueOf(convertedV))
			}

			return newMap.Interface().(T), true
		}
	}

	// General type conversion
	if reflect.TypeOf(data).ConvertibleTo(targetType) {
		converted := reflect.ValueOf(data).Convert(targetType).Interface()
		return converted.(T), true
	}

	return zero, false
}

// Works only for primitive types and maps.
func VerifyJWT[T any](tokenStr string, secret string) (T, error) {
	var zero T
	anyData, err := verifyJWTUnsafe[any](tokenStr, secret)
	if err != nil {
		return zero, err
	}
	if data, ok := convertToType[T](anyData); ok {
		return data, nil
	}
	return zero, fmt.Errorf("expected data to have type %T, but got %T", zero, anyData)
}

func checkCertValidity(filePath string) bool {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	return time.Now().Before(cert.NotAfter)
}

func checkKeyValidity(filePath string) bool {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return false
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return false
	}

	return privateKey != nil
}

// GenerateSelfSignedCert returns certificate path, key path, isFromCache flag and error.
func GenerateSelfSignedCert() (string, string, bool, error) {
	dir := ".local/tls"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", "", false, err
	}
	certPath := filepath.Join(dir, "localhost.crt")
	keyPath := filepath.Join(dir, "localhost.key")

	if checkCertValidity(certPath) && checkKeyValidity(keyPath) {
		return certPath, keyPath, true, nil
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", false, err
	}

	// Certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Development"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", false, err
	}

	// Write certificate to file
	certFile, err := os.Create(certPath)
	if err != nil {
		return "", "", false, err
	}
	defer certFile.Close()

	certBlock := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	if err = pem.Encode(certFile, &certBlock); err != nil {
		return "", "", false, nil
	}

	// Write private key to file
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return "", "", false, err
	}
	defer keyFile.Close()

	keyBock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err = pem.Encode(keyFile, &keyBock); err != nil {
		return "", "", false, nil
	}

	return certPath, keyPath, false, nil
}
