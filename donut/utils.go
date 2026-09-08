package donut

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net/http"
)

// RandomString generates a random lowercase ASCII string of the requested
// length.
//
// Deprecated: use RandomStringWithError when the random source failure must be
// handled. This legacy API cannot report an error, so it returns an empty
// string when length is negative or crypto/rand fails.
func RandomString(length int) string {
	value, err := RandomStringWithError(length)
	if err != nil {
		return ""
	}
	return value
}

// RandomStringWithError generates a random lowercase ASCII string of the
// requested length and reports failures from the cryptographic random source.
func RandomStringWithError(length int) (string, error) {
	if length < 0 {
		return "", fmt.Errorf("donut: invalid random string length %d", length)
	}
	if length == 0 {
		return "", nil
	}

	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	result := make([]byte, length)
	for i := range result {
		sample, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", fmt.Errorf("donut: random string: %w", err)
		}
		result[i] = alphabet[sample.Int64()]
	}
	return string(result), nil
}

// DownloadFile will download an URL to a byte buffer
func DownloadFile(url string) (*bytes.Buffer, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	buf := bytes.NewBuffer([]byte{})
	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// GenerateRandomBytes : Generates as many random bytes as you ask for, returns them as []byte
func GenerateRandomBytes(count int) ([]byte, error) {
	if count < 0 {
		return nil, fmt.Errorf("donut: invalid random byte count %d", count)
	}
	b := make([]byte, count)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}
