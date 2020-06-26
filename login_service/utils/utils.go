package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mr "math/rand"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

func GetRandomString(n int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	r := mr.New(mr.NewSource(time.Now().UnixNano()))
	for i := 0; i < n; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}
func Sha256(text string) string {
	h := sha256.New()
	h.Write([]byte(text))
	bs := h.Sum(nil)
	return string(bs)
}

func DjangoEncode(passsword, salt string, iterations int) (string, error) {
	if iterations <= 0 {
		iterations = 10000
	}
	if salt == "" {
		salt = GetRandomString(12)
	}
	// 盐中不包含美元$符号
	if strings.Contains(salt, "$") {
		return "", errors.New("salt contains dollar sign ($)")
	}
	hash := pbkdf2.Key([]byte(passsword), []byte(salt), iterations, sha256.Size, sha256.New)
	b64Hash := base64.StdEncoding.EncodeToString(hash)
	return fmt.Sprintf("%s$%d$%s$%s", "pbkdf2_sha256", iterations, salt, b64Hash), nil
}

func CheckDjangoPasswrod(inAlgorithm, password string, strEncoded string) (bool, error) {
	s := strings.Split(strEncoded, "$")
	if len(s) != 4 {
		return false, errors.New("hashed password components mismatch")
	}
	algorithm, iterations, salt := s[0], s[1], s[2]
	if inAlgorithm != algorithm {
		return false, errors.New("algorithm mismatch")
	}
	i, err := strconv.Atoi(iterations)
	if err != nil {
		return false, errors.New("unreadable component in hashed password")
	}
	newStrEncoded, err := DjangoEncode(password, salt, i)
	if err != nil {
		return false, err
	}
	return hmac.Equal([]byte(newStrEncoded), []byte(strEncoded)), nil
}

func HmacSha256(text, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(text))
	// sha := hex.EncodeToString(h.Sum(nil))
	// base64.StdEncoding.EncodeToString([]byte(sha))
	return hex.EncodeToString(h.Sum(nil))
}

func HmacSha256Base64(text, secret string) string {
	baseText := base64.StdEncoding.EncodeToString([]byte(text))
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(baseText))
	return hex.EncodeToString(h.Sum(nil))
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//aes加密，填充秘钥key的16位，24,32分别对应AES-128, AES-192, or AES-256.
func AesCBCEncrypt(rawData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//填充原文
	blockSize := block.BlockSize()
	rawData = PKCS7Padding(rawData, blockSize)
	//初始向量IV必须是唯一，但不需要保密
	cipherText := make([]byte, blockSize+len(rawData))
	//block大小 16
	iv := cipherText[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	//block大小和初始向量大小一定要一致
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[blockSize:], rawData)

	return cipherText, nil
}

func AesCBCDncrypt(encryptData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(encryptData) < blockSize {
		panic("ciphertext too short")
	}
	iv := encryptData[:blockSize]
	encryptData = encryptData[blockSize:]

	// CBC mode always works in whole blocks.
	if len(encryptData)%blockSize != 0 {
		return nil, errors.New("not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(encryptData, encryptData)
	//解填充
	encryptData = PKCS7UnPadding(encryptData)
	return encryptData, nil
}

func AesEncrypt(rawData, key string) (string, error) {
	data, err := AesCBCEncrypt([]byte(rawData), []byte(key))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func AesDncrypt(rawData, key string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(rawData)
	if err != nil {
		return "", err
	}
	dnData, err := AesCBCDncrypt(data, []byte(key))
	if err != nil {
		return "", err
	}
	return string(dnData), nil
}
