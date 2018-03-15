package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"encoding/base64"
)

func main() {
	privateFile := "/Users/mike/Downloads/private.pem"
	publicFile := "/Users/mike/Downloads/public.pem"

	privateKey, err := ioutil.ReadFile(privateFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	publicKey, err := ioutil.ReadFile(publicFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	var theMsg = `{"BTC": 2.001}`
	fmt.Println("Source:", theMsg)

	sig, _ := RsaSign([]byte(theMsg), privateKey)
	fmt.Println(string(base64.StdEncoding.EncodeToString(sig)))

	fmt.Println(RsaSignVer([]byte(theMsg), sig, publicKey))

	//公钥加密
	enc, _ := RsaEncrypt([]byte(theMsg), publicKey)
	fmt.Println("Encrypted:", string(base64.StdEncoding.EncodeToString(enc)))

	//私钥解密
	decstr, _ := RsaDecrypt(enc, privateKey)
	fmt.Println("Decrypted:", string(decstr))
}

func RsaSign(data, privateKey []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	hashed := h.Sum(nil)
	//获取私钥
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed)
}

func RsaSignVer(data, signature, publicKey []byte) error {
	hashed := sha256.Sum256(data)
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return errors.New("public key error")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	pub := pubInterface.(*rsa.PublicKey)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
}

func RsaEncrypt(data, publicKey []byte) ([]byte, error) {

	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, data)
}

func RsaDecrypt(ciphertext, privateKey []byte) ([]byte, error) {

	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}
