package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"fmt"
)

type Pem struct {
	PrivateKey *rsa.PrivateKey
}

var (
	bits        = 2048
	err         error
	privateFile = "/Users/mike/Downloads/private.pem"
	publicFile  = "/Users/mike/Downloads/public.pem"
)

func main() {
	rsaPem := Pem{}

	err = rsaPem.GenPrivateKey(bits)
	if err != nil {
		fmt.Println(err)

		return
	}

	err = rsaPem.GenPublicKey()
	if err != nil {
		fmt.Println(err)

		return
	}
}

func (this *Pem) GenPrivateKey(bits int) error {

	this.PrivateKey, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	derStream := x509.MarshalPKCS1PrivateKey(this.PrivateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}

	file, err := os.Create(privateFile)
	if err != nil {
		return err
	}

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	return nil
}

func (this *Pem) GenPublicKey() error {

	publicKey := &this.PrivateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}

	file, err := os.Create(publicFile)
	if err != nil {
		return err
	}

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	return nil

}
