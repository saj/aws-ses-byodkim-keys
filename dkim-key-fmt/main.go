package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var prog = filepath.Base(os.Args[0])

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s prv-in prv-out pub-out\n", prog)
	fmt.Fprintf(os.Stderr, `
prv-in is the filesystem path to an existing RSA private key in PEM format.

A new 1024-bit RSA private key may be generated with OpenSSL as follows:

    openssl genrsa -f4 -out private.key 1024

The first PEM block is assumed to contain an RSA private key in PKCS#1 or PKCS#8
ASN.1 DER form.  Subsequent PEM blocks, if any, are silently ignored.

A formatted RSA private key is written to path prv-out.
Output format is suitable for use with AWS SES.
The file at path prv-out is overwritten if it exists.

A formatted RSA public key is written to path pub-out.
Output format is suitable for use with DKIM DNS resource records.
The file at path pub-out is overwritten if it exists.

`)
}

func init() {
	log.SetFlags(0)
}

func main() {
	if len(os.Args) < 4 {
		usage()
		os.Exit(2)
	}
	var (
		prvin  = os.Args[1]
		prvout = os.Args[2]
		pubout = os.Args[3]
	)

	var privateKey *rsa.PrivateKey
	{
		b, err := os.ReadFile(prvin)
		if err != nil {
			log.Fatal(err)
		}
		block, err := parsePEMBlock(b)
		if err != nil {
			log.Fatalf("%s: %v", prvin, err)
		}
		privateKey, err = parseKey(block)
		if err != nil {
			log.Fatalf("%s: %v", prvin, err)
		}
	}

	var buf bytes.Buffer
	{
		buf.Reset()
		buf.Write(marshalPrivateKey(privateKey))
		buf.WriteString("\n")
		if err := os.WriteFile(prvout, buf.Bytes(), 0600); err != nil {
			log.Fatal(err)
		}
	}
	{
		buf.Reset()
		buf.WriteString(`"`)
		buf.WriteString("v=DKIM1; ")
		buf.WriteString("k=rsa; ")
		buf.WriteString("p=")
		k, err := marshalPublicKey(&privateKey.PublicKey)
		if err != nil {
			log.Fatal(err)
		}
		buf.Write(k)
		buf.WriteString(`"`)
		buf.WriteString("\n")
		if err := os.WriteFile(pubout, buf.Bytes(), 0644); err != nil {
			log.Fatal(err)
		}
	}
}

func parsePEMBlock(data []byte) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("PEM block not found")
	}
	return block.Bytes, nil
}

func parseKey(data []byte) (*rsa.PrivateKey, error) {
	// Some builds of openssl-genrsa default to PKCS#1.
	// Others default to PKCS#8.  We attempt to parse both.

	var first error
	{
		pk, err := x509.ParsePKCS1PrivateKey(data)
		first = err
		if err == nil {
			return pk, nil
		}
	}
	{
		k, err := x509.ParsePKCS8PrivateKey(data)
		if err == nil {
			switch k.(type) {
			case *rsa.PrivateKey:
				return k.(*rsa.PrivateKey), nil
			default:
				return nil, errors.New("not an RSA private key")
			}
		}
	}
	return nil, first
}

var encoding = base64.StdEncoding

func marshalPrivateKey(key *rsa.PrivateKey) []byte {
	der := x509.MarshalPKCS1PrivateKey(key)
	b64 := make([]byte, encoding.EncodedLen(len(der)))
	encoding.Encode(b64, der)
	return b64
}

func marshalPublicKey(key *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	b64 := make([]byte, encoding.EncodedLen(len(der)))
	encoding.Encode(b64, der)
	return b64, nil
}
