//go:build js && wasm

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"syscall/js"
)

func jsGenerateKey() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}

		privDER, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

		pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

		return map[string]any{
			"privateKey": string(privPEM),
			"publicKey":  string(pubPEM),
		}
	})
}

func jsSign() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return map[string]any{"error": "sign requires privateKeyPEM, message"}
		}
		block, _ := pem.Decode([]byte(args[0].String()))
		if block == nil {
			return map[string]any{"error": "failed to decode PEM"}
		}
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}

		hash := sha256.Sum256([]byte(args[1].String()))
		r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
		if err != nil {
			return map[string]any{"error": err.Error()}
		}

		// r, s を32バイトずつ結合してbase64
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return map[string]any{"result": base64.StdEncoding.EncodeToString(sig)}
	})
}

func jsVerify() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 3 {
			return map[string]any{"error": "verify requires publicKeyPEM, message, signature"}
		}
		block, _ := pem.Decode([]byte(args[0].String()))
		if block == nil {
			return map[string]any{"error": "failed to decode PEM"}
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return map[string]any{"error": "not an EC public key"}
		}

		sig, err := base64.StdEncoding.DecodeString(args[2].String())
		if err != nil || len(sig) != 64 {
			return map[string]any{"error": "invalid signature"}
		}

		hash := sha256.Sum256([]byte(args[1].String()))
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		valid := ecdsa.Verify(ecPub, hash[:], r, s)
		return map[string]any{"result": valid}
	})
}

func main() {
	js.Global().Set("ecdsaGenerateKey", jsGenerateKey())
	js.Global().Set("ecdsaSign", jsSign())
	js.Global().Set("ecdsaVerify", jsVerify())
	<-make(chan struct{})
}