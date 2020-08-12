package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/registry"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

type ConstatKeyManager []byte

var constantkeyURL = "constantkey.com"

func (km ConstatKeyManager) TypeURL() string             { return constantkeyURL }
func (km ConstatKeyManager) DoesSupport(url string) bool { return url == constantkeyURL }

func (km ConstatKeyManager) Primitive(sk []byte) (interface{}, error) {
	return subtle.NewAESGCM([]byte(km))
}

func (km ConstatKeyManager) NewKey(key []byte) (proto.Message, error) {
	return nil, nil
}

func (km ConstatKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return &tinkpb.KeyData{
		TypeUrl:         constantkeyURL,
		Value:           []byte(km),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

func ConstantKeyTemplate() *tinkpb.KeyTemplate {
	return &tinkpb.KeyTemplate{
		TypeUrl:          constantkeyURL,
		Value:            []byte{},
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
}

func main() {

	msg := "This is a test"

	keyMgr := ConstatKeyManager([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	registry.RegisterKeyManager(keyMgr)

	key, err := keyset.NewHandle(ConstantKeyTemplate())
	orPanic(err)

	a, err := aead.New(key)
	orPanic(err)

	ct, err := a.Encrypt([]byte(msg), nil)
	orPanic(err)

	pt, err := a.Decrypt(ct, nil)
	orPanic(err)

	fmt.Printf("Message: %s\n", msg)
	prefix := ct[:cryptofmt.TinkPrefixSize]
	iv := ct[cryptofmt.TinkPrefixSize : cryptofmt.TinkPrefixSize+subtle.AESGCMIVSize]
	ciphertext := ct[cryptofmt.TinkPrefixSize+subtle.AESGCMIVSize:]
	fmt.Printf("Key: %x Cipher text: %x\nTinkPrefix: %x IV: %x CT: %x\nPlain text: %s\n", keyMgr, ct, prefix, iv, ciphertext, pt)

	fmt.Printf("We will now decrypt the ciphertext with GCM primitives without using tink with the key %x\n", keyMgr)
	block, err := aes.NewCipher(keyMgr)
	orPanic(err)
	gcm, err := cipher.NewGCM(block)
	orPanic(err)
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	orPanic(err)
	fmt.Printf("note it uses the same key: %s\n", plaintext)

}

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}
