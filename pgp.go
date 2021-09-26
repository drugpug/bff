package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"

	_ "golang.org/x/crypto/ripemd160"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/rs/zerolog/log"
)

func encodePrivateKey(out io.Writer, key *rsa.PrivateKey) {
	w, err := armor.Encode(out, openpgp.PrivateKeyType, make(map[string]string))
	if err != nil {
		log.Err(err).Msg("cannot create openpgp armor")
	}

	pgpKey := packet.NewRSAPrivateKey(time.Now(), key)
	if err := pgpKey.Serialize(w); err != nil {
		log.Err(err).Msg("cannot serialize private key")
	}

	if err := w.Close(); err != nil {
		log.Err(err).Msg("cannot close armor writer")
	}
}

func decodePrivateKey(filename string) *packet.PrivateKey {

	// open ascii armored private key
	in, err := os.Open(filename)
	if err != nil {
		log.Err(err).Msg("cannot open private key")
	}
	defer in.Close()

	block, err := armor.Decode(in)
	if err != nil {
		log.Err(err).Msg("cannot decode openpgp armor")
	}

	if block.Type != openpgp.PrivateKeyType {
		log.Err(errors.New("invalid private key file")).Msg("cannot decode private key")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		log.Err(err).Msg("cannot read private key")
	}

	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		log.Err(errors.New("invalid private key file")).Msg("Error parsing private key")
	}
	return key
}

func encodePublicKey(out io.Writer, key *rsa.PrivateKey) {
	w, err := armor.Encode(out, openpgp.PublicKeyType, make(map[string]string))
	if err != nil {
		log.Err(err).Msg("cannot create openpgp armor")
	}

	pgpKey := packet.NewRSAPublicKey(time.Now(), &key.PublicKey)

	if err := pgpKey.Serialize(w); err != nil {
		log.Err(err).Msg("cannot serialize private key")
	}

	if err := w.Close(); err != nil {
		log.Err(err).Msg("cannot close armor writer")
	}
}

func decodePublicKey(filename string) *packet.PublicKey {

	// open ascii armored public key
	in, err := os.Open(filename)
	if err != nil {
		log.Err(err).Msg("cannot open public key")
	}
	defer in.Close()

	block, err := armor.Decode(in)
	if err != nil {
		log.Err(err).Msg("cannot decode openpgp armor")
	}

	if block.Type != openpgp.PublicKeyType {
		log.Err(errors.New("invalid private key file")).Msg("cannot decode private key")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		log.Err(err).Msg("cannot decode private key")
	}

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		log.Err(errors.New("invalid public key")).Msg("cannot parse public key")
	}
	return key
}

func decodeSignature(data string) *packet.Signature {
	in := strings.NewReader(data)

	block, err := armor.Decode(in)
	if err != nil {
		log.Err(err).Msg("cannot decode OpenPGP Armor")
	}

	if block.Type != openpgp.SignatureType {
		log.Err(errors.New("invalid signature file")).Msg("cannotc decode signature")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		log.Err(err).Msg("cannot readi signature")
	}

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		log.Err(errors.New("Invalid signature")).Msg("cannot parse signature")
	}
	return sig
}

func decodeSignatureFromFile(filename string) *packet.Signature {

	// open ascii armored public key
	in, err := os.Open(filename)
	if err != nil {
		log.Err(err).Msg("cannot open public key")
	}
	defer in.Close()

	block, err := armor.Decode(in)
	if err != nil {
		log.Err(err).Msg("cannot decode OpenPGP Armor")
	}

	if block.Type != openpgp.SignatureType {
		log.Err(errors.New("invalid signature file")).Msg("cannotc decode signature")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		log.Err(err).Msg("cannot readi signature")
	}

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		log.Err(errors.New("Invalid signature")).Msg("cannot parse signature")
	}
	return sig
}

func signString(input string, publicKeyPath, privateKeyPath string) string {
	pubKey := decodePublicKey(publicKeyPath)
	privKey := decodePrivateKey(privateKeyPath)

	signer := createEntityFromKeys(2048, pubKey, privKey)

	var buf bytes.Buffer

	err := openpgp.ArmoredDetachSign(&buf, signer, strings.NewReader(input), nil)
	if err != nil {
		log.Err(err).Msg("cannot sign file")
	}
	return buf.String()
}

func verifySignature(content, signatureString, publicKeyFilePath string) error{
	pubKey := decodePublicKey(publicKeyFilePath)
	sig := decodeSignature(signatureString)

	hash := sig.Hash.New()
	r := strings.NewReader(content)
	io.Copy(hash, r)

	return pubKey.VerifySignature(hash, sig)
}

func createEntityFromKeys(keyBits int, pubKey *packet.PublicKey, privKey *packet.PrivateKey) *openpgp.Entity {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: keyBits,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e
}

func generateKeys() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	priv, err := os.Create("./private.pem")
	if err != nil {
		panic(err)
	}
	defer priv.Close()

	pub, err := os.Create("./public.pem")
	if err != nil {
		panic(err)
	}
	defer pub.Close()

	encodePrivateKey(priv, key)
	encodePublicKey(pub, key)
}
