package crypto

import (
	"bytes"
	"io"

	"github.com/dfinity-side-projects/go-dfinity-crypto/bls"

	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
)

func UnmarshalBLSPrivateKey(data []byte) (PrivKey, error) {
	var sk bls.SecretKey
	err := sk.SetLittleEndian(data)
	if err != nil {
		return nil, err
	}
	return &BLSPrivKey{Key: sk}, nil
}

func UnmarshalBLSPublicKey(data []byte) (PubKey, error) {
	var pk bls.PublicKey
	err := pk.Deserialize(data)
	if err != nil {
		return nil, err
	}

	return &BLSPubKey{Key: pk}, nil
}

type BLSPrivKey struct {
	Key bls.SecretKey
}

func (k *BLSPrivKey) Raw() ([]byte, error) {
	return k.Key.GetLittleEndian(), nil
}

func (k *BLSPrivKey) Equals(key Key) bool {
	b0, err := k.Raw()
	if err != nil {
		return false
	}

	b1, err := key.Raw()
	if err != nil {
		return false
	}

	return bytes.Equal(b0, b1)
}

func (k *BLSPrivKey) Sign(msg []byte) ([]byte, error) {
	return k.Key.Sign(string(msg)).Serialize(), nil
}

// Type returns the key type
func (k *BLSPrivKey) Type() pb.KeyType {
	return pb.KeyType_BLS
}

func (k *BLSPrivKey) GetPublic() PubKey {
	return &BLSPubKey{Key: *k.Key.GetPublicKey()}
}

type BLSPubKey struct {
	Key bls.PublicKey
}

func (k *BLSPubKey) Raw() ([]byte, error) {
	return k.Key.Serialize(), nil
}

func (k *BLSPubKey) Type() pb.KeyType {
	return pb.KeyType_ECDSA
}

func (k *BLSPubKey) Equals(key Key) bool {
	b0, err := k.Raw()
	if err != nil {
		return false
	}

	b1, err := key.Raw()
	if err != nil {
		return false
	}

	return bytes.Equal(b0, b1)
}

func (k *BLSPubKey) Verify(data []byte, sig []byte) (bool, error) {
	var sign bls.Sign
	err := sign.Deserialize(sig)
	if err != nil {
		return false, err
	}

	return sign.Verify(&k.Key, string(data)), nil
}

// GenerateBLSKeyPair generates a new BLS private and public key
func GenerateBLSKeyPair(src io.Reader) (PrivKey, PubKey, error) {
	var sk bls.SecretKey
	sk.SetByCSPRNG()

	pk := sk.GetPublicKey()

	return &BLSPrivKey{Key: sk}, &BLSPubKey{Key: *pk}, nil
}
