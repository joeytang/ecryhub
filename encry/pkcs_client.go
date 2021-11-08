package encry

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

type pkcsClient struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func (this *pkcsClient) Encrypt(plaintext []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, this.publicKey, plaintext)
}
func (this *pkcsClient) Decrypt(ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, this.privateKey, ciphertext)
}

func (this *pkcsClient) Sign(src []byte, hash crypto.Hash) ([]byte, error) {
	h := hash.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, this.privateKey, hash, hashed)
}

func (this *pkcsClient) Verify(src []byte, sign []byte, hash crypto.Hash) error {
	h := hash.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.VerifyPKCS1v15(this.publicKey, hash, hashed, sign)
}

//默认客户端，pkcs8私钥格式，pem编码
func NewDefault(privateKey, publicKey string) (Cipher, error) {
	blockPri, _ := pem.Decode([]byte(privateKey))
	if blockPri == nil {
		return nil, errors.New("private key error")
	}

	blockPub, _ := pem.Decode([]byte(publicKey))
	if blockPub == nil {
		return nil, errors.New("public key error")
	}

	return New(blockPri.Bytes, blockPub.Bytes, PKCS8)
}

func New(privateKey, publicKey []byte, privateKeyType Type) (Cipher, error) {

	priKey, err := genPriKey(privateKey, privateKeyType)
	if err != nil {
		return nil, err
	}
	pubKey, err := genPubKey(publicKey)
	if err != nil {
		return nil, err
	}
	return &pkcsClient{privateKey: priKey, publicKey: pubKey}, nil
}

func genPubKey(publicKey []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}

func genPriKey(privateKey []byte, privateKeyType Type) (*rsa.PrivateKey, error) {
	var priKey *rsa.PrivateKey
	var err error
	switch privateKeyType {
	case PKCS1:
		{
			priKey, err = x509.ParsePKCS1PrivateKey([]byte(privateKey))
			if err != nil {
				return nil, err
			}
		}
	case PKCS8:
		{
			prkI, err := x509.ParsePKCS8PrivateKey([]byte(privateKey))
			if err != nil {
				return nil, err
			}
			priKey = prkI.(*rsa.PrivateKey)
		}
	default:
		{
			return nil, errors.New("unsupport private key type")
		}
	}
	return priKey, nil
}

func Encrypt(plaintext []byte, pub *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext)
}
func EncryptBase64(plaintext []byte, pub *rsa.PublicKey, maxEncryBlock int) ([]byte, error) {
	inputLenth := len(plaintext)
	offset := 0
	leftLenth := inputLenth - offset
	outResult := make([]byte, 0)
	// 对数据分段加密
	for leftLenth > 0 {
		var data []byte
		var err error
		if leftLenth > maxEncryBlock {
			data, err = Encrypt(plaintext[offset:offset+maxEncryBlock], pub)
		} else {
			data, err = Encrypt(plaintext[offset:], pub)
		}
		if err != nil {
			fmt.Println("encry error", err)
			return nil, err
		}
		offset = offset + maxEncryBlock
		leftLenth = inputLenth - offset
		outResult = append(outResult, data...)
	}
	out := base64.StdEncoding.EncodeToString(outResult)
	return []byte(out), nil
}
func Decrypt(ciphertext []byte, private *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, private, ciphertext)
}
func DecryptBase64(ciphertext []byte, private *rsa.PrivateKey, maxDecryBlock int) ([]byte, error) {
	srcBase64, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		fmt.Println("DecodeString:", err)
		return nil, err
	}
	inputLenth := len(srcBase64)
	offset := 0
	leftLenth := inputLenth - offset
	outResult := make([]byte, 0)
	// 对数据分段加密
	for leftLenth > 0 {
		var data []byte
		var err error
		if leftLenth > maxDecryBlock {
			data, err = Decrypt(srcBase64[offset:offset+maxDecryBlock], private)
		} else {
			data, err = Decrypt(srcBase64[offset:], private)
		}
		if err != nil {
			fmt.Println("decry error: inputlen:", inputLenth, ", offset:", offset, err)
			return nil, err
		}
		offset = offset + maxDecryBlock
		leftLenth = inputLenth - offset
		outResult = append(outResult, data...)
	}
	return outResult, nil
}

func Sign(src []byte, hash crypto.Hash, private *rsa.PrivateKey) ([]byte, error) {
	h := hash.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, private, hash, hashed)
}
func SignBase64(src []byte, hash crypto.Hash, private *rsa.PrivateKey) ([]byte, error) {
	data, err := Sign(src, hash, private)
	out := base64.StdEncoding.EncodeToString(data)
	return []byte(out), err
}

func Verify(src []byte, sign []byte, hash crypto.Hash, pub *rsa.PublicKey) error {
	h := hash.New()
	h.Write(src)
	hashed := h.Sum(nil)
	return rsa.VerifyPKCS1v15(pub, hash, hashed, sign)
}
func VerifyBase64(src []byte, sign []byte, hash crypto.Hash, pub *rsa.PublicKey) error {
	signBase64, err := base64.StdEncoding.DecodeString(string(sign))
	if err != nil {
		fmt.Println("DecodeString:", err)
		return err
	}
	return Verify(src, signBase64, hash, pub)
}
func GetPrivateKeyWithBase64(privateKey string, privateKeyType Type) (*rsa.PrivateKey, error) {
	key, _ := base64.StdEncoding.DecodeString(privateKey)
	return genPriKey(key, privateKeyType)
}
func GetPublicKeyWithBase64(publicKey string) (*rsa.PublicKey, error) {
	key, _ := base64.StdEncoding.DecodeString(publicKey)
	return genPubKey(key)
}
func RsaEncryptWithBase64(originalData, publicKey string) (string, error) {
	pub, _ := GetPublicKeyWithBase64(publicKey)
	d, err := Encrypt([]byte(originalData), pub)
	return string(d), err
}
func RsaDecryptPKCS8WithBase64(originalData, privateKey string) (string, error) {
	pri, _ := GetPrivateKeyWithBase64(privateKey, PKCS8)
	d, err := Decrypt([]byte(originalData), pri)
	return string(d), err
}

// 签名
func RsaSignWithMd5PKCS8(data string, prvKey string) (sign string, err error) {
	//如果密钥是urlSafeBase64的话需要处理下
	privateKey, _ := GetPrivateKeyWithBase64(prvKey, PKCS8)
	d, err := SignBase64([]byte(data), crypto.MD5, privateKey)
	return string(d), err
}

// 验签
func RsaVerifySignWithMd5(originalData, signData, pubKey string) error {
	pub, _ := GetPublicKeyWithBase64(pubKey)
	return VerifyBase64([]byte(originalData), []byte(signData), crypto.MD5, pub)
}
