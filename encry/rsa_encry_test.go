package encry

import (
	"crypto"
	"fmt"
	"io/ioutil"
	"testing"
)

func Test_GenKey(t *testing.T) {

	//err:=RSAGenKey(4096)
	//if err!=nil {
	//	fmt.Println(err)
	//	return
	//}
	//fmt.Println("秘钥生成成功！")
	//str:="山重水复疑无路，柳暗花明又一村！"
	//fmt.Println("加密之前的数据为：",string(str))
	//data,err:=EncyptogRSA([]byte(str),"publicKey.pem")
	//data,err=DecrptogRSA(data,"privateKey.pem")
	//fmt.Println("加密之后的数据为：",string(data))
}
func Test_Decry(t *testing.T) {
	pubdata, err := ioutil.ReadFile("/Users/tanghc/Documents/pubkey1.txt")
	if err != nil {
		fmt.Println("load pub key error")
		return
	}
	pridata, err := ioutil.ReadFile("/Users/tanghc/Documents/prikey1.txt")
	if err != nil {
		fmt.Println("load pri key error")
		return
	}
	thirdpubdata, err := ioutil.ReadFile("/Users/tanghc/Documents/thirdpubkey1.txt")
	if err != nil {
		fmt.Println("load thirdpart pub key error")
		return
	}
	pub, err := GetPublicKeyWithBase64(string(pubdata))
	if err != nil {
		fmt.Println("generate pub key error")
		return
	}
	pri, err := GetPrivateKeyWithBase64(string(pridata), PKCS8)
	//pri, err := GetPrivateKeyWithBase64(string(pridata), PKCS1)
	if err != nil {
		fmt.Println("generate pri key error")
		return
	}
	thirdpub, err := GetPublicKeyWithBase64(string(thirdpubdata))
	if err != nil {
		fmt.Println("generate thirdpart pub key error")
		return
	}
	fmt.Sprintf("pub:%v, pri:%v, thirdpub:%v", pub, pri, thirdpub)
	//var raw = "aaaa"
	//encrydata, _ := EncryptBase64([]byte(raw), pub)
	//fmt.Println("encry: ", string(encrydata))
	encrydata := "Qu/d9A329yqTaDfPAEJek/xMutC3jO07wonL/BZsRw9EZiBm3i7gYvXcPUx7kJQTTabJvyybCIjAi9qjgE81VJuwbSwcdsgNakllyYrqDz0gAGPv5hkz5Sk8Idi9wj9wkCBX2RK77pANU5H3j1URA6UjhJnZE0Wlo6WZl6Qwxyo="
	data, err := DecryptBase64([]byte(encrydata), pri)
	fmt.Println("decry: ", string(data), err)
	ss := "QE4S2t26Fgd6hEDqDW88w4CtmEXFdHQoAaAbeFtjmeD17AjQnwtjw0JWNhl3VidccXvc5cyDYmTwufG64FZuyHR6wWQiMck8Q8Iy/NMVUtFQZUhDMPCg6anK6ACQgMz/FiIu+vyrsGVgyu9OJZDk1FtY+AHdKRmYHqCvxaPXjmc="
	err = VerifyBase64(data, []byte(ss), crypto.MD5, thirdpub)
	fmt.Println("verify: ", err)
}
