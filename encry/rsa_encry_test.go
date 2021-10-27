package encry

import (
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
	if err != nil {
		fmt.Println("generate pri key error")
		return
	}
	thirdpub, err := GetPublicKeyWithBase64(string(thirdpubdata))
	if err != nil {
		fmt.Println("generate thirdpart pub key error")
		return
	}
	fmt.Sprintf("%v", thirdpub)
	var raw = "aaaa"
	encrydata, _ := EncryptBase64([]byte(raw), pub)
	fmt.Println("encry: ", string(encrydata))
	data, _ := DecryptBase64(encrydata, pri)
	fmt.Println("decry: ", string(data))
}
