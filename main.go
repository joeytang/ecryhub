package main

import (
	"crypto"
	"crypto/rsa"
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/joeytang/ecryhub.git/encry"
	"io/ioutil"
	"net/http"
)

var port int
var pub string
var pri string
var thirdpub string

type ApiReturn struct {
	Ret  int         `json:"ret"`
	Msg  string      `json:"msg,omitempty"`
	Data interface{} `json:"data,omitempty"`
}

var PUB *rsa.PublicKey
var PRI *rsa.PrivateKey
var THIRD_PUB *rsa.PublicKey

/**
 * RSA最大加密明文大小
 */
var MAX_ENCRYPT_BLOCK = 117

/**
 * RSA最大解密密文大小
 */
var MAX_DECRYPT_BLOCK = 128

func main() {

	flag.IntVar(&port, "port", 60240, "port")
	flag.StringVar(&pub, "pub", "/etc/pub.txt", "public key")
	flag.StringVar(&pri, "pri", "/etc/pri.txt", "private key")
	flag.StringVar(&thirdpub, "thirdpub", "/etc/thirdpub.txt", "third party public key")
	flag.Parse()

	pubdata, err := ioutil.ReadFile(pub)
	if err != nil {
		fmt.Println("load pub key error")
		return
	}
	pridata, err := ioutil.ReadFile(pri)
	if err != nil {
		fmt.Println("load pri key error")
		return
	}
	thirdpubdata, err := ioutil.ReadFile(thirdpub)
	if err != nil {
		fmt.Println("load thirdpart pub key error")
		return
	}
	PUB, err = encry.GetPublicKeyWithBase64(string(pubdata))
	if err != nil {
		fmt.Println("generate pub key error")
		return
	}
	PRI, err = encry.GetPrivateKeyWithBase64(string(pridata), encry.PKCS8)
	if err != nil {
		fmt.Println("generate pri key error")
		return
	}
	THIRD_PUB, err = encry.GetPublicKeyWithBase64(string(thirdpubdata))
	if err != nil {
		fmt.Println("generate thirdpart pub key error")
		return
	}
	// 1.创建路由
	r := gin.Default()
	// 2.绑定路由规则，执行的函数
	// gin.Context，封装了request和response
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "hello World!")
	})
	r.POST("/encrypt", func(c *gin.Context) {
		var p = struct {
			Data   string `json:"data"`
			NoSign bool   `json:"noSign"`
		}{}
		if err := c.ShouldBind(&p); err != nil {
			c.JSON(http.StatusOK, ApiReturn{
				Ret: -1,
				Msg: "request parameters format error",
			})
			return
		}
		pk := THIRD_PUB
		encryDate, err := encry.EncryptBase64([]byte(p.Data), pk, MAX_ENCRYPT_BLOCK)
		if err != nil {
			c.JSON(http.StatusOK, ApiReturn{
				Ret: -1,
				Msg: err.Error(),
			})
			return
		}
		var sign []byte
		if !p.NoSign {
			sign, err = encry.SignBase64([]byte(p.Data), crypto.MD5, PRI)
			if err != nil {
				c.JSON(http.StatusOK, ApiReturn{
					Ret: -1,
					Msg: err.Error(),
				})
				return
			}
		}
		if c.IsAborted() {
			return
		}
		c.JSON(http.StatusOK, ApiReturn{
			Ret: 1,
			Data: map[string]string{
				"encryptData": string(encryDate),
				"sign":        string(sign),
			},
		})
	})
	r.POST("/decrypt", func(c *gin.Context) {
		var p = struct {
			EncryptData string `json:"encryptData"`
			Sign        string `json:"sign"`
		}{}
		if err := c.ShouldBind(&p); err != nil {
			c.JSON(http.StatusOK, ApiReturn{
				Ret: -1,
				Msg: "request parameters format error",
			})
			return
		}
		decryDate, err := encry.DecryptBase64([]byte(p.EncryptData), PRI, MAX_DECRYPT_BLOCK)
		if err != nil {
			c.JSON(http.StatusOK, ApiReturn{
				Ret: -1,
				Msg: err.Error(),
			})
			return
		}
		if len(p.Sign) != 0 {
			err = encry.VerifyBase64(decryDate, []byte(p.Sign), crypto.MD5, THIRD_PUB)
			if err != nil {
				c.JSON(http.StatusOK, ApiReturn{
					Ret: -1,
					Msg: err.Error(),
				})
				return
			}
		}
		if c.IsAborted() {
			return
		}
		c.JSON(http.StatusOK, ApiReturn{
			Ret: 1,
			Data: map[string]string{
				"decryptData": string(decryDate),
			},
		})
	})
	r.POST("/verify_sign", func(c *gin.Context) {
		var p = struct {
			Hash string `json:"hash"`
			Sign string `json:"sign"`
		}{}
		if err := c.ShouldBind(&p); err != nil {
			c.JSON(http.StatusOK, ApiReturn{
				Ret: -1,
				Msg: "request parameters format error",
			})
			return
		}
		err := encry.VerifyBase64WithHashed([]byte(p.Hash), []byte(p.Sign), crypto.SHA256, PUB)
		if err != nil {
			c.JSON(http.StatusOK, ApiReturn{
				Ret: -1,
				Msg: err.Error(),
			})
			return
		}
		if c.IsAborted() {
			return
		}
		c.JSON(http.StatusOK, ApiReturn{
			Ret:  1,
			Data: map[string]string{},
		})
	})
	// 3.监听端口，默认在8080
	// Run("里面不指定端口号默认为8080")
	r.Run(fmt.Sprintf(":%d", port))
}
