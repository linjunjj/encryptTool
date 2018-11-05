package encryptTool

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/pkcs12"
	"io/ioutil"
	"net/url"
)

//初始使用的配置
type Config struct {
	// pfx 证书路径,和同时传入PrivatePath和CertPath 效果一样
	PfxPath string
	// pfx 证书的密码
	PfxPwd string
	//证书是否需要base64解密
	IsDecode bool
	// 验签私钥证书地址，传入pfx此路径可不传
	PrivatePath string
	// 公钥证书地址,传入pfx此路径可以不传
	PublicPath string
	// pfx加密证书地址
	EncryptCertPath string
	//	加密采用的模式
	Mode Hash
}

// 证书信息结构体
type Cert struct {
	// 私钥 签名使用
	Private *rsa.PrivateKey
	// 证书 与私钥为一套
	Cert *x509.Certificate
	// 签名证书ID
	CertId string
	// 加密证书
	EncryptCert *x509.Certificate
	// 公钥 加密验签使用
	Public *rsa.PublicKey
	// 加密公钥ID
	EncryptId string
	//	加密采用的模式
	Mode Hash
}

func NewInstance(config *Config) *Cert {
	if config.Mode == 0 {
		panic("请输入验签模式")
	}

	if config.PfxPwd != "" && config.PfxPath != "" {
		private, certdata, _ := parserPfxToCert(config.PfxPath, config.PfxPwd, config.IsDecode)
		encryptCert, _ := parseCertificateFromFile(config.EncryptCertPath)
		//certData.Public = certData.EncryptCert.PublicKey.(*rsa.PublicKey)
		return &Cert{
			Mode:        config.Mode,
			Private:     private,
			Cert:        certdata,
			EncryptCert: encryptCert,
		}
	} else if config.PublicPath != "" && config.PrivatePath != "" {
		private, _ := parsePrivateFromFile(config.PrivatePath)
		public, _ := parsePublicFromFile(config.PublicPath)
		return &Cert{
			Mode:    config.Mode,
			Private: private,
			Public:  public,
		}
	} else {
		panic("请输入有效初始数据")
	}

}

// 根据PFX文件和密码来解析出里面包含的私钥(rsa)和证书(x509)
func parserPfxToCert(path string, password string, isbase64decode bool) (private *rsa.PrivateKey, cert *x509.Certificate, err error) {
	var pfxData []byte
	pfxData, err = ioutil.ReadFile(path)
	if isbase64decode {
		fmt.Println(string(pfxData))
		pfxData, _ = base64Decode(string(pfxData))

	}
	if err != nil {
		return
	}
	var priv interface{}
	priv, cert, err = pkcs12.Decode(pfxData, password)
	if err != nil {
		return
	}
	private = priv.(*rsa.PrivateKey)
	return
}

// 根据文件名解析出私钥 ,文件必须是rsa 私钥格式。
func parsePrivateFromFile(path string) (private *rsa.PrivateKey, err error) {
	// Read the private key
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		err = fmt.Errorf("read key file: %s", err)
		return
	}

	// Extract the PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		err = fmt.Errorf("bad key data: %s", "not PEM-encoded")
		return
	}

	if block.Type == "RSA PRIVATE KEY" {

		if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
			err = fmt.Errorf("unknown key type %q, want %q", got, want)
			return
		}
		private, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			err = fmt.Errorf("bad private key: %s", err)
			return
		}
		return

	} else if block.Type == "PRIVATE KEY" {
		if got, want := block.Type, "PRIVATE KEY"; got != want {
			err = fmt.Errorf("unknown key type %q, want %q", got, want)
			return
		}
		privates, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		private = privates.(*rsa.PrivateKey)
		if err != nil {
			err = fmt.Errorf("bad private key: %s", err)
		}
	}
	return
}

// 根据文件名解析出公钥 ,文件必须是rsa 公钥格式。
func parsePublicFromFile(path string) (private *rsa.PublicKey, err error) {
	// Read the private key
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		err = fmt.Errorf("read key file: %s", err)
		return
	}

	// Extract the PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		err = fmt.Errorf("bad key data: %s", "not PEM-encoded")
		return
	}

	if block.Type == "RSA PRIVATE KEY" {

		if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
			err = fmt.Errorf("unknown key type %q, want %q", got, want)
			return
		}
		private, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			err = fmt.Errorf("bad private key: %s", err)
			return
		}
		return

	}
	return
}

// 根据文件名解析出证书
func parseCertificateFromFile(path string) (cert *x509.Certificate, err error) {
	// Read the verify sign certification key
	pemData, err := ioutil.ReadFile(path)
	fmt.Println(pemData)
	if err != nil {
		return
	}

	// Extract the PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		err = fmt.Errorf("bad key data: %s", "not PEM-encoded")
		return
	}
	if got, want := block.Type, "CERTIFICATE"; got != want {
		err = fmt.Errorf("unknown key type %q, want %q", got, want)
		return
	}

	// Decode the certification
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		err = fmt.Errorf("bad private key: %s", err)
		return
	}
	return
}

// 利用加密证书公钥对数据加密
func (c *Cert) EncryptData(data string) (res string, err error) {
	if c.EncryptId == "" {
		err = fmt.Errorf("请先配置加密证书信息")
		return
	}
	rng := rand.Reader
	signer, err := rsa.EncryptPKCS1v15(rng, c.Public, []byte(data))
	res = base64Encode(signer)
	return
}

// sign 做签
func (c *Cert) SignData(request map[string]string) (signdata string, err error) {
	str := mapSortByKey(request, "=", "&")
	rng := rand.Reader
	var signer []byte
	switch c.Mode {
	case SHA256:
		hashed := sha256.Sum256([]byte(fmt.Sprintf("%x", sha256.Sum256([]byte(str)))))
		signer, err = rsa.SignPKCS1v15(rng, c.Private, crypto.SHA256, hashed[:])
		if err != nil {
			return "", err
		}
	case MD5:
		hashed := md5.Sum([]byte(str))
		signer, err = rsa.SignPKCS1v15(rng, c.Private, crypto.MD5, hashed[:])
		if err != nil {
			return "", err
		}
	case SHA1:
		hashed := sha1.Sum([]byte(fmt.Sprintf("%x", sha1.Sum([]byte(str)))))
		signer, err = rsa.SignPKCS1v15(rng, c.Private, crypto.SHA1, hashed[:])
		if err != nil {
			return "", err
		}
	}
	return base64Encode(signer), nil
}

// 返回数据验签Sha256
func (c *Cert) VerifyData(vals url.Values) (res interface{}, err error) {
	var signature string
	kvs := map[string]string{}
	for k := range vals {
		if k == "signature" {
			signature = vals.Get(k)
			continue
		}
		if vals.Get(k) == "" {
			continue
		}
		kvs[k] = vals.Get(k)
	}
	str := mapSortByKey(kvs, "=", "&")
	hashed := sha256.Sum256([]byte(fmt.Sprintf("%x", sha256.Sum256([]byte(str)))))
	var inSign []byte
	inSign, err = base64Decode(signature)
	if err != nil {
		return nil, fmt.Errorf("解析返回signature失败 %v", err)
	}

	err = rsa.VerifyPKCS1v15(c.Public, crypto.SHA256, hashed[:], inSign)
	if err != nil {
		return nil, fmt.Errorf("返回数据验签失败 ERR:%v", err)
	}
	return kvs, nil
}
