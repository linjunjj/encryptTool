package examples

import (
	"encryptTool"
	"fmt"
)

//加密数据 rsa加密
func examples() {
	postData := make(map[string]string)
	postData["tranCode"] = "T002"
	postData["agentId"] = "加密的数据"
	ras := new(encryptTool.Config)
	ras.IsDecode = true
	//采用rsawithmd5加密方式
	ras.Mode = encryptTool.MD5
	ras.PublicPath = "./cert/21502900_private_key_2048.pem"
	ras.PrivatePath = "./cert/21502900_private_key_2048.pem"
	a := encryptTool.NewInstance(ras)
	result, err := a.SignData(postData)
	if err != nil {
		fmt.Errorf("加密失败")
	}
	fmt.Printf(string(result))
}
