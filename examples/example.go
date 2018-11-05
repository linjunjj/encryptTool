package examples

import (
	"fmt"
	"git.coding.net/greatLIU/sbt7-merchant-service/utils"
)

//加密数据 rsa加密
func example() {

	postData := make(map[string]string)
	postData["tranCode"] = "T002"
	postData["agentId"] = "加密的数据"

	ras := new(utils.Config)
	ras.IsDecode = true
	ras.PublicPath = "./cert/21502900_private_key_2048.pem"
	ras.PrivatePath = "./cert/21502900_private_key_2048.pem"
	a := utils.NewInstance(ras)
	result, err := a.SignDataBySHA1(postData)
	if err != nil {
		fmt.Errorf("加密失败")
	}
	fmt.Printf(string(result))
}
