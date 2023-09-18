package main

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist/file-adapter"
)

func main() {
	// 定义Casbin模型
	// 创建一个Casbin模型
	m, _ := model.NewModelFromString(`
		[request_definition]
	r = sub, dom, obj, act
	
	[policy_definition]
	p = sub, dom, obj, act
	
	[role_definition]
	g = _, _, _
	
	[policy_effect]
	e = some(where (p.eft == allow))
	
	[matchers]
	m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && regexMatch(r.obj, p.obj) == true && r.act == p.act
	`)

	// 创建Casbin Enforcer
	adapter := fileadapter.NewAdapter("./rbac_policy.csv")
	enforcer, _ := casbin.NewEnforcer(m, adapter)

	// 添加自定义函数
	//enforcer.AddFunction("regexMatch1", func(args ...interface{}) (interface{}, error) {
	//	return true, nil
	//})

	// 加载策略
	enforcer.LoadPolicy()

	// 进行访问控制检查
	requestSub := "user_10000324"
	requestDom := "tenant_1"
	requestObj := "agent_3"
	requestAct := "agent_10001"

	//requestSub := "user_10000324"
	//requestDom := "tenant_1"
	//requestObj := "/adservice/list"
	//requestAct := "-"

	result, _ := enforcer.Enforce(requestSub, requestDom, requestObj, requestAct)

	fmt.Println(result) // 输出: true
}
