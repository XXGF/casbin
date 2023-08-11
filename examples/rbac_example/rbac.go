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

	// 定义角色匹配器
	//enforcer.AddFunction("g", func(args ...interface{}) (interface{}, error) {
	//	requestSub := args[0].(string)
	//	policySub := args[1].(string)
	//	requestDom := args[2].(string)
	//
	//	// 自定义角色匹配逻辑
	//	// 这里可以根据实际需求进行角色匹配的判断
	//	// 返回 true 表示匹配成功，否则返回 false
	//	return requestSub == policySub && requestDom == "domain1", nil
	//})

	// 加载策略
	enforcer.LoadPolicy()

	// 进行访问控制检查
	requestSub := "admin"
	requestDom := "domain1"
	requestObj := "data1"
	requestAct := "read"
	result, _ := enforcer.Enforce(requestSub, requestDom, requestObj, requestAct)

	fmt.Println(result) // 输出: true
}
