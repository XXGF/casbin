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
	r = sub, obj, act
	r2 = sub, obj, act
	
	[policy_definition]
	p = sub, obj, act
	p2 = sub_rule, obj, act, eft
	
	[role_definition]
	g = _, _
	
	[policy_effect]
	e = some(where (p.eft == allow))
	
	[matchers]
	#RABC
	m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
	#ABAC
	m2 = eval(p2.sub_rule) && r2.obj == p2.obj && r2.act == p2.act
	`)

	// 创建Casbin Enforcer
	adapter := fileadapter.NewAdapter("./multi_policy.csv")
	e, _ := casbin.NewEnforcer(m, adapter)

	// 加载策略
	e.LoadPolicy()

	// 在后缀将参数传入NewEnforceContext，例如2或3，它将创建 r2,p2,等。
	enforceContext := casbin.NewEnforceContext("2")
	// You can also specify a certain type individually
	enforceContext.EType = "e"
	// Don't pass in EnforceContext,the default is r,p,e,m
	//e.Enforce("alice", "data2", "read")        // true
	// pass in EnforceContext
	result1, _ := e.Enforce(enforceContext, struct{ Age int }{Age: 70}, "/data1", "read") //false
	result2, _ := e.Enforce(enforceContext, struct{ Age int }{Age: 30}, "/data1", "read") //true

	fmt.Println(result1) // 输出: false
	fmt.Println(result2) // 输出: true

}
