package main

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist/file-adapter"
	"sync"
	"time"
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

	// 加载策略
	enforcer.LoadPolicy()
	fmt.Println("LoadPolicy first finished")

	// 定时从数据库中加载策略到内存中
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			<-ticker.C
			//s := time.Now()
			//fmt.Printf("%v LoadPolicy start .....\n", time.Now())
			//enforcer.ClearPolicy()
			//fmt.Printf("%v ClearPolicy finish .....\n", time.Now())
			enforcer.LoadPolicy()
			//e := time.Now()
			//fmt.Printf("%v LoadPolicy end ..... cost=%v\n", time.Now(), e.Sub(s))
		}
	}()

	//// 增加策略并持久化
	//enforcer.EnableAutoSave(true)
	//r, err := enforcer.AddPermissionsForUser("user_10000324", []string{"tenant_1", "/adservice/xxx", "-"})
	//fmt.Println(r, err)

	//go func() {
	//	ticker := time.NewTicker(3 * time.Second)
	//	defer ticker.Stop()
	//	for {
	//		<-ticker.C
	//		s := time.Now()
	//		fmt.Printf("%v AddPermissionsForUser start .....\n", time.Now())
	//		//enforcer.ClearPolicy()
	//		//fmt.Printf("%v ClearPolicy finish .....\n", time.Now())
	//		r, err := enforcer.AddPermissionsForUser("user_10000324", []string{"tenant_1", "/adservice/xxx", "-"})
	//		fmt.Println(r, err)
	//		e := time.Now()
	//		fmt.Printf("%v AddPermissionsForUser end ..... cost=%v\n", time.Now(), e.Sub(s))
	//	}
	//}()

	// 进行访问控制检查
	requestSub := "user_10000324"
	requestDom := "tenant_1"
	requestObj := "/a/b/c"
	requestAct := "-"

	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			for {
				result, _ := enforcer.Enforce(requestSub, requestDom, requestObj, requestAct)
				//fmt.Println(result) // 输出: true
				if !result {
					fmt.Printf("%v %d --------------> false come out\nç", time.Now(), i)
				} else {
					//fmt.Printf("%v %d true \nç", time.Now(), i)
				}
			}
		}()
	}
	wg.Wait()
}
