package main

import (
	"errors"
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist/file-adapter"
	"regexp"
	"strings"
)

var PathMap map[string]struct{}

func main() {
	// 初始化 pathMap
	PathMap = map[string]struct{}{}
	PathMap["/a"] = struct{}{}
	PathMap["/a/b"] = struct{}{}
	PathMap["/a/b/c"] = struct{}{}

	//pathMap["/a/b/c/d"] = struct{}{}

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
	m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && regexMatch1(r.obj, p.obj) == true && r.act == p.act
	`)

	// 创建Casbin Enforcer
	adapter := fileadapter.NewAdapter("./rbac_policy.csv")
	enforcer, _ := casbin.NewEnforcer(m, adapter)

	// 路径匹配函数
	f := func(args ...interface{}) (interface{}, error) {

		if err := validateVariadicArgs(2, args...); err != nil {
			return false, fmt.Errorf("%s: %s", "regexMatch1", err)
		}
		// 请求的path
		name1 := args[0].(string)
		// Policy的path
		name2 := args[1].(string)
		// 前缀匹配成功，确定是否有更精确的配置路径存在
		if bool(RegexMatch(name1, name2)) {
			if HasMoreExactPath(name1, name2) {
				return false, nil
			}
			return true, nil
		}
		return false, nil
	}

	enforcer.AddFunction("regexMatch1", f)

	// 加载策略
	enforcer.LoadPolicy()

	// 进行访问控制检查
	requestSub := "user_10000324"
	requestDom := "tenant_1"
	requestObj := "/a/b/c/d"
	requestAct := "-"

	result, _ := enforcer.Enforce(requestSub, requestDom, requestObj, requestAct)
	//fmt.Println(result) // 输出: true
	fmt.Println(result)
}

// validate the variadic parameter size and type as string
func validateVariadicArgs(expectedLen int, args ...interface{}) error {
	if len(args) != expectedLen {
		return fmt.Errorf("expected %d arguments, but got %d", expectedLen, len(args))
	}

	for _, p := range args {
		_, ok := p.(string)
		if !ok {
			return errors.New("argument must be a string")
		}
	}

	return nil
}

// RegexMatch determines whether key1 matches the pattern of key2 in regular expression.
func RegexMatch(key1 string, key2 string) bool {
	res, err := regexp.MatchString(key2, key1)
	if err != nil {
		panic(err)
	}
	return res
}

// HasMoreExactPath 有没有更精确的路由权限配置存在
func HasMoreExactPath(name1, name2 string) bool {
	// 1. 请求的路径和当前Policy中的路径，完全匹配
	if name1 == name2 {
		return false
	}
	// 2. 在全局的路径map中找到请求的路径，说明有精确的路径配置
	if _, ok := PathMap[name1]; ok {
		return true
	}

	// 3. 当前Policy中的路径的结尾有几种情况：*、/、/*
	if strings.HasSuffix(name2, "*") {
		name2 = name2[:strings.LastIndex(name2, "*")]
		if name1 == name2 {
			return false
		}
	}
	if strings.HasSuffix(name2, "/") {
		name2 = name2[:strings.LastIndex(name2, "/")]
		if name1 == name2 {
			return false
		}
	}

	// 4. 在for循环中不断的，按 / 截断请求的路径，然后判断截断后的路径，是否在全局路径map中找到更精确的匹配
	for {
		// 4.1 获取lastIdx
		lastIdx := strings.LastIndex(name1, "/")
		if lastIdx == -1 {
			break
		}
		// 3. 对请求路径进行截断
		name1 = name1[:lastIdx]
		// 4. 如果截断后的请求路径和当前Policy的路径一致。
		if name1 == name2 {
			return false
		}
		// 5. 判断在全局的map中，是否存在截断后的请求路径的权限配置。
		if IsPathExist(name1) {
			return true
		}
	}
	return false
}

// IsPathExist 路径是否在全局Map中存在
func IsPathExist(path string) bool {
	if _, ok := PathMap[path]; ok {
		return true
	}
	if _, ok := PathMap[path+"*"]; ok {
		return true
	}
	if _, ok := PathMap[path+"/"]; ok {
		return true
	}
	if _, ok := PathMap[path+"/*"]; ok {
		return true
	}
	return false
}
