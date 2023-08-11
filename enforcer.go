// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package casbin

import (
	"errors"
	"fmt"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/casbin/casbin/v2/effector"
	"github.com/casbin/casbin/v2/log"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/casbin/casbin/v2/rbac"
	defaultrolemanager "github.com/casbin/casbin/v2/rbac/default-role-manager"
	"github.com/casbin/casbin/v2/util"

	"github.com/Knetic/govaluate"
	"github.com/tidwall/gjson"
)

// Enforcer is the main interface for authorization enforcement and policy management.
/*
在 Casbin 中，Enforcer 接口提供了一组方法，用于执行访问控制决策、管理策略规则和角色等操作。它是 Casbin 的核心组件，用于实现访问控制的功能。

通过 Enforcer 接口，您可以执行以下操作：

授权决策（Authorization Decision）：使用 Enforce 方法来判断是否允许或拒绝某个请求的访问。该方法会根据已定义的策略规则和角色进行访问控制决策。

策略管理（Policy Management）：使用 AddPolicy、RemovePolicy、RemoveFilteredPolicy 等方法来管理策略规则。您可以添加、删除或查询策略规则，以便动态调整访问控制策略。

角色管理（Role Management）：使用 AddRoleForUser、DeleteRoleForUser、GetRolesForUser 等方法来管理角色。您可以为用户分配角色、删除用户的角色，或查询用户所拥有的角色。

模型管理（Model Management）：使用 SetModel 方法来设置访问控制模型。您可以定义请求、策略、角色等模型的组成部分，以满足特定的访问控制需求。

策略持久化（Policy Persistence）：使用 SavePolicy、LoadPolicy 等方法来将策略规则持久化到存储介质（如文件、数据库）或从存储介质加载策略规则。

Enforcer 接口提供了许多其他方法，用于更精细的控制和管理访问控制策略。具体的方法和用法可能因 Casbin 库和所使用的编程语言而有所不同。
*/
type Enforcer struct {
	// 模型文件的路径，表示访问控制模型的配置文件路径。
	modelPath string
	// 访问控制模型，表示整个访问控制模型的结构和组成部分。
	model model.Model
	// 函数映射，用于注册和管理自定义函数，以供策略规则中使用。
	fm model.FunctionMap
	// 效果器（Effector），用于计算多个策略规则的整体效果。
	eft effector.Effector

	// 持久化适配器（Adapter），用于将策略规则持久化到存储介质或从存储介质加载策略规则。
	adapter persist.Adapter
	// 持久化观察者（Watcher），用于监视策略规则的变化。
	watcher persist.Watcher
	// 持久化调度器（Dispatcher），用于在策略规则变化时触发相应的操作。
	dispatcher persist.Dispatcher
	// 角色管理器（Role Manager）映射，用于管理不同角色的角色管理器实例。
	rmMap map[string]rbac.RoleManager
	// 匹配器（Matcher）映射，用于缓存和管理匹配器实例。
	matcherMap sync.Map

	// enabled：是否启用访问控制功能。
	enabled bool
	// autoSave：是否自动保存策略规则到持久化适配器。
	autoSave bool
	// autoBuildRoleLinks：是否自动构建角色关联。
	autoBuildRoleLinks bool
	// autoNotifyWatcher：是否自动通知持久化观察者。
	autoNotifyWatcher bool
	// autoNotifyDispatcher：是否自动通知持久化调度器。
	autoNotifyDispatcher bool
	// acceptJsonRequest：是否接受 JSON 格式的请求。
	acceptJsonRequest bool

	// logger：日志记录器，用于记录 Enforcer 相关的日志信息。
	logger log.Logger
}

// EnforceContext is used as the first element of the parameter "rvals" in method "enforce"
type EnforceContext struct {
	RType string
	PType string
	EType string
	MType string
}

func (e EnforceContext) GetCacheKey() string {
	return "EnforceContext{" + e.RType + "-" + e.PType + "-" + e.EType + "-" + e.MType + "}"
}

// NewEnforcer creates an enforcer via file or DB.
//
// File:
//
//	e := casbin.NewEnforcer("path/to/basic_model.conf", "path/to/basic_policy.csv")
//
// MySQL DB:
//
//	a := mysqladapter.NewDBAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/")
//	e := casbin.NewEnforcer("path/to/basic_model.conf", a)
func NewEnforcer(params ...interface{}) (*Enforcer, error) {
	e := &Enforcer{logger: &log.DefaultLogger{}}

	parsedParamLen := 0
	paramLen := len(params)
	if paramLen >= 1 {
		enableLog, ok := params[paramLen-1].(bool)
		if ok {
			e.EnableLog(enableLog)
			parsedParamLen++
		}
	}

	if paramLen-parsedParamLen >= 1 {
		logger, ok := params[paramLen-parsedParamLen-1].(log.Logger)
		if ok {
			e.logger = logger
			parsedParamLen++
		}
	}

	if paramLen-parsedParamLen == 2 {
		switch p0 := params[0].(type) {
		case string:
			switch p1 := params[1].(type) {
			case string:
				err := e.InitWithFile(p0, p1)
				if err != nil {
					return nil, err
				}
			default:
				err := e.InitWithAdapter(p0, p1.(persist.Adapter))
				if err != nil {
					return nil, err
				}
			}
		default:
			switch params[1].(type) {
			case string:
				return nil, errors.New("invalid parameters for enforcer")
			default:
				err := e.InitWithModelAndAdapter(p0.(model.Model), params[1].(persist.Adapter))
				if err != nil {
					return nil, err
				}
			}
		}
	} else if paramLen-parsedParamLen == 1 {
		switch p0 := params[0].(type) {
		case string:
			err := e.InitWithFile(p0, "")
			if err != nil {
				return nil, err
			}
		default:
			err := e.InitWithModelAndAdapter(p0.(model.Model), nil)
			if err != nil {
				return nil, err
			}
		}
	} else if paramLen-parsedParamLen == 0 {
		return e, nil
	} else {
		return nil, errors.New("invalid parameters for enforcer")
	}

	return e, nil
}

// InitWithFile initializes an enforcer with a model file and a policy file.
func (e *Enforcer) InitWithFile(modelPath string, policyPath string) error {
	a := fileadapter.NewAdapter(policyPath)
	return e.InitWithAdapter(modelPath, a)
}

// InitWithAdapter initializes an enforcer with a database adapter.
func (e *Enforcer) InitWithAdapter(modelPath string, adapter persist.Adapter) error {
	m, err := model.NewModelFromFile(modelPath)
	if err != nil {
		return err
	}

	err = e.InitWithModelAndAdapter(m, adapter)
	if err != nil {
		return err
	}

	e.modelPath = modelPath
	return nil
}

// InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.
func (e *Enforcer) InitWithModelAndAdapter(m model.Model, adapter persist.Adapter) error {
	e.adapter = adapter

	e.model = m
	m.SetLogger(e.logger)
	e.model.PrintModel()
	e.fm = model.LoadFunctionMap()

	e.initialize()

	// Do not initialize the full policy when using a filtered adapter
	fa, ok := e.adapter.(persist.FilteredAdapter)
	if e.adapter != nil && (!ok || ok && !fa.IsFiltered()) {
		err := e.LoadPolicy()
		if err != nil {
			return err
		}
	}

	return nil
}

// SetLogger changes the current enforcer's logger.
func (e *Enforcer) SetLogger(logger log.Logger) {
	e.logger = logger
	e.model.SetLogger(e.logger)
	for k := range e.rmMap {
		e.rmMap[k].SetLogger(e.logger)
	}
}

func (e *Enforcer) initialize() {
	e.rmMap = map[string]rbac.RoleManager{}
	e.eft = effector.NewDefaultEffector()
	e.watcher = nil
	e.matcherMap = sync.Map{}

	e.enabled = true
	e.autoSave = true
	e.autoBuildRoleLinks = true
	e.autoNotifyWatcher = true
	e.autoNotifyDispatcher = true
	e.initRmMap()
}

// LoadModel reloads the model from the model CONF file.
// Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
func (e *Enforcer) LoadModel() error {
	var err error
	e.model, err = model.NewModelFromFile(e.modelPath)
	if err != nil {
		return err
	}
	e.model.SetLogger(e.logger)

	e.model.PrintModel()
	e.fm = model.LoadFunctionMap()

	e.initialize()

	return nil
}

// GetModel gets the current model.
func (e *Enforcer) GetModel() model.Model {
	return e.model
}

// SetModel sets the current model.
func (e *Enforcer) SetModel(m model.Model) {
	e.model = m
	e.fm = model.LoadFunctionMap()

	e.model.SetLogger(e.logger)
	e.initialize()
}

// GetAdapter gets the current adapter.
func (e *Enforcer) GetAdapter() persist.Adapter {
	return e.adapter
}

// SetAdapter sets the current adapter.
func (e *Enforcer) SetAdapter(adapter persist.Adapter) {
	e.adapter = adapter
}

// SetWatcher sets the current watcher.
func (e *Enforcer) SetWatcher(watcher persist.Watcher) error {
	e.watcher = watcher
	if _, ok := e.watcher.(persist.WatcherEx); ok {
		// The callback of WatcherEx has no generic implementation.
		return nil
	} else {
		// In case the Watcher wants to use a customized callback function, call `SetUpdateCallback` after `SetWatcher`.
		return watcher.SetUpdateCallback(func(string) { _ = e.LoadPolicy() })
	}
}

// GetRoleManager gets the current role manager.
func (e *Enforcer) GetRoleManager() rbac.RoleManager {
	return e.rmMap["g"]
}

// GetNamedRoleManager gets the role manager for the named policy.
func (e *Enforcer) GetNamedRoleManager(ptype string) rbac.RoleManager {
	return e.rmMap[ptype]
}

// SetRoleManager sets the current role manager.
func (e *Enforcer) SetRoleManager(rm rbac.RoleManager) {
	e.invalidateMatcherMap()
	e.rmMap["g"] = rm
}

// SetNamedRoleManager sets the role manager for the named policy.
func (e *Enforcer) SetNamedRoleManager(ptype string, rm rbac.RoleManager) {
	e.invalidateMatcherMap()
	e.rmMap[ptype] = rm
}

// SetEffector sets the current effector.
func (e *Enforcer) SetEffector(eft effector.Effector) {
	e.eft = eft
}

// ClearPolicy clears all policy.
func (e *Enforcer) ClearPolicy() {
	e.invalidateMatcherMap()

	if e.dispatcher != nil && e.autoNotifyDispatcher {
		_ = e.dispatcher.ClearPolicy()
		return
	}
	e.model.ClearPolicy()
}

// LoadPolicy reloads the policy from file/database.
func (e *Enforcer) LoadPolicy() error {
	e.invalidateMatcherMap()

	needToRebuild := false
	newModel := e.model.Copy()
	newModel.ClearPolicy()

	var err error
	defer func() {
		if err != nil {
			if e.autoBuildRoleLinks && needToRebuild {
				_ = e.BuildRoleLinks()
			}
		}
	}()
	// 1. 将adapter对应的策略，加载到model中。
	// 主要有两种策略：1. 哪些用户有哪些角色[g]、2. 哪些角色有哪些资源的那些操作[p]
	if err = e.adapter.LoadPolicy(newModel); err != nil && err.Error() != "invalid file path, file path cannot be empty" {
		return err
	}
	// 2.
	if err = newModel.SortPoliciesBySubjectHierarchy(); err != nil {
		return err
	}

	if err = newModel.SortPoliciesByPriority(); err != nil {
		return err
	}

	if e.autoBuildRoleLinks {
		needToRebuild = true
		for _, rm := range e.rmMap {
			err := rm.Clear()
			if err != nil {
				return err
			}
		}
		err = newModel.BuildRoleLinks(e.rmMap)
		if err != nil {
			return err
		}
	}
	e.model = newModel
	return nil
}

func (e *Enforcer) loadFilteredPolicy(filter interface{}) error {
	e.invalidateMatcherMap()

	var filteredAdapter persist.FilteredAdapter

	// Attempt to cast the Adapter as a FilteredAdapter
	switch adapter := e.adapter.(type) {
	case persist.FilteredAdapter:
		filteredAdapter = adapter
	default:
		return errors.New("filtered policies are not supported by this adapter")
	}
	if err := filteredAdapter.LoadFilteredPolicy(e.model, filter); err != nil && err.Error() != "invalid file path, file path cannot be empty" {
		return err
	}

	if err := e.model.SortPoliciesBySubjectHierarchy(); err != nil {
		return err
	}

	if err := e.model.SortPoliciesByPriority(); err != nil {
		return err
	}

	e.initRmMap()
	e.model.PrintPolicy()
	if e.autoBuildRoleLinks {
		err := e.BuildRoleLinks()
		if err != nil {
			return err
		}
	}
	return nil
}

// LoadFilteredPolicy reloads a filtered policy from file/database.
func (e *Enforcer) LoadFilteredPolicy(filter interface{}) error {
	e.model.ClearPolicy()

	return e.loadFilteredPolicy(filter)
}

// LoadIncrementalFilteredPolicy append a filtered policy from file/database.
func (e *Enforcer) LoadIncrementalFilteredPolicy(filter interface{}) error {
	return e.loadFilteredPolicy(filter)
}

// IsFiltered returns true if the loaded policy has been filtered.
func (e *Enforcer) IsFiltered() bool {
	filteredAdapter, ok := e.adapter.(persist.FilteredAdapter)
	if !ok {
		return false
	}
	return filteredAdapter.IsFiltered()
}

// SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
func (e *Enforcer) SavePolicy() error {
	if e.IsFiltered() {
		return errors.New("cannot save a filtered policy")
	}
	if err := e.adapter.SavePolicy(e.model); err != nil {
		return err
	}
	if e.watcher != nil {
		var err error
		if watcher, ok := e.watcher.(persist.WatcherEx); ok {
			err = watcher.UpdateForSavePolicy(e.model)
		} else {
			err = e.watcher.Update()
		}
		return err
	}
	return nil
}

func (e *Enforcer) initRmMap() {
	for ptype := range e.model["g"] {
		if rm, ok := e.rmMap[ptype]; ok {
			_ = rm.Clear()
		} else {
			e.rmMap[ptype] = defaultrolemanager.NewRoleManager(10)
			matchFun := "keyMatch(r_dom, p_dom)"
			if strings.Contains(e.model["m"]["m"].Value, matchFun) {
				e.AddNamedDomainMatchingFunc(ptype, "g", util.KeyMatch)
			}
		}
	}
}

// EnableEnforce changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.
func (e *Enforcer) EnableEnforce(enable bool) {
	e.enabled = enable
}

// EnableLog changes whether Casbin will log messages to the Logger.
func (e *Enforcer) EnableLog(enable bool) {
	e.logger.EnableLog(enable)
}

// IsLogEnabled returns the current logger's enabled status.
func (e *Enforcer) IsLogEnabled() bool {
	return e.logger.IsEnabled()
}

// EnableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
func (e *Enforcer) EnableAutoNotifyWatcher(enable bool) {
	e.autoNotifyWatcher = enable
}

// EnableAutoNotifyDispatcher controls whether to save a policy rule automatically notify the Dispatcher when it is added or removed.
func (e *Enforcer) EnableAutoNotifyDispatcher(enable bool) {
	e.autoNotifyDispatcher = enable
}

// EnableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.
func (e *Enforcer) EnableAutoSave(autoSave bool) {
	e.autoSave = autoSave
}

// EnableAutoBuildRoleLinks controls whether to rebuild the role inheritance relations when a role is added or deleted.
func (e *Enforcer) EnableAutoBuildRoleLinks(autoBuildRoleLinks bool) {
	e.autoBuildRoleLinks = autoBuildRoleLinks
}

// EnableAcceptJsonRequest controls whether to accept json as a request parameter
func (e *Enforcer) EnableAcceptJsonRequest(acceptJsonRequest bool) {
	e.acceptJsonRequest = acceptJsonRequest
}

// BuildRoleLinks manually rebuild the role inheritance relations.
func (e *Enforcer) BuildRoleLinks() error {
	for _, rm := range e.rmMap {
		err := rm.Clear()
		if err != nil {
			return err
		}
	}

	return e.model.BuildRoleLinks(e.rmMap)
}

// BuildIncrementalRoleLinks provides incremental build the role inheritance relations.
func (e *Enforcer) BuildIncrementalRoleLinks(op model.PolicyOp, ptype string, rules [][]string) error {
	e.invalidateMatcherMap()
	return e.model.BuildIncrementalRoleLinks(e.rmMap, op, "g", ptype, rules)
}

// NewEnforceContext Create a default structure based on the suffix
func NewEnforceContext(suffix string) EnforceContext {
	return EnforceContext{
		RType: "r" + suffix,
		PType: "p" + suffix,
		EType: "e" + suffix,
		MType: "m" + suffix,
	}
}

func (e *Enforcer) invalidateMatcherMap() {
	e.matcherMap = sync.Map{}
}

// enforce use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
func (e *Enforcer) enforce(matcher string, explains *[]string, rvals ...interface{}) (ok bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v\n%s", r, debug.Stack())
		}
	}()
	// 1. 没有开启访问控制，直接返回true
	if !e.enabled {
		return true, nil
	}
	// 2. 获取已有的 function map，key 是 函数名，val是具体函数
	functions := e.fm.GetFunctions()
	// 3. 如果 model 中配置了 g，也就是：[role_definition]
	// 为 [role_definition] 自动生成一个 g 函数，对应的 m = g(r.sub, p.sub, r.dom)
	if _, ok := e.model["g"]; ok {
		for key, ast := range e.model["g"] {
			// rm 是role管理器或domain管理器
			rm := ast.RM
			// 为 [role_definition] 自动生成一个 g 函数，对应的 m = g(r.sub, p.sub, r.dom)
			// 这里自定生成的 g 函数，会覆盖代码里手动添加的g函数【如果有添加的话】
			functions[key] = util.GenerateGFunction(rm)
		}
	}

	var (
		rType = "r"
		pType = "p"
		eType = "e"
		mType = "m"
	)
	// 4. 对EnforceContext进行处理
	if len(rvals) != 0 {
		switch rvals[0].(type) {
		case EnforceContext:
			enforceContext := rvals[0].(EnforceContext)
			rType = enforceContext.RType
			pType = enforceContext.PType
			eType = enforceContext.EType
			mType = enforceContext.MType
			rvals = rvals[1:]
		default:
			break
		}
	}
	// 获取 [matchers] 的表达式
	var expString string
	if matcher == "" {
		expString = e.model["m"][mType].Value
	} else {
		expString = util.RemoveComments(util.EscapeAssertion(matcher))
	}
	// 5. 获取请求占位符，即[request_definition]的值
	rTokens := make(map[string]int, len(e.model["r"][rType].Tokens))
	for i, token := range e.model["r"][rType].Tokens {
		rTokens[token] = i
	}
	// 6. 获取Policy占位符，即[policy_definition]的值
	pTokens := make(map[string]int, len(e.model["p"][pType].Tokens))
	for i, token := range e.model["p"][pType].Tokens {
		pTokens[token] = i
	}
	// 7. 是否支持json请求
	if e.acceptJsonRequest {
		expString = requestJsonReplace(expString, rTokens, rvals)
	}
	// 8. 组合数据
	parameters := enforceParameters{
		// 请求的占位符
		rTokens: rTokens,
		// 请求参数
		rVals: rvals,
		// Policy的占位符
		pTokens: pTokens,
	}
	// 9. 判断 [matcher] 中的表达式是否包含 Eval 函数
	// Eval函数是Casbin中的一个内置函数，用于在策略规则中执行自定义的表达式逻辑。它允许用户在策略规则中使用更复杂的条件判断和逻辑运算。
	// 通过调用util.HasEval(expString)函数，可以在Casbin中判断策略规则中是否使用了Eval函数，以便在需要时执行自定义的表达式逻辑。
	hasEval := util.HasEval(expString)
	if hasEval {
		// 如果 [matcher] 表达式中配置了 eval 函数，则这里要生成 eval 函数
		functions["eval"] = generateEvalFunction(functions, &parameters)
	}
	var expression *govaluate.EvaluableExpression
	expression, err = e.getAndStoreMatcherExpression(hasEval, expString, functions)
	if err != nil {
		return false, err
	}

	if len(e.model["r"][rType].Tokens) != len(rvals) {
		return false, fmt.Errorf(
			"invalid request size: expected %d, got %d, rvals: %v",
			len(e.model["r"][rType].Tokens),
			len(rvals),
			rvals)
	}

	// 用于存储每条Policy的结果，结果可以是：允许（Allow）、拒绝（Deny）或未知（Indeterminate）
	var policyEffects []effector.Effect
	// 用于存储匹配器（Matcher）的结果。
	// Matcher是Casbin中用于匹配策略规则的组件，它根据请求的属性和策略规则进行匹配，并生成一个匹配结果。
	var matcherResults []float64

	var effect effector.Effect
	var explainIndex int

	if policyLen := len(e.model["p"][pType].Policy); policyLen != 0 && strings.Contains(expString, pType+"_") {
		policyEffects = make([]effector.Effect, policyLen)
		matcherResults = make([]float64, policyLen)

		for policyIndex, pvals := range e.model["p"][pType].Policy {
			// log.LogPrint("Policy Rule: ", pvals)
			if len(e.model["p"][pType].Tokens) != len(pvals) {
				return false, fmt.Errorf(
					"invalid policy size: expected %d, got %d, pvals: %v",
					len(e.model["p"][pType].Tokens),
					len(pvals),
					pvals)
			}

			if e.acceptJsonRequest {
				pvalsCopy := make([]string, len(pvals))
				copy(pvalsCopy, pvals)
				for i, pStr := range pvalsCopy {
					pvalsCopy[i] = requestJsonReplace(util.EscapeAssertion(pStr), rTokens, rvals)
				}
				parameters.pVals = pvalsCopy
			} else {
				parameters.pVals = pvals
			}

			result, err := expression.Eval(parameters)
			// log.LogPrint("Result: ", result)

			if err != nil {
				return false, err
			}

			// set to no-match at first
			matcherResults[policyIndex] = 0
			switch result := result.(type) {
			case bool:
				if result {
					matcherResults[policyIndex] = 1
				}
			case float64:
				if result != 0 {
					matcherResults[policyIndex] = 1
				}
			default:
				return false, errors.New("matcher result should be bool, int or float")
			}

			if j, ok := parameters.pTokens[pType+"_eft"]; ok {
				eft := parameters.pVals[j]
				if eft == "allow" {
					policyEffects[policyIndex] = effector.Allow
				} else if eft == "deny" {
					policyEffects[policyIndex] = effector.Deny
				} else {
					policyEffects[policyIndex] = effector.Indeterminate
				}
			} else {
				policyEffects[policyIndex] = effector.Allow
			}

			// if e.model["e"]["e"].Value == "priority(p_eft) || deny" {
			//	break
			// }

			effect, explainIndex, err = e.eft.MergeEffects(e.model["e"][eType].Value, policyEffects, matcherResults, policyIndex, policyLen)
			if err != nil {
				return false, err
			}
			if effect != effector.Indeterminate {
				break
			}
		}
	} else {

		if hasEval && len(e.model["p"][pType].Policy) == 0 {
			return false, errors.New("please make sure rule exists in policy when using eval() in matcher")
		}

		policyEffects = make([]effector.Effect, 1)
		matcherResults = make([]float64, 1)
		matcherResults[0] = 1

		parameters.pVals = make([]string, len(parameters.pTokens))

		result, err := expression.Eval(parameters)

		if err != nil {
			return false, err
		}

		if result.(bool) {
			policyEffects[0] = effector.Allow
		} else {
			policyEffects[0] = effector.Indeterminate
		}

		effect, explainIndex, err = e.eft.MergeEffects(e.model["e"][eType].Value, policyEffects, matcherResults, 0, 1)
		if err != nil {
			return false, err
		}
	}

	var logExplains [][]string

	if explains != nil {
		if len(*explains) > 0 {
			logExplains = append(logExplains, *explains)
		}

		if explainIndex != -1 && len(e.model["p"][pType].Policy) > explainIndex {
			*explains = e.model["p"][pType].Policy[explainIndex]
			logExplains = append(logExplains, *explains)
		}
	}

	// effect -> result
	result := false
	if effect == effector.Allow {
		result = true
	}
	e.logger.LogEnforce(expString, rvals, result, logExplains)

	return result, nil
}

var requestObjectRegex = regexp.MustCompile(`r[_.][A-Za-z_0-9]+\.[A-Za-z_0-9.]+[A-Za-z_0-9]`)
var requestObjectRegexPrefix = regexp.MustCompile(`r[_.][A-Za-z_0-9]+\.`)

// requestJsonReplace used to support request parameters of type json
// It will replace the access of the request object in matchers or policy with the actual value in the request json parameter
// For example: request sub = `{"Owner": "alice", "Age": 30}`
// policy: p, r.sub.Age > 18, /data1, read  ==>  p, 30 > 18, /data1, read
// matchers: m = r.sub == r.obj.Owner  ==>  m = r.sub == "alice"
func requestJsonReplace(str string, rTokens map[string]int, rvals []interface{}) string {
	matches := requestObjectRegex.FindStringSubmatch(str)
	for _, matchesStr := range matches {
		prefix := requestObjectRegexPrefix.FindString(matchesStr)
		jsonPath := strings.TrimPrefix(matchesStr, prefix)
		tokenIndex := rTokens[prefix[:len(prefix)-1]]
		if jsonStr, ok := rvals[tokenIndex].(string); ok {
			newStr := gjson.Get(jsonStr, jsonPath).String()
			if !util.IsNumeric(newStr) {
				newStr = `"` + newStr + `"`
			}
			str = strings.Replace(str, matchesStr, newStr, -1)
		}
	}
	return str
}

func (e *Enforcer) getAndStoreMatcherExpression(hasEval bool, expString string, functions map[string]govaluate.ExpressionFunction) (*govaluate.EvaluableExpression, error) {
	var expression *govaluate.EvaluableExpression
	var err error
	var cachedExpression, isPresent = e.matcherMap.Load(expString)

	if !hasEval && isPresent {
		expression = cachedExpression.(*govaluate.EvaluableExpression)
	} else {
		expression, err = govaluate.NewEvaluableExpressionWithFunctions(expString, functions)
		if err != nil {
			return nil, err
		}
		e.matcherMap.Store(expString, expression)
	}
	return expression, nil
}

// Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
func (e *Enforcer) Enforce(rvals ...interface{}) (bool, error) {
	return e.enforce("", nil, rvals...)
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
func (e *Enforcer) EnforceWithMatcher(matcher string, rvals ...interface{}) (bool, error) {
	return e.enforce(matcher, nil, rvals...)
}

// EnforceEx explain enforcement by informing matched rules
func (e *Enforcer) EnforceEx(rvals ...interface{}) (bool, []string, error) {
	explain := []string{}
	result, err := e.enforce("", &explain, rvals...)
	return result, explain, err
}

// EnforceExWithMatcher use a custom matcher and explain enforcement by informing matched rules
func (e *Enforcer) EnforceExWithMatcher(matcher string, rvals ...interface{}) (bool, []string, error) {
	explain := []string{}
	result, err := e.enforce(matcher, &explain, rvals...)
	return result, explain, err
}

// BatchEnforce enforce in batches
func (e *Enforcer) BatchEnforce(requests [][]interface{}) ([]bool, error) {
	var results []bool
	for _, request := range requests {
		result, err := e.enforce("", nil, request...)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

// BatchEnforceWithMatcher enforce with matcher in batches
func (e *Enforcer) BatchEnforceWithMatcher(matcher string, requests [][]interface{}) ([]bool, error) {
	var results []bool
	for _, request := range requests {
		result, err := e.enforce(matcher, nil, request...)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

// AddNamedMatchingFunc add MatchingFunc by ptype RoleManager
func (e *Enforcer) AddNamedMatchingFunc(ptype, name string, fn rbac.MatchingFunc) bool {
	if rm, ok := e.rmMap[ptype]; ok {
		rm.AddMatchingFunc(name, fn)
		return true
	}
	return false
}

// AddNamedDomainMatchingFunc add MatchingFunc by ptype to RoleManager
func (e *Enforcer) AddNamedDomainMatchingFunc(ptype, name string, fn rbac.MatchingFunc) bool {
	if rm, ok := e.rmMap[ptype]; ok {
		rm.AddDomainMatchingFunc(name, fn)
		return true
	}
	return false
}

// assumes bounds have already been checked
type enforceParameters struct {
	// 存储请求的占位符
	rTokens map[string]int
	// 存储具体的请求值
	rVals []interface{}
	// 存储Policy的占位符
	pTokens map[string]int
	// 存储具体的Policy
	pVals []string
}

// implements govaluate.Parameters
func (p enforceParameters) Get(name string) (interface{}, error) {
	if name == "" {
		return nil, nil
	}

	switch name[0] {
	case 'p':
		i, ok := p.pTokens[name]
		if !ok {
			return nil, errors.New("No parameter '" + name + "' found.")
		}
		return p.pVals[i], nil
	case 'r':
		i, ok := p.rTokens[name]
		if !ok {
			return nil, errors.New("No parameter '" + name + "' found.")
		}
		return p.rVals[i], nil
	default:
		return nil, errors.New("No parameter '" + name + "' found.")
	}
}

func generateEvalFunction(functions map[string]govaluate.ExpressionFunction, parameters *enforceParameters) govaluate.ExpressionFunction {
	return func(args ...interface{}) (interface{}, error) {
		if len(args) != 1 {
			return nil, fmt.Errorf("function eval(subrule string) expected %d arguments, but got %d", 1, len(args))
		}

		expression, ok := args[0].(string)
		if !ok {
			return nil, errors.New("argument of eval(subrule string) must be a string")
		}
		expression = util.EscapeAssertion(expression)
		expr, err := govaluate.NewEvaluableExpressionWithFunctions(expression, functions)
		if err != nil {
			return nil, fmt.Errorf("error while parsing eval parameter: %s, %s", expression, err.Error())
		}
		return expr.Eval(parameters)
	}
}
