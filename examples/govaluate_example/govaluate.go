package main

import (
	"github.com/Knetic/govaluate"
	"sync"
)

import (
	"fmt"
)

func main() {
	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			for {
				expression, err := govaluate.NewEvaluableExpression("2 + 3 * 4")
				if err != nil {
					fmt.Printf(" %d Expression parsing error:%v", i, err)
					return
				}

				result, err := expression.Evaluate(nil)
				if err != nil {
					fmt.Printf(" %d Expression evaluation error:%v", i, err)
					return
				}
				if result.(float64) != 14 {

					fmt.Println("---------------Result:", result)
				}
			}
		}()
	}
	wg.Wait()

}
