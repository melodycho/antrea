// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package framework

import (
	"context"
	"fmt"
	"os"
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/framework/table"
)

type RunFunc func(ctx context.Context, ch chan time.Duration, data *ScaleData) error

var cases = make(map[string]RunFunc, 128)

func RegisterFunc(name string, runFunc RunFunc) {
	cases[name] = runFunc
	klog.InfoS("register func", "Name", name)
}

type ScaleTestCase struct {
	name     string
	run      RunFunc
	parallel bool
}

func NewScaleTestCase(name string, parallel bool) (*ScaleTestCase, error) {
	tCase, ok := cases[name]
	if !ok {
		return nil, fmt.Errorf("test func %s not registered", name)
	}
	return &ScaleTestCase{
		name:     name,
		run:      tCase,
		parallel: parallel,
	}, nil
}

func (c *ScaleTestCase) Name() string {
	return c.name
}

type ResponseTime struct {
	max time.Duration
	min time.Duration
	avg time.Duration
}

func (c *ScaleTestCase) Run(ctx context.Context, testData *ScaleData) error {
	ctx = wrapScaleTestName(ctx, c.name)
	done := make(chan interface{}, 1)

	startTime := time.Now()
	caseName := ctx.Value(CtxScaleCaseName).(string)
	testData.maxCheckNum = testData.nodesNum * 2
	ress := make(chan time.Duration, testData.maxCheckNum)
	res := "failed"
	defer func() {
		var rows [][]string

		var total, minRes, maxRes, avg time.Duration
		count := 0
		for i := 0; i < testData.maxCheckNum; i++ {
			res := <-ress
			total += res
			count++

			if count == 1 || res < minRes {
				minRes = res
			}

			if res > maxRes {
				maxRes = res
			}
		}

		avg = total / time.Duration(count)

		rows = append(rows, table.GenerateRow(caseName, res, time.Since(startTime).String(),
			avg.String(), maxRes.String(), minRes.String()))
		table.ShowResult(os.Stdout, rows)

		close(ress)
		close(done)
	}()

	go func() {
		done <- c.run(ctx, ress, testData)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return err.(error)
		}
		res = "success"
		return nil
	}
}

type CtxScaleCaseNameType string

const (
	CtxScaleCaseName CtxScaleCaseNameType = "scale-case-name"
)

func wrapScaleTestName(ctx context.Context, name string) context.Context {
	v := ctx.Value(CtxScaleCaseName)
	if v != nil {
		return context.WithValue(ctx, CtxScaleCaseName, fmt.Sprintf("%s[%s]", v.(string), name))
	}
	return context.WithValue(ctx, CtxScaleCaseName, fmt.Sprintf("[%s]", name))
}
