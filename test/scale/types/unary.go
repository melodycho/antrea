// Copyright 2020 Antrea Authors
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

package types

import (
	"context"

	"k8s.io/klog"
)

type RunFunc func(ctx context.Context, data TestData) error

type Unary struct {
	name     string
	run      RunFunc
	parallel bool
}

func NewUnary(name string, parallel bool, run RunFunc) *Unary {
	return &Unary{
		name:     name,
		run:      run,
		parallel: parallel,
	}
}

func (u *Unary) Name() string {
	return u.name
}

func (u *Unary) Includes(testCases ...TestCase) TestCase {
	panic("Unary does not support subside test cases")
}

func (u *Unary) Run(ctx context.Context, testData TestData) error {
	ctx = wrapWithBreadcrumb(ctx, u.name)
	klog.Infof("Begin: %s", ctx.Value(CtxBreadcrumbs).(string))
	defer klog.Infof("Finish: %s", ctx.Value(CtxBreadcrumbs).(string))

	done := make(chan interface{}, 1)
	go func() {
		done <- u.run(ctx, testData)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return err.(error)
		}
		return nil
	}
}
