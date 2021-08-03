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
	"time"

	"k8s.io/klog/v2"
)

func NewChain(name string) *Chain {
	return &Chain{
		name: name,
	}
}

type Chain struct {
	name      string
	testCases []TestCase
}

func (c *Chain) Name() string {
	return c.name
}

func (c *Chain) Includes(testCases ...TestCase) TestCase {
	c.testCases = append(c.testCases, testCases...)
	return c
}

func (c *Chain) Run(ctx context.Context, testData TestData) error {
	ctx = wrapWithBreadcrumb(ctx, c.name)
	startTime := time.Now()
	caseName := ctx.Value(CtxBreadcrumbs).(string)
	klog.InfoS("Testing======>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", "Name", caseName)
	defer func() {
		klog.InfoS("Tested=======>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", "Name", caseName)
		klog.V(2).InfoS("Test time", "Name", caseName, "durationTime", time.Since(startTime))
	}()

	for _, tc := range c.testCases {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := tc.Run(ctx, testData); err != nil {
				return err
			}
		}
	}
	return nil
}
