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

package main

import (
	"context"
	"fmt"
	"time"

	flag "github.com/spf13/pflag"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/scale/cases"
	"antrea.io/antrea/test/scale/types"
)

const (
	totalTimeout = 10 * time.Minute
)

var (
	globalCtx, globalCancelFunc = context.WithTimeout(context.Background(), totalTimeout)
	splitter                    = "...................................................................................."
	option                      = struct {
		ipv6 bool
	}{}
)

func init() {
	flag.BoolVar(&option.ipv6, "ipv6", false, "Use IPv6 address instead of IPv4 to run the scale test")
	flag.Parse()
}

func main() {
	startTime := time.Now()
	klog.InfoS("Starting scale test", "startTime", startTime)
	defer func() {
		klog.InfoS("Shutting down scale test", "durationTime", time.Since(startTime))
	}()
	if err := run(); err != nil {
		klog.ErrorS(err, "Test failed")
	}
}

func run() error {
	defer globalCancelFunc()

	klog.Infoln("Scale test start...")
	testData, err := types.NewTestData(globalCtx)
	if err != nil {
		return fmt.Errorf("error when creating TestData: %w", err)
	}

	for _, tc := range []cases.TestCase{
		cases.TestCasePodCreation(),
		cases.TestCaseNetworkPolicyRealization(),
		cases.TestCaseServiceChurns(option.ipv6),
	} {
		klog.Infoln(splitter)
		klog.Infoln("[TEST]", tc.Name())
		if err := func() error {
			done := make(chan interface{}, 1)
			go func() { done <- tc.Run(globalCtx, testData) }()
			select {
			case obj := <-done:
				if obj == nil {
					break
				} else {
					return fmt.Errorf("error when running test case: %s, error: %v", tc.Name(), obj.(error))
				}
			case <-globalCtx.Done():
				if err := globalCtx.Err(); err != nil {
					return fmt.Errorf("test case %s failed: %w", tc.Name(), err)
				}
			}
			return nil
		}(); err != nil {
			return err
		}
	}
	tearDownCase := cases.TestCaseTearDown()
	if err := tearDownCase.Run(context.TODO(), testData); err != nil {
		klog.ErrorS(err, "Destroy Test Namespace error")
	}
	time.Sleep(3 * time.Second)
	return nil
}
