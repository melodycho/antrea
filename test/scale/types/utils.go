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
	"fmt"
)

type CtxBreadcrumbsType string

const (
	CtxBreadcrumbs CtxBreadcrumbsType = "breadcrumbs"
)

func wrapWithBreadcrumb(ctx context.Context, name string) context.Context {
	v := ctx.Value(CtxBreadcrumbs)
	if v != nil {
		return context.WithValue(ctx, CtxBreadcrumbs, fmt.Sprintf("%s[%s]", v.(string), name))
	}
	return context.WithValue(ctx, CtxBreadcrumbs, fmt.Sprintf("[%s]", name))
}
