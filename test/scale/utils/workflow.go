package utils

import "k8s.io/client-go/util/retry"

func DefaultRetry(fn func() error) error {
	return retry.OnError(retry.DefaultRetry, func(_ error) bool { return true }, fn)
}
