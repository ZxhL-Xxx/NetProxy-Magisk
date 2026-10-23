//go:build !linux && !android

package agh

import "errors"

func WatchProcess(int) (<-chan struct{}, func(), error) {
	return nil, nil, errors.New("pidfd unavailable")
}
