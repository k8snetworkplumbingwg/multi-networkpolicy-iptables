/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"testing"
	"time"

	"k8s.io/kubernetes/pkg/proxy/runner"
)

func TestSyncAfterRunnerShutdownDoesNotPanic(t *testing.T) {
	s := &Server{
		syncRunner: runner.NewBoundedFrequencyRunner(
			"test-sync-runner",
			func() error { return nil },
			time.Millisecond,
			time.Millisecond,
			time.Hour,
		),
		syncRunnerStopCh: make(chan struct{}),
		syncRunnerDoneCh: make(chan struct{}),
	}

	go s.SyncLoop()
	waitForSyncRunner(t, s)

	s.stopSyncRunner()
	s.Sync()
}

func waitForSyncRunner(t *testing.T, s *Server) {
	t.Helper()

	deadline := time.After(time.Second)
	for {
		s.syncRunnerMu.Lock()
		active := s.syncRunnerActive
		s.syncRunnerMu.Unlock()
		if active {
			return
		}

		select {
		case <-deadline:
			t.Fatal("sync runner did not start")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}
