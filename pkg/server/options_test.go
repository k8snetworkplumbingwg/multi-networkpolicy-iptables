/*
Copyright 2020 The Kubernetes Authors.

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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("server option", func() {
	It("Check container runtime option valid case", func() {
		opt := NewOptions()
		opt.containerRuntimeStr = "docker"
		Expect(opt.Validate()).To(BeNil())
		opt.containerRuntimeStr = "DOCKER"
		Expect(opt.Validate()).To(BeNil())
		opt.containerRuntimeStr = "crio"
		Expect(opt.Validate()).To(BeNil())
		opt.containerRuntimeStr = "CRIO"
		Expect(opt.Validate()).To(BeNil())
	})
	It("Check container runtime option invalid case", func() {
		opt := NewOptions()
		opt.containerRuntimeStr = "Foobar"
		Expect(opt.Validate()).To(MatchError("Invalid container-runtime option Foobar (possible value: \"docker\", \"crio\""))
	})
})
