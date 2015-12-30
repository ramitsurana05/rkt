// Copyright 2015 The rkt Authors
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

//+build linux

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/coreos/rkt/Godeps/_workspace/src/github.com/appc/spec/schema/types"

	"github.com/coreos/rkt/common"
	"github.com/coreos/rkt/networking"
)

var (
	debug bool
)

func init() {
	flag.BoolVar(&debug, "debug", false, "Run in debug mode")

	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func main() {
	flag.Parse()

	if !debug {
		log.SetOutput(ioutil.Discard)
	}

	podID, err := types.NewUUID(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "UUID is missing or malformed")
		os.Exit(1)
	}

	if err := gcNetworking(podID); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func gcNetworking(podID *types.UUID) error {
	var flavor string
	// we first try to read the flavor from stage1 for backwards compatibility
	flavor, err := os.Readlink(filepath.Join(common.Stage1RootfsPath("."), "flavor"))
	if err != nil {
		// if we couldn't read the flavor from stage1 it could mean the overlay
		// filesystem is already unmounted (e.g. the system has been rebooted).
		// In that case we try to read it from the pod's root directory
		flavor, err = os.Readlink("flavor")
		if err != nil {
			return fmt.Errorf("Failed to get stage1 flavor: %v\n", err)
		}
	}

	n, err := networking.Load(".", podID)
	switch {
	case err == nil:
		n.Teardown(flavor)
	case os.IsNotExist(err):
		// probably ran with --net=host
	default:
		return fmt.Errorf("Failed loading networking state: %v", err)
	}

	return nil
}
