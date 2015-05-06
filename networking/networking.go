// Copyright 2015 CoreOS, Inc.
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

package networking

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/coreos/rkt/Godeps/_workspace/src/github.com/appc/cni/pkg/ns"
	"github.com/coreos/rkt/Godeps/_workspace/src/github.com/appc/spec/schema/types"
	"github.com/coreos/rkt/Godeps/_workspace/src/github.com/vishvananda/netlink"

	"github.com/coreos/rkt/networking/netinfo"
)

const (
	ifnamePattern = "eth%d"
	selfNetNS     = "/proc/self/ns/net"
)

// ForwardedPort describes a port that will be
// forwarded (mapped) from the host to the rkt
type ForwardedPort struct {
	Protocol string
	HostPort uint
	rktPort  uint
}

// Networking describes the networking details of a rkt.
type Networking struct {
	rktEnv

	hostNS *os.File
	nets   []activeNet
}

// Setup creates a new networking namespace and executes network plugins to
// setup private networking. It returns in the new rkt namespace
func Setup(rktRoot string, rktID types.UUID, fps []ForwardedPort) (*Networking, error) {
	// TODO(jonboulle): currently rktRoot is _always_ ".", and behaviour in other
	// circumstances is untested. This should be cleaned up.
	n := Networking{
		rktEnv: rktEnv{
			rktRoot: rktRoot,
			rktID:   rktID,
		},
	}

	hostNS, rktNS, err := basicNetNS()
	if err != nil {
		return nil, err
	}
	// we're in rktNS!
	n.hostNS = hostNS

	nspath := n.rktNSPath()

	if err = bindMountFile(selfNetNS, nspath); err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			if err := syscall.Unmount(nspath, 0); err != nil {
				log.Printf("Error unmounting %q: %v", nspath, err)
			}
		}
	}()

	n.nets, err = n.loadNets()
	if err != nil {
		return nil, fmt.Errorf("error loading network definitions: %v", err)
	}

	err = withNetNS(rktNS, hostNS, func() error {
		if err := n.setupNets(n.nets); err != nil {
			return err
		}
		return n.forwardPorts(fps, n.GetDefaultIP())
	})
	if err != nil {
		return nil, err
	}

	return &n, nil
}

// Load creates the Networking object from saved state.
// Assumes the current netns is that of the host.
func Load(rktRoot string, rktID *types.UUID) (*Networking, error) {
	// the current directory is rkt root
	pdirfd, err := syscall.Open(rktRoot, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("Failed to open rkt root directory (%v): %v", rktRoot, err)
	}
	defer syscall.Close(pdirfd)

	nis, err := netinfo.LoadAt(pdirfd)
	if err != nil {
		return nil, err
	}

	hostNS, err := os.Open(selfNetNS)
	if err != nil {
		return nil, err
	}

	nets := []activeNet{}
	for _, ni := range nis {
		n, err := loadNet(ni.ConfPath)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Printf("Error loading %q: %v; ignoring", ni.ConfPath, err)
			}
			continue
		}

		// make a copy of ni to make it a unique object as it's saved via ptr
		rti := ni
		nets = append(nets, activeNet{
			conf:    n.conf,
			runtime: &rti,
		})
	}

	return &Networking{
		rktEnv: rktEnv{
			rktRoot: rktRoot,
			rktID:   *rktID,
		},
		hostNS: hostNS,
		nets:   nets,
	}, nil
}

func (n *Networking) GetDefaultIP() net.IP {
	if len(n.nets) == 0 {
		return nil
	}
	return n.nets[len(n.nets)-1].runtime.IP
}

func (n *Networking) GetDefaultHostIP() net.IP {
	if len(n.nets) == 0 {
		return nil
	}
	return n.nets[len(n.nets)-1].hostIP
}

// Teardown cleans up a produced Networking object.
func (n *Networking) Teardown() {
	// Teardown everything in reverse order of setup.
	// This should be idempotent -- be tolerant of missing stuff

	if err := n.enterHostNS(); err != nil {
		log.Printf("Error switching to host netns: %v", err)
		return
	}

	if err := n.unforwardPorts(); err != nil {
		log.Printf("Error removing forwarded ports: %v", err)
	}

	n.teardownNets(n.nets)

	if err := syscall.Unmount(n.rktNSPath(), 0); err != nil {
		// if already unmounted, umount(2) returns EINVAL
		if !os.IsNotExist(err) && err != syscall.EINVAL {
			log.Printf("Error unmounting %q: %v", n.rktNSPath(), err)
		}
	}
}

// sets up new netns with just lo
func basicNetNS() (hostNS, rktNS *os.File, err error) {
	hostNS, rktNS, err = newNetNS()
	if err != nil {
		err = fmt.Errorf("failed to create new netns: %v", err)
		return
	}
	// we're in rktNS!!

	if err = loUp(); err != nil {
		hostNS.Close()
		rktNS.Close()
		return nil, nil, err
	}

	return
}

// enterHostNS moves into the host's network namespace.
func (n *Networking) enterHostNS() error {
	return ns.SetNS(n.hostNS, syscall.CLONE_NEWNET)
}

// Save writes out the info about active nets
// for "rkt list" and friends to display
func (e *Networking) Save() error {
	nis := []netinfo.NetInfo{}
	for _, n := range e.nets {
		nis = append(nis, *n.runtime)
	}

	return netinfo.Save(e.rktRoot, nis)
}

func newNetNS() (hostNS, childNS *os.File, err error) {
	defer func() {
		if err != nil {
			if hostNS != nil {
				hostNS.Close()
			}
			if childNS != nil {
				childNS.Close()
			}
		}
	}()

	hostNS, err = os.Open(selfNetNS)
	if err != nil {
		return
	}

	if err = syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
		return
	}

	childNS, err = os.Open(selfNetNS)
	if err != nil {
		ns.SetNS(hostNS, syscall.CLONE_NEWNET)
		return
	}

	return
}

// execute f() in tgtNS
func withNetNS(curNS, tgtNS *os.File, f func() error) error {
	if err := ns.SetNS(tgtNS, syscall.CLONE_NEWNET); err != nil {
		return err
	}

	if err := f(); err != nil {
		// Attempt to revert the net ns in a known state
		if err := ns.SetNS(curNS, syscall.CLONE_NEWNET); err != nil {
			log.Printf("Cannot revert the net namespace: %v", err)
		}
		return err
	}

	return ns.SetNS(curNS, syscall.CLONE_NEWNET)
}

func loUp() error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to lookup lo: %v", err)
	}

	if err := netlink.LinkSetUp(lo); err != nil {
		return fmt.Errorf("failed to set lo up: %v", err)
	}

	return nil
}

func bindMountFile(src, dst string) error {
	// mount point has to be an existing file
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	f.Close()

	return syscall.Mount(src, dst, "none", syscall.MS_BIND, "")
}
