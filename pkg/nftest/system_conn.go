package nftest

import (
	"runtime"
	"testing"

	"github.com/google/nftables"
	"github.com/vishvananda/netns"
)

const netNsName = "testing"

// OpenSystemConn returns a netlink connection that tests against
// the running kernel in a separate network namespace.
// nftest.CleanupSystemConn() must be called from a defer to cleanup
// created network namespace.
func OpenSystemConn(t *testing.T, enableSysTests bool) (*nftables.Conn, netns.NsHandle) {
	t.Helper()
	if !enableSysTests {
		t.SkipNow()
	}
	// We lock the goroutine into the current thread, as namespace operations
	// such as those invoked by `netns.New()` are thread-local. This is undone
	// in nftest.CleanupSystemConn().
	runtime.LockOSThread()
	ns, err := netns.GetFromName(netNsName)
	if err == nil {
		t.Logf("Reused netns %q %d, %s", netNsName, ns, ns.UniqueId())
	} else {
		ns, err = netns.NewNamed(netNsName)
		t.Logf("Created new netns %q %d, %s", netNsName, ns, ns.UniqueId())
		if err != nil {
			t.Fatalf("netns.NewNamed(%q) failed: %v", netNsName, err)
		}
	}
	c, err := nftables.New(nftables.WithNetNSFd(int(ns)), nftables.AsLasting())
	if err != nil {
		t.Fatalf("nftables.New() failed: %v", err)
	}
	return c, ns
}

func CleanupSystemConn(t *testing.T, newNS netns.NsHandle) {
	defer runtime.UnlockOSThread()

	if err := newNS.Close(); err != nil {
		t.Fatalf("newNS.Close() failed: %v", err)
	}
	if err := netns.DeleteNamed(netNsName); err != nil {
		t.Fatalf("netns.DeleteNamed(%q) failed: %v", netNsName, err)
	}
	t.Logf("Deleted netns %q", netNsName)
}
