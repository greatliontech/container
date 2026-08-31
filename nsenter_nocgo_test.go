//go:build !cgo

package container

import (
	"strings"
	"testing"
)

// Without CGO the create path cannot setns; a config asking for namespace
// joins must fail loudly instead of silently running unjoined.
func TestNoCgoCreateRejectsNamespaceJoins(t *testing.T) {
	c := New("nocgo-join-reject", Config{
		Namespaces: Namespaces{JoinNet: "/proc/1/ns/net"},
	})
	err := c.Run(&Process{Cmd: "/bin/true"})
	if err == nil {
		c.Wait()
		t.Fatal("Run with JoinNet succeeded without CGO; want error")
	}
	if !strings.Contains(err.Error(), "CGO") {
		t.Errorf("error %q does not name the CGO requirement", err)
	}
}
