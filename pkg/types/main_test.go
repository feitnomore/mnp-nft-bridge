// Arquivo: pkg/types/main_test.go
package types

import (
	"flag"
	"os"
	"testing"

	"k8s.io/klog/v2"
)

func TestMain(m *testing.M) {
	klog.InitFlags(nil)
	/* Try setting the flags directly. This may or may not work depending on when/how the flags are parsed by `go test` */
	_ = flag.Set("v", "5")              /* High verbosity level for klog.V(..) and to ensure that klog.Info outputs */
	_ = flag.Set("logtostderr", "true") /* Ensures logs go to stderr */

	exitCode := m.Run()
	klog.Flush()
	os.Exit(exitCode)
}
