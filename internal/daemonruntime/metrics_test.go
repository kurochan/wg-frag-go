package daemonruntime

import "testing"

func TestEffectiveListenPort(t *testing.T) {
	t.Parallel()
	if got, err := effectiveListenPort("private_key=abc\nlisten_port=51820\n"); err != nil || got != 51820 {
		t.Fatalf("effectiveListenPort = (%d, %v)", got, err)
	}
	if _, err := effectiveListenPort("listen_port=0\n"); err == nil {
		t.Fatal("effectiveListenPort accepted zero")
	}
}
