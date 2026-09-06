package fidohid

import (
	"bytes"
	"testing"
)

func TestMultiPacketMessageWaitsForContinuation(t *testing.T) {
	device := &Device{channels: make(map[uint32]*channel)}
	payload := bytes.Repeat([]byte{0xAB}, initDataLen)

	device.handleInitPacket(1, cmdCBOR, 100, payload)

	assembled := device.channels[1]
	if assembled == nil {
		t.Fatal("channel was not created")
	}
	if got := len(assembled.data); got != initDataLen {
		t.Fatalf("initial fragment length = %d, want %d", got, initDataLen)
	}
	if assembled.totalLen != 100 {
		t.Fatalf("total message length = %d, want 100", assembled.totalLen)
	}
}
