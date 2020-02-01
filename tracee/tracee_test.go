package tracee

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func Test_readArgFromBuff(t *testing.T) {
	testCases := []struct {
		name          string
		input         []byte
		expectedArg   interface{}
		expectedError error
	}{
		{
			name:        "IntT",
			input:       []byte{1, 0x85, 0xFF, 0xFF, 0xFF},
			expectedArg: int32(-123),
		},
		{
			name:        "UintT",
			input:       []byte{2, 0x7B, 0, 0, 0},
			expectedArg: uint32(123),
		},
		{
			name:        "LongT",
			input:       []byte{3, 0x15, 0x5F, 0xD0, 0xAC, 0x4B, 0x9B, 0xB6, 0xFF},
			expectedArg: int64(-20658398952399083),
		},
		{
			name:        "UlongT",
			input:       []byte{4, 0xEB, 0xA0, 0x2F, 0x53, 0xB4, 0x64, 0x49, 0x00},
			expectedArg: uint64(20658398952399083),
		},
		{
			name:        "StrT",
			input:       []byte{10, 16, 0, 0, 0, 47, 117, 115, 114, 47, 98, 105, 110, 47, 100, 111, 99, 107, 101, 114},
			expectedArg: "/usr/bin/docker",
		},
		//{ // FIXME: Find a valid input test case for this
		//	name:        "StrArrT",
		//	input:       []byte{11, 11, 11, 11, 11, 11, 11, 11, 11, 0, 0, 0, 0},
		//	expectedArg: "/usr/bin/docker",
		//},
		{
			name:        "CapT",
			input:       []byte{17, 10, 0, 0, 0},
			expectedArg: "CAP_NET_BIND_SERVICE",
		},
		{
			name:        "CapT, unknown capability",
			input:       []byte{17, 99, 0, 0, 0},
			expectedArg: "CAP_UNKNOWN",
		},
		{
			name:        "SyscallT",
			input:       []byte{18, 25, 0, 0, 0},
			expectedArg: "mremap",
		},
		{
			name:        "SyscallT, unknown syscall",
			input:       []byte{18, 0xFF, 0xFF, 0, 0},
			expectedArg: "syscall_unknown",
		},
		{
			name:          "unknown event type",
			input:         []byte{0xDE, 0xAD, 0xBE, 0xEF},
			expectedError: errors.New("error unknown arg type 222"),
		},
	}

	for _, tc := range testCases {
		actual, err := readArgFromBuff(bytes.NewReader(tc.input))
		assert.Equal(t, tc.expectedError, err, tc.name)
		assert.Equal(t, tc.expectedArg, actual, tc.name)
	}
}

func Test_New(t *testing.T) {
	tc := TraceConfig{
		BPFFile:               "./event_monitor_ebpf.c",
		Syscalls:              map[string]bool{},
		Sysevents:             map[string]bool{},
		ContainerMode:         false,
		DetectOriginalSyscall: false,
		OutputFormat:          "json",
	}
	tr, err := New(tc)
	require.NoError(t, err)
	assert.Equal(t, TraceConfig{
		BPFFile:               "./event_monitor_ebpf.c",
		Syscalls:              map[string]bool{"execve": true, "execveat": true},
		Sysevents:             map[string]bool{"do_exit": true},
		ContainerMode:         false,
		DetectOriginalSyscall: false,
		OutputFormat:          "json",
	}, tr.config)
	assert.NotNil(t, tr.bpfModule)
	assert.NotNil(t, tr.bpfPerfMap)
	assert.NotNil(t, tr.eventsChannel)
	assert.NotNil(t, tr.printer)

}
