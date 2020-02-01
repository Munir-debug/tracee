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
	testCases := []struct {
		name                string
		inputTraceConfig    TraceConfig
		expectedTraceConfig TraceConfig
		expectedError       error
	}{
		{
			name: "happy path, with no extra syscalls or sysevents",
			inputTraceConfig: TraceConfig{
				BPFFile:               "./event_monitor_ebpf.c",
				Syscalls:              map[string]bool{},
				Sysevents:             map[string]bool{},
				ContainerMode:         false,
				DetectOriginalSyscall: false,
				OutputFormat:          "json",
			},
			expectedTraceConfig: TraceConfig{
				BPFFile:               "./event_monitor_ebpf.c",
				Syscalls:              map[string]bool{"execve": true, "execveat": true},
				Sysevents:             map[string]bool{"do_exit": true},
				ContainerMode:         false,
				DetectOriginalSyscall: false,
				OutputFormat:          "json",
			},
		},
		{
			name: "happy path, with extra syscalls and sysevents",
			inputTraceConfig: TraceConfig{
				BPFFile:               "./event_monitor_ebpf.c",
				Syscalls:              map[string]bool{"mmap": true, "fork": true},
				Sysevents:             map[string]bool{"cap_capable": true},
				ContainerMode:         false,
				DetectOriginalSyscall: false,
				OutputFormat:          "table",
			},
			expectedTraceConfig: TraceConfig{
				BPFFile:               "./event_monitor_ebpf.c",
				Syscalls:              map[string]bool{"execve": true, "execveat": true, "mmap": true, "fork": true},
				Sysevents:             map[string]bool{"do_exit": true, "cap_capable": true},
				ContainerMode:         false,
				DetectOriginalSyscall: false,
				OutputFormat:          "table",
			},
		},
		{
			name:             "sad path, no bpf code file specified",
			inputTraceConfig: TraceConfig{},
			expectedError:    errors.New("validation error: trace config validation failed: no bpf program file specified"),
		},
	}

	for _, tc := range testCases {
		tr, err := New(tc.inputTraceConfig)
		switch {
		case tc.expectedError != nil:
			require.Equal(t, tc.expectedError, err, tc.name)
		default:
			require.NoError(t, err, tc.name)
			assert.Equal(t, tc.expectedTraceConfig, tr.config, tc.name)
			assert.NotNil(t, tr.bpfModule, tc.name)
			assert.NotNil(t, tr.bpfPerfMap, tc.name)
			assert.NotNil(t, tr.eventsChannel, tc.name)
			assert.NotNil(t, tr.printer, tc.name)
			tr.Close()
		}
	}
}
