package main

var syscalls = []string{"execve", "execveat", "mmap", "mprotect", "clone", "fork", "vfork", "newstat",
	"newfstat", "newlstat", "mknod", "mknodat", "dup", "dup2", "dup3",
	"memfd_create", "socket", "close", "ioctl", "access", "faccessat", "kill", "listen",
	"connect", "accept", "accept4", "bind", "getsockname", "prctl", "ptrace",
	"process_vm_writev", "process_vm_readv", "init_module", "finit_module", "delete_module",
	"symlink", "symlinkat", "getdents", "getdents64", "creat", "open", "openat",
	"mount", "umount", "unlink", "unlinkat", "setuid", "setgid", "setreuid", "setregid",
	"setresuid", "setresgid", "setfsuid", "setfsgid"}
var sysevents = []string{"cap_capable", "do_exit"}
var essentialSyscalls = []string{"execve", "execveat"}
var essentialSysevents = []string{"do_exit"}

type argType int

const (
	NONE          argType = 0
	INT_T         argType = 1
	UINT_T        argType = 2
	LONG_T        argType = 3
	ULONG_T       argType = 4
	OFF_T_T       argType = 5
	MODE_T_T      argType = 6
	DEV_T_T       argType = 7
	SIZE_T_T      argType = 8
	POINTER_T     argType = 9
	STR_T         argType = 10
	STR_ARR_T     argType = 11
	SOCKADDR_T    argType = 12
	OPEN_FLAGS_T  argType = 13
	EXEC_FLAGS_T  argType = 14
	SOCK_DOM_T    argType = 15
	SOCK_TYPE_T   argType = 16
	CAP_T         argType = 17
	SYSCALL_T     argType = 18
	PROT_FLAGS_T  argType = 19
	ACCESS_MODE_T argType = 20
	TYPE_MAX      argType = 255
)

type bpfConfig int

const (
	CONFIG_CONT_MODE    bpfConfig = 0
	CONFIG_SHOW_SYSCALL bpfConfig = 1
)
