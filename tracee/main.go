package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "Tracee",
		Usage: "Trace container syscalls and events",
		Action: func(c *cli.Context) error {
			t := Tracee{}
			return t.Run()
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

type Tracee struct {
}

func (t Tracee) Run() error {
	var err error
	bpfText, err := ioutil.ReadFile("./event_monitor_ebpf.c")
	if err != nil {
		return fmt.Errorf("error reading ebpf program file: %v", err)
	}
	m := bpf.NewModule(string(bpfText), []string{})
	defer m.Close()

	for _, sc := range essentialSyscalls {
		kp, err := m.LoadKprobe(fmt.Sprintf("syscall__%s", sc))
		if err != nil {
			return fmt.Errorf("error loading kprobe %s: %v", sc, err)
		}
		err = m.AttachKprobe(bpf.GetSyscallFnName(sc), kp, -1)
		if err != nil {
			return fmt.Errorf("error attaching kprobe %s: %v", sc, err)
		}
		kp, err = m.LoadKprobe(fmt.Sprintf("trace_ret_%s", sc))
		if err != nil {
			return fmt.Errorf("error loading kprobe %s: %v", sc, err)
		}
		err = m.AttachKretprobe(bpf.GetSyscallFnName(sc), kp, -1)
		if err != nil {
			return fmt.Errorf("error attaching kretprobe %s: %v", sc, err)
		}
	}

	eventsBPFTable := bpf.NewTable(m.TableId("events"), m)
	eventsChannel := make(chan []byte, 1000)
	eventsPerfMap, err := bpf.InitPerfMap(eventsBPFTable, eventsChannel)
	if err != nil {
		return fmt.Errorf("error initializing events perf map: %v", err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		for {
			data := <-eventsChannel
			fmt.Println("Event: ")
			fmt.Println(data)
		}
	}()

	eventsPerfMap.Start()
	<-sig
	eventsPerfMap.Stop()

	return nil
}
