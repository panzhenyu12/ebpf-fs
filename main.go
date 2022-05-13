//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS --target=amd64 bpf kprobe.c -- -I./headers

const mapKey uint32 = 0

func main() {
	// logrus.Info(seccomp.GetApi())
	// if err := seccomp.SetApi(2); err != nil {
	// 	logrus.Error(err)
	// 	return
	// }
	// logrus.Info(seccomp.GetApi())
	// mkdircall, err := seccomp.GetSyscallFromName("mkdirat")
	// if err != nil {
	// 	logrus.Error(err)
	// 	return
	// }
	// filter, err := seccomp.NewFilter(seccomp.ActAllow)
	// if err != nil {
	// 	logrus.Error(err)
	// 	return
	// }
	// erract := seccomp.ActErrno.SetReturnCode(10)
	// err = filter.AddRule(mkdircall, erract)
	// if err != nil {
	// 	logrus.Error(err)
	// 	return
	// }
	// err = filter.AddArch(seccomp.ArchAMD64)
	// if err != nil {
	// 	logrus.Error(err)
	// 	return
	// }
	// logrus.Info(filter.IsValid())
	// err = filter.Load()
	// if err != nil {
	// 	logrus.Error(err)
	// 	return
	// }

	// for {
	// 	err := os.Mkdir("a", 0755)
	// 	if err != nil {
	// 		logrus.Error(err)
	// 		//return
	// 	}
	// 	time.Sleep(2 * time.Second)
	// }
	// //logrus.Info(mkdircall, err)
	// return
	// Name of the kernel function to trace.
	//do_sys_openat2
	fn := "sys_mkdir"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.

	kp, err := link.Kprobe(fn, objs.KprobeMkdir, nil)
	//kp, err := link.Tracepoint("syscalls", "sys_enter_mkdir", objs.TraceMkdir, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
	i := 0
	for range ticker.C {
		i++
		var value uint64
		// if err := objs.CountingMap.Lookup(mapKey, &value); err != nil {
		// 	log.Fatalf("reading map: %v", err)
		// }
		if err := objs.KprobeMap.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		// if i == 10 {
		// 	return
		// }
		log.Printf("%s called %d times\n", fn, value)
	}
}

//CONFIG_BPF_KPROBE_OVERRIDE
