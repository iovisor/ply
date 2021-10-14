#!/bin/sh

set -e

if [ ! "$PLYBIN" ]; then
    echo PLYBIN is not set
    exit 1
fi

err=0

if [ -f /proc/config.gz ]; then
    echo -n "Verifying kernel config (/proc/config.gz)... "
    kconf="zcat /proc/config.gz"
elif [ -f /boot/config-$(uname -r) ]; then
    echo -n "Verifying kernel config (/boot/config-$(uname -r))... "
    kconf="cat /boot/config-$(uname -r)"
fi

if [ "$kconf" ]; then
    $kconf | awk '
	/^CONFIG_BPF_SYSCALL=y$/    { bpf=1 }
	/^CONFIG_KPROBES=y$/        { kprobes=1 }
	/^CONFIG_UPROBES=y$/        { uprobes=1 }
	/^CONFIG_TRACEPOINTS=y$/    { tracepoints=1 }
	/^CONFIG_FTRACE=y$/         { ftrace=1 }
	/^CONFIG_DYNAMIC_FTRACE=y$/ { dftrace=1 }
	/^CONFIG_PERF_EVENTS=y$/    { perf_events=1 }
	END {
	    if (bpf && (kprobes || tracepoints) && ftrace) {
	       print("OK");
	       err = 0;
	    } else {
	       print("ERROR");
	       err = 1;
	    }

	    if (!bpf)
	       print("  CONFIG_BPF_SYSCALL is not set");
	    if (!kprobes)
	       print("  CONFIG_KPROBES is not set");
	    if (!uprobes)
	       print("  CONFIG_UPROBES is not set");
	    if (!tracepoints)
	       print("  CONFIG_TRACEPOINTS is not set");
	    if (!ftrace)
	       print("  CONFIG_FTRACE is not set");
	    if (!dftrace)
	       print("  CONFIG_DYNAMIC_FTRACE is not set");
	    if (!perf_events)
	       print("  CONFIG_PERF_EVENTS is not set");

	    exit(err);
	}' || err=1
else
    echo "WARN: Unable to verify kernel config"
fi

echo -n "Ensuring that debugfs is mounted... "
if mountpoint -q /sys/kernel/debug; then
    echo "OK"
else
    echo "ERROR"
    err=1
fi

if [ $(id -u) -ne 0 ]; then
    echo "WARN: not running as root, ply requires cap_sys_admin"
fi

echo -n "Verifying kprobe... "
if $PLYBIN 'kprobe:schedule { exit(0); }' 2>/dev/null; then
    echo "OK"
else
    echo "ERROR"
    err=1
fi

echo -n "Verifying tracepoint... "
if $PLYBIN 'tracepoint:sched/sched_switch { exit(0); }' 2>/dev/null; then
    echo "OK"
else
    echo "ERROR"
    err=1
fi

echo -n "Verifying special... "
if $PLYBIN 'BEGIN { exit(0); }' 2>/dev/null; then
    echo "OK"
else
    echo "ERROR"
    err=1
fi

echo -n "Verifying interval... "
if $PLYBIN 'interval:1s { exit(0); }' 2>/dev/null; then
    echo "OK"
else
    echo "ERROR"
    err=1
fi

exit $err
