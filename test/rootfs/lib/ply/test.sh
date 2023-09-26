#!/bin/sh

total_fails=0

atomics_supported()
{
    case $(uname -m) in
	arm*)
	    # No JIT support for atomic operations as of Linux 6.6.
	    # Alpine kernels set CONFIG_BPF_JIT_ALWAYS_ON, which means
	    # we can't run ply scripts that generate those.
	    return 1
	    ;;
    esac

    return 0
}

fail()
{
    echo "  FAIL $case expected \"$1\", got \"$2\""
    total_fails=$(($total_fails + 1))
}

ply_simple()
{
    stdout=$(ply -c true "tracepoint:sched/sched_process_exit { ${1} }")
    code=$?
}

case=self-test
ply -T || fail "zero exitcode" "non-zero exitcode"

case=exit && ply_simple 'exit(42);' && \
    [ $code -eq 42 ] || fail 42 $code

case=if-stmt && ply_simple 'if (pid > 1) exit(0); else exit(1);' && \
    [ $code -eq 0 ] || fail 0 $code

case=print && ply_simple 'print("test"); exit(0);' && \
    [ $stdout = test ] || fail test "$stdout"


case=wildcard
ply -c \
    "dd if=/dev/zero of=/dev/null bs=1 count=100" \
    "kprobe:vfs_*r[ei][at][de] { @[comm, caller] = count(); }" >/tmp/wildcard \
&& \
cat /tmp/wildcard | awk '
    /dd.*vfs_read/  { if ($NF >= 100) read  = 1; }
    /dd.*vfs_write/ { if ($NF >= 100) write = 1; }
    END             { exit(!(read && write)); }' \
|| fail "at least 100 reads/writes" "$(cat /tmp/wildcard)"


if atomics_supported; then
    case=quantize
    ply -c \
	"dd if=/dev/zero of=/dev/null bs=10240 count=10" \
	'kr:vfs_read if (!strcmp(comm, "dd")) {
    		 @["rdsz"] = quantize(retval);
     }' >/tmp/quantize \
	&& \
	grep -qe '8k\s*,\s*16k\s*)\s*10' /tmp/quantize \
	    || fail "10 reads in (8k, 16k]" "$(cat /tmp/quantize)"
fi

case=interval
ply -c 'for i in `seq 3`; do dd if=/dev/zero of=/dev/null count=10; sleep 1; done' \
    'k:vfs_read { @[pid] = count(); }
     i:1 { print(@); clear(@); }' >/tmp/interval \
&& \
cat /tmp/interval | awk '/^@:/ { count++; } END { exit(count < 3); }' \
|| fail "at least 3 print" "$(cat /tmp/interval)"

case=tracepoint-dyn
ply -c 'for i in $(seq 10); do uname >/dev/null; done' \
    'tracepoint:sched/sched_process_exec {
        @[dyn(data->filename)] = count();
    }' >/tmp/tracepoint-dyn \
&& \
cat /tmp/tracepoint-dyn | awk '
    /uname/  { unames = $NF; }
    END      { exit(!(unames >= 10)); }' \
|| fail "at least 10 unames" "$(cat /tmp/tracepoint-dyn)"

case=profile
ply 'BEGIN { printf("profile provider unit test\n"); c["profile_test"] = 0; }
     profile:0:100hz
     {
         if (c["profile_test"] == 100)
             exit(0);
         else
             c["profile_test"] = c["profile_test"] + 1;
     }' >/tmp/profile \
&& \
cat /tmp/profile | awk -F': ' '
    /profile_test/  { count = $2; }
    END             { exit(count != 100); }' \
|| fail "count should be 100 for profile provider test" "$(cat /tmp/profile)"

exit $total_fails
