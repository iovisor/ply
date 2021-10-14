#!/bin/sh

total_fails=0

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
    "kprobe:vfs_* { @[comm, caller] = count(); }" >/tmp/wildcard \
&& \
cat /tmp/wildcard | awk '
    /dd.*vfs_read/  { if ($NF > 100) read  = 1; }
    /dd.*vfs_write/ { if ($NF > 100) write = 1; }
    END             { exit(!(read && write)); }' \
|| fail "at least 100 reads/writes" "$(cat /tmp/wildcard)"


case=quantize
ply -c \
    "dd if=/dev/zero of=/dev/null bs=10240 count=10" \
    'kr:vfs_read if (!strcmp(comm, "dd")) {
    		 @["rdsz"] = quantize(retval);
     }' >/tmp/quantize \
&& \
grep -qe '8k\s*,\s*16k\s*)\s*10' /tmp/quantize \
|| fail "10 reads in (8k, 16k]" "$(cat /tmp/quantize)"

case=interval
ply -c 'for i in `seq 3`; do dd if=/dev/zero of=/dev/null count=10; sleep 1; done' \
    'k:vfs_read { @[pid] = count(); }
     i:1 { print(@); clear(@); }' >/tmp/interval \
&& \
cat /tmp/interval | awk '/^@:/ { count++; } END { exit(count < 3); }' \
|| fail "at least 3 print" "$(cat /tmp/interval)"

exit $total_fails
