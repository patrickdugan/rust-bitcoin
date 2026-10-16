#!/usr/bin/env bash
# Run a command, sampling its RSS and swap every second to $GUARD_LOG, and kill it if
# its swap use passes $GUARD_SWAP_MIB (default 6144). A proof that only finishes by
# paging is reported as memory-bound rather than timed. Exit 137 means the guard fired.
LIMIT=${GUARD_SWAP_MIB:-6144}
LOG=${GUARD_LOG:-/dev/null}
"$@" &
PID=$!
fired=0
while kill -0 $PID 2>/dev/null; do
  # The bench may run under wasmtime; sample the heaviest process in the child tree.
  for p in $PID $(pgrep -P $PID); do
    s=$(awk '/VmRSS|VmSwap/ {print $2}' /proc/$p/status 2>/dev/null | tr '\n' ' ')
    [ -n "$s" ] && echo "$(date +%s) $p $s" >> "$LOG"
    swap=$(echo $s | awk '{print int($2/1024)}')
    if [ "${swap:-0}" -gt "$LIMIT" ]; then
      echo "guard: pid $p swap ${swap} MiB > ${LIMIT} MiB, killing" >&2
      kill -9 $p $PID 2>/dev/null; fired=1
    fi
  done
  sleep 1
done
wait $PID; rc=$?
[ $fired = 1 ] && exit 137
exit $rc
