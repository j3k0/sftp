#!/usr/bin/env bash
# Concurrency / memory test for an SFTP image under the production limits
# (mem_limit 64M, memswap_limit 64M). WPH-45 B2: Debian 12's default yescrypt
# needs ~16 MiB per password check, so parallel logins get OOM-killed.
#
# The test is only conclusive if swap is really limited for the container:
# otherwise memory pressure spills to host swap and nothing is OOM-killed.
# It therefore FAILS (not passes) when it cannot prove the swap limit.
#
# Usage: concurrency.sh IMAGE [PORT]
# Steps: A) open 10 sftp sessions and keep them open
#        B) 10 parallel wrong-password logins + 1 timed good login
#        C) open 10 more sessions (20 open in total), staggered
# Pass:  oom_kill delta 0, OOMKilled=false, RestartCount 0, still running,
#        20/20 sessions opened, 10/10 wrong passwords rejected,
#        good login during B <= 2 s.
set -u
IMAGE=${1:?usage: concurrency.sh IMAGE [PORT]}
PORT=${2:-$(( 20000 + RANDOM % 20000 ))}
USER_=admin
PASS=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
NAME=sftp-conc-$$
WORK=$(mktemp -d /tmp/sftp-conc.XXXX)
NPASS=0 NFAIL=0
log()  { echo "$*"; }
pass() { NPASS=$((NPASS+1)); log "PASS $1${2:+ -- $2}"; }
fail() { NFAIL=$((NFAIL+1)); log "FAIL $1${2:+ -- $2}"; }
info() { log "INFO $1${2:+ -- $2}"; }
cleanup() {
  jobs -p | xargs -r kill 2>/dev/null
  docker rm -f "$NAME" >/dev/null 2>&1
  docker run --rm -v "$WORK:/w" debian:bookworm rm -rf /w/html >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/html"
docker run --rm -v "$WORK:/w" debian:bookworm chown 33:33 /w/html
log "# image=$IMAGE id=$(docker image inspect -f '{{.Id}}' "$IMAGE" | cut -c8-19) date=$(date -Is)"
log "# host: $(docker info -f 'docker {{.ServerVersion}} cgroup v{{.CgroupVersion}} driver={{.CgroupDriver}}') nproc=$(nproc)"
docker run -d --name "$NAME" -v "$WORK/html:/var/www/html" -p "127.0.0.1:$PORT:22" \
  --memory 64m --memory-swap 64m --cpu-shares 256 \
  "$IMAGE" "$USER_:$PASS:33::/var/www" >/dev/null || { fail start; exit 1; }
CID=$(docker inspect -f '{{.Id}}' "$NAME")

# ---- 0. prove that swap is limited for this container ----
if docker info 2>&1 | grep -qi 'no swap limit support'; then
  fail swap-limited "docker reports 'No swap limit support': test NOT conclusive"
fi
CG=""
for d in /sys/fs/cgroup/system.slice/docker-$CID.scope /sys/fs/cgroup/docker/$CID /sys/fs/cgroup/memory/docker/$CID; do
  [ -d "$d" ] && { CG=$d; break; }
done
if [ -f "$CG/memory.swap.max" ]; then
  sw=$(cat "$CG/memory.swap.max"); mx=$(cat "$CG/memory.max")
  if [ "$sw" = 0 ] && [ "$mx" = $((64*1024*1024)) ]; then pass swap-limited "cgroup v2 memory.max=64M memory.swap.max=0"
  else fail swap-limited "memory.max=$mx memory.swap.max=$sw"; fi
elif [ -f "$CG/memory.memsw.limit_in_bytes" ]; then
  ms=$(cat "$CG/memory.memsw.limit_in_bytes")
  if [ "$ms" = $((64*1024*1024)) ]; then pass swap-limited "cgroup v1 memsw=64M"; else fail swap-limited "memsw=$ms"; fi
else
  fail swap-limited "no swap limit file found under '${CG:-?}': test NOT conclusive"
fi
oomk() { if [ -f "$CG/memory.events" ]; then awk '$1=="oom_kill"{print $2}' "$CG/memory.events"
         else awk '$1=="oom_kill"{print $2}' "$CG/memory.oom_control"; fi; }
stat_of() { awk -v k="$1" '$1==k{print $2}' "$CG/memory.stat"; }
OOM0=$(oomk); PGMAJ0=$(stat_of pgmajfault)

cat > "$WORK/askpass" <<'EOF'
#!/bin/sh
cat "$SFTP_PWFILE"
EOF
chmod 700 "$WORK/askpass"
(umask 077; printf '%s\n' "$PASS" > "$WORK/pw.good"; printf '%s\n' "wrong-$RANDOM-$RANDOM" > "$WORK/pw.bad")
OPTS=(-F /dev/null -o BatchMode=no -o IdentityFile=none -o IdentitiesOnly=yes -P "$PORT"
      -o ConnectTimeout=15 -o PreferredAuthentications=password -o PubkeyAuthentication=no
      -o NumberOfPasswordPrompts=1 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
# sftp reads commands from stdin; "pwd" then sleep keeps the session open
session() { # $1 = id, $2 = seconds to hold
  { echo pwd; sleep "$2"; echo bye; } | SFTP_PWFILE=$WORK/pw.good SSH_ASKPASS=$WORK/askpass \
    SSH_ASKPASS_REQUIRE=force DISPLAY=:0 setsid sftp "${OPTS[@]}" "$USER_@127.0.0.1" > "$WORK/s$1.out" 2>&1
}
wrong() { # $1 = id
  echo pwd | SFTP_PWFILE=$WORK/pw.bad SSH_ASKPASS=$WORK/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
    timeout 60 setsid sftp "${OPTS[@]}" "$USER_@127.0.0.1" > "$WORK/w$1.out" 2>&1
}
for _ in $(seq 1 30); do ssh-keyscan -T 2 -p "$PORT" 127.0.0.1 2>/dev/null | grep -q . && break; sleep 1; done

# ---- A. 10 sessions, held ----
for i in $(seq 1 10); do session "$i" 90 & sleep 0.3; done
sleep 8
nA=$(grep -l 'Remote working directory' "$WORK"/s{1..10}.out 2>/dev/null | wc -l)
info A.sessions-open "$nA/10, mem $(docker stats --no-stream --format '{{.MemUsage}}' "$NAME")"

# ---- B. 10 parallel wrong passwords + timed good login ----
for i in $(seq 1 10); do wrong "$i" & done
sleep 0.5
t0=$(date +%s.%N)
echo pwd | SFTP_PWFILE=$WORK/pw.good SSH_ASKPASS=$WORK/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
  timeout 60 setsid sftp "${OPTS[@]}" "$USER_@127.0.0.1" > "$WORK/good.out" 2>&1
t1=$(date +%s.%N)
sleep 15
LAT=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')
rej=0 drop=0 other=0
for i in $(seq 1 10); do
  if grep -qi 'permission denied' "$WORK/w$i.out"; then rej=$((rej+1))
  elif grep -qiE 'kex_exchange_identification|connection (reset|closed)' "$WORK/w$i.out"; then drop=$((drop+1))
  else other=$((other+1)); fi
done
if grep -q 'Remote working directory' "$WORK/good.out"; then
  if awk -v l="$LAT" 'BEGIN{exit !(l <= 2)}'; then pass B.good-login-latency "${LAT}s during 10 parallel wrong passwords"
  else fail B.good-login-latency "${LAT}s (> 2 s)"; fi
else fail B.good-login "failed: $(tr '\n' '|' < "$WORK/good.out" | head -c 200)"; fi
if [ "$rej" = 10 ]; then pass B.wrong-rejected "10/10"
else fail B.wrong-rejected "rejected=$rej MaxStartups-drops=$drop other=$other"; fi

# ---- C. 10 more sessions (20 open) ----
for i in $(seq 11 20); do session "$i" 45 & sleep 0.5; done
sleep 10
info C.mem-20-sessions "$(docker stats --no-stream --format '{{.MemUsage}} pids={{.PIDs}}' "$NAME")"
nAll=$(grep -l 'Remote working directory' "$WORK"/s{1..20}.out 2>/dev/null | wc -l)
if [ "$nAll" = 20 ]; then pass C.sessions-open "20/20"; else fail C.sessions-open "$nAll/20"; fi
sleep 2

# ---- verdict ----
OOM1=$(oomk); d=$((OOM1 - OOM0))
if [ "$d" = 0 ]; then pass oom_kill-delta "0"; else fail oom_kill-delta "$d process(es) OOM-killed"; fi
st=$(docker inspect -f '{{.State.Running}} OOMKilled={{.State.OOMKilled}} RestartCount={{.RestartCount}}' "$NAME")
if [ "$st" = "true OOMKilled=false RestartCount=0" ]; then pass container-state "$st"; else fail container-state "$st"; fi
peak=$(cat "$CG/memory.peak" 2>/dev/null || cat "$CG/memory.max_usage_in_bytes" 2>/dev/null)
info memory "peak=$(( ${peak:-0} / 1048576 ))MiB pgmajfault_delta=$(( $(stat_of pgmajfault) - PGMAJ0 )) events: $(tr '\n' ' ' < "$CG/memory.events" 2>/dev/null)"
n=$(docker logs "$NAME" 2>&1 | grep -cF "$PASS")
if [ "$n" = 0 ]; then pass no-password-in-logs; else fail no-password-in-logs "$n"; fi
log "SUMMARY $IMAGE: $NPASS passed, $NFAIL failed"
[ "$NFAIL" -eq 0 ]
