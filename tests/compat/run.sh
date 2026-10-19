#!/usr/bin/env bash
# Black-box compatibility test for an SFTP image emulating production compose usage.
# Usage: run.sh IMAGE [PORT]
set -u
IMAGE=${1:?usage: run.sh IMAGE [PORT]}
PORT=${2:-$(( 20000 + RANDOM % 20000 ))}
BASE=/tmp/sftp-compat
KEYS=$BASE/hostkeys
USER_=admin PASS=GstYVSjWAwNSsVMwdWFR6SEd
HELPER=debian:bookworm   # has OpenSSH 9.2: can still generate/scan DSA
SAFE=$(printf %s "$IMAGE" | tr -c 'A-Za-z0-9._-' '_')
RES=$BASE/results-$SAFE.txt
WORK=$(mktemp -d "$BASE/work.XXXX")
NAME=sftp-compat-$$
HTML=$WORK/html
NPASS=0 NFAIL=0
mkdir -p "$KEYS"; : > "$RES"

log()  { echo "$*" | tee -a "$RES"; }
pass() { NPASS=$((NPASS+1)); log "PASS $1${2:+ -- $2}"; }
fail() { NFAIL=$((NFAIL+1)); log "FAIL $1${2:+ -- $2}"; }
info() { log "INFO $1${2:+ -- $2}"; }
helper() { docker run --rm --network host -v "$KEYS:/k" -v "$WORK:/w" "$HELPER" bash -c \
  "command -v ssh-keygen >/dev/null || { apt-get -qq update && apt-get -qq install -y openssh-client >/dev/null 2>&1; }; $1"; }

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1
  # volume files may be owned by uid 33: remove from inside a container
  docker run --rm -v "$WORK:/w" "$HELPER" rm -rf /w/html >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---- 1. host keys (cached) ----
for t in rsa ecdsa ed25519; do
  [ -f "$KEYS/ssh_host_${t}_key" ] || ssh-keygen -q -t $t -N '' -f "$KEYS/ssh_host_${t}_key"
done
if [ ! -f "$KEYS/ssh_host_dsa_key" ]; then
  ssh-keygen -q -t dsa -N '' -f "$KEYS/ssh_host_dsa_key" 2>/dev/null ||
    helper "ssh-keygen -q -t dsa -N '' -f /k/ssh_host_dsa_key && chown $(id -u):$(id -g) /k/ssh_host_dsa_key*"
fi
chmod 600 "$KEYS"/*_key; chmod 644 "$KEYS"/*.pub

# ---- 2. container ----
mkdir -p "$HTML"
docker run --rm -v "$WORK:/w" "$HELPER" chown 33:33 /w/html   # prod html dir is www-data owned
MOUNTS=()
for t in dsa ecdsa ed25519 rsa; do for s in "" .pub; do
  [ -f "$KEYS/ssh_host_${t}_key$s" ] && MOUNTS+=(-v "$KEYS/ssh_host_${t}_key$s:/etc/ssh/ssh_host_${t}_key$s:ro")
done; done
log "# image=$IMAGE port=$PORT date=$(date -Is)"
log "# image id: $(docker image inspect -f '{{.Id}} created={{.Created}}' "$IMAGE" 2>&1)"
docker run -d --name "$NAME" -v "$HTML:/var/www/html" "${MOUNTS[@]}" -p "127.0.0.1:$PORT:22" \
  --restart always --memory 64m --memory-swap 64m --cpu-shares 256 \
  "$IMAGE" "$USER_:$PASS:33::/var/www" >/dev/null || { fail start "docker run failed"; exit 1; }

# ---- ssh helpers ----
cat > "$WORK/askpass" <<'EOF'
#!/bin/sh
printf '%s\n' "$SFTP_PW"
EOF
chmod +x "$WORK/askpass"
# -F /dev/null + IdentityFile=none: never touch the user's ~/.ssh; BatchMode=no: sftp -b would disable passwords
COMMON=(-F /dev/null
        -o BatchMode=no
        -o IdentityFile=none
        -o IdentitiesOnly=yes
        -P "$PORT"
        -o ConnectTimeout=10
        "-o PreferredAuthentications=password,keyboard-interactive"
        -o PubkeyAuthentication=no
        -o NumberOfPasswordPrompts=1
        -o LogLevel=ERROR)
# run_sftp PASSWORD BATCHFILE [extra ssh opts...]
run_sftp() {
  local pw=$1 batch=$2; shift 2
  SFTP_PW=$pw SSH_ASKPASS=$WORK/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
    timeout 30 setsid sftp "${COMMON[@]}" "$@" -b "$batch" "$USER_@127.0.0.1" </dev/null 2>&1
}
NOPIN=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
wait_port() { for _ in $(seq 1 30); do ssh-keyscan -T 2 -p "$PORT" 127.0.0.1 2>/dev/null | grep -q . && return 0; sleep 1; done; return 1; }

# ---- a. container alive ----
sleep 3
if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" = true ]; then pass a.running
else fail a.running "state=$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}}' "$NAME" 2>&1)"; fi
info a.logs "$(docker logs "$NAME" 2>&1 | tr '\n' '|' | head -c 1500)"
wait_port || fail a.port "port $PORT never answered"

# ---- b. host key scan ----
fp() { { ssh-keygen -lf "$1" 2>/dev/null || { p=${1/#$WORK//w}; helper "ssh-keygen -lf ${p/#$KEYS//k}" 2>/dev/null; }; } | awk '{print $2}'; }
OFFERED=()
for t in rsa ecdsa ed25519 dsa; do
  pubf=$KEYS/ssh_host_${t}_key.pub
  [ -f "$pubf" ] || { info b.keyscan.$t "no local key, skipped"; continue; }
  line=$(ssh-keyscan -T 5 -t $t -p "$PORT" 127.0.0.1 2>/dev/null | grep -v '^#' | head -1)
  via=local
  if [ -z "$line" ]; then   # local client may not speak this alg (e.g. dsa): try old client
    line=$(helper "ssh-keyscan -T 5 -t $t -p $PORT 127.0.0.1 2>/dev/null" | grep -v '^#' | head -1); via=$HELPER
  fi
  if [ -z "$line" ]; then fail b.keyscan.$t "not offered (tried local + $HELPER)"; continue; fi
  echo "$line" | cut -d' ' -f2- > "$WORK/scan_$t.pub"
  echo "$line" > "$WORK/kh_$t"
  got=$(fp "$WORK/scan_$t.pub"); want=$(fp "$pubf")
  if [ "$got" = "$want" ]; then pass b.keyscan.$t "$got (via $via)"; OFFERED+=("$t")
  else fail b.keyscan.$t "fingerprint mismatch got=$got want=$want"; fi
done
info b.offered "${OFFERED[*]:-none}"

# ---- c. sftp session ----
echo "hello compat $$ $(date +%s%N)" > "$WORK/up.txt"
cat > "$WORK/batch_c" <<EOF
pwd
ls
put $WORK/up.txt html/up.txt
mkdir html/sub
get html/up.txt $WORK/down.txt
rename html/up.txt html/sub/moved.txt
ls html/sub
EOF
out=$(run_sftp "$PASS" "$WORK/batch_c" "${NOPIN[@]}"); rc=$?
echo "$out" > "$WORK/out_c"
if [ $rc -eq 0 ]; then pass c.login+batch; else fail c.login+batch "rc=$rc: $(echo "$out" | tr '\n' '|' | head -c 600)"; fi
if grep -q 'Remote working directory: /$' "$WORK/out_c"; then pass c.pwd "/"
else fail c.pwd "$(grep -i 'working dir' "$WORK/out_c")"; fi
if awk '/^sftp> ls$/{f=1;next} /^sftp>/{f=0} f' "$WORK/out_c" | grep -qw html; then pass c.ls "html visible"
else fail c.ls "html not listed"; fi
if cmp -s "$WORK/up.txt" "$WORK/down.txt"; then pass c.get-roundtrip
else fail c.get-roundtrip "content differs/missing"; fi
if grep -q 'moved.txt' "$WORK/out_c"; then pass c.rename
else fail c.rename; fi

# ---- d. ownership on host volume ----
f=$HTML/sub/moved.txt
if [ -e "$f" ]; then
  info d.file-owner "$(stat -c 'uid:gid=%u:%g mode=%a' "$f") (baseline expectation 33:100)"
  info d.dir-owner "$(stat -c 'uid:gid=%u:%g mode=%a' "$HTML/sub") (html/sub)"
else fail d.file-owner "uploaded file not found on host volume"; fi

printf 'rm html/sub/moved.txt\nrmdir html/sub\n' > "$WORK/batch_rm"
out=$(run_sftp "$PASS" "$WORK/batch_rm" "${NOPIN[@]}"); rc=$?
if [ $rc -eq 0 ] && [ ! -e "$f" ]; then pass c.rm
else fail c.rm "rc=$rc: $(echo "$out" | tr '\n' '|')"; fi

# ---- e. chroot root not writable ----
printf 'put %s /root-write.txt\n' "$WORK/up.txt" > "$WORK/batch_e"
out=$(run_sftp "$PASS" "$WORK/batch_e" "${NOPIN[@]}"); rc=$?
# must be logged in (prompt echoed) and the open itself refused
if [ $rc -ne 0 ] && echo "$out" | grep -q '^sftp> put' && echo "$out" | grep -qi 'open.*\(permission denied\|failure\)'; then
  pass e.root-readonly "$(echo "$out" | grep -i 'open' | head -1)"
else fail e.root-readonly "rc=$rc: $(echo "$out" | tr '\n' '|')"; fi

# ---- f. wrong password ----
echo pwd > "$WORK/batch_pwd"
out=$(run_sftp "wrong-$PASS" "$WORK/batch_pwd" "${NOPIN[@]}"); rc=$?
if [ $rc -ne 0 ] && echo "$out" | grep -qi 'permission denied'; then pass f.wrong-password-rejected
else fail f.wrong-password-rejected "rc=$rc: $(echo "$out" | tr '\n' '|')"; fi

# ---- i. memory with an idle session (start before restart test) ----
mkfifo "$WORK/fifo"
( SFTP_PW=$PASS SSH_ASKPASS=$WORK/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
    timeout 30 setsid sftp "${COMMON[@]}" "${NOPIN[@]}" "$USER_@127.0.0.1" <"$WORK/fifo" >/dev/null 2>&1 ) &
exec 9>"$WORK/fifo"; sleep 3
info i.mem-idle-session "$(docker stats --no-stream --format '{{.MemUsage}} ({{.MemPerc}}) pids={{.PIDs}}' "$NAME")"
echo bye >&9; exec 9>&-; wait 2>/dev/null

# ---- g. restart ----
docker restart -t 5 "$NAME" >/dev/null
sleep 3; wait_port
out=$(run_sftp "$PASS" "$WORK/batch_pwd" "${NOPIN[@]}"); rc=$?
if [ $rc -eq 0 ]; then pass g.login-after-restart
else fail g.login-after-restart "rc=$rc: $(echo "$out" | tr '\n' '|' | head -c 400)"; fi
info g.logs-after-restart "$(docker logs --since 20s "$NAME" 2>&1 | tr '\n' '|' | head -c 800)"

# ---- h. pinned known_hosts, one key type at a time ----
for t in ecdsa ed25519 rsa dsa; do
  if [ ! -f "$WORK/kh_$t" ]; then
    if [ "$t" = dsa ]; then info h.pinned.$t "no scanned key, skipped"; else fail h.pinned.$t "no scanned key"; fi
    continue
  fi
  PIN=(-o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WORK/kh_$t")
  out=$(run_sftp "$PASS" "$WORK/batch_pwd" "${PIN[@]}"); rc=$?
  if [ $rc -eq 0 ]; then pass h.pinned.$t "default client algorithms"
  else
    det="rc=$rc: $(echo "$out" | grep -v '^@\|^IT IS\|^Someone\|^Please\|^It is also' | grep . | head -2 | tr '\n' '|' | head -c 250)"
    alg=$t; [ $t = rsa ] && alg=ssh-rsa; [ $t = dsa ] && alg=ssh-dss
    if run_sftp "$PASS" "$WORK/batch_pwd" "${PIN[@]}" -o HostKeyAlgorithms=+$alg >/dev/null; then
      fail h.pinned.$t "local $(ssh -V 2>&1 | cut -d, -f1) fails by default ($det); works with -o HostKeyAlgorithms=+$alg"
    # local client may not support the alg at all (dsa): retry with the older helper client
    elif helper "cp /w/askpass /tmp/ap; SFTP_PW='$PASS' SSH_ASKPASS=/tmp/ap SSH_ASKPASS_REQUIRE=force DISPLAY=:0 setsid \
        sftp -F /dev/null -o BatchMode=no -o IdentityFile=none -o PreferredAuthentications=password -P $PORT \
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/w/kh_$t -o HostKeyAlgorithms=+$alg -b /w/batch_pwd \
        $USER_@127.0.0.1 </dev/null" >/dev/null 2>&1; then
      fail h.pinned.$t "local client fails ($det); works from $HELPER client (OpenSSH 9.2) with HostKeyAlgorithms=+$alg"
    else fail h.pinned.$t "$det (also fails with +$alg and from $HELPER)"; fi
  fi
done

info sshd-version "$(docker exec "$NAME" sh -c 'ssh -V 2>&1; grep PRETTY /etc/os-release' 2>&1 | tr '\n' ' ')"
log "SUMMARY $IMAGE: $NPASS passed, $NFAIL failed (results: $RES)"
[ $NFAIL -eq 0 ]
