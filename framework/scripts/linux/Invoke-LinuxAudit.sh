#!/usr/bin/env bash
# Invoke-LinuxAudit.sh - read-only Linux hardening/exposure audit (our linPEAS-style equivalent, report only).
# Reads configuration and file metadata. Modifies nothing, copies no keys, reads no secrets.
# Usage: ./Invoke-LinuxAudit.sh [outfile.json]
set -u
OUT="${1:-linuxaudit_$(hostname).json}"
findings=()

add() { # id severity title detail
  local d="${4//\\/\\\\}"; d="${d//\"/\\\"}"
  findings+=("{\"id\":\"$1\",\"severity\":\"$2\",\"title\":\"$3\",\"detail\":\"$d\"}")
}

# sudo rules that grant passwordless root or allow shell escapes (config read only)
if [ -r /etc/sudoers ]; then
  while IFS= read -r line; do
    add LIN-SUDO-NOPASSWD High "Passwordless sudo rule" "$line"
  done < <(grep -hE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^\s*#')
fi

# SUID/SGID binaries outside the usual system set (names only)
while IFS= read -r f; do
  add LIN-SUID Medium "Unexpected SUID/SGID binary" "$f"
done < <(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null \
  | grep -Ev '^/(usr/(bin|sbin|lib|libexec)|bin|sbin)/(sudo|su|passwd|chsh|chfn|gpasswd|newgrp|mount|umount|ping|pkexec|chage|expiry|wall|write|ssh-agent|crontab|at)$' | head -50)

# world-writable files referenced by cron
for c in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/*; do
  [ -f "$c" ] || continue
  if [ -w "$c" ] && [ "$(id -u)" -ne 0 ]; then add LIN-CRON-WRITABLE High "Cron file writable by current user" "$c"; fi
  perm=$(stat -c '%a' "$c" 2>/dev/null); case "$perm" in *[2367]) add LIN-CRON-WORLDW High "World-writable cron file" "$c";; esac
done

# SSH private keys readable by others, and weak sshd settings (paths and settings only, no key content)
for d in /home/* /root; do
  for k in "$d"/.ssh/id_*; do
    [ -f "$k" ] || continue
    case "$k" in *.pub) continue;; esac
    perm=$(stat -c '%a' "$k" 2>/dev/null)
    case "$perm" in 600|400) ;; *) add LIN-SSH-KEYPERM Medium "SSH private key has loose permissions" "$k ($perm)";; esac
  done
done
if [ -r /etc/ssh/sshd_config ]; then
  grep -qiE '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config && add LIN-SSH-ROOT High "sshd permits root login" "PermitRootLogin yes"
  grep -qiE '^\s*PasswordAuthentication\s+yes' /etc/ssh/sshd_config && add LIN-SSH-PWAUTH Low "sshd allows password authentication" "PasswordAuthentication yes"
fi

# writable directories in root's PATH-like system paths and key file permissions
[ -w /etc/passwd ] && [ "$(id -u)" -ne 0 ] && add LIN-PASSWD-WRITABLE Critical "/etc/passwd writable by current user" "/etc/passwd"
[ -r /etc/shadow ] && [ "$(id -u)" -ne 0 ] && add LIN-SHADOW-READABLE Critical "/etc/shadow readable by current user" "/etc/shadow"

# linux capabilities on binaries (names only)
if command -v getcap >/dev/null 2>&1; then
  while IFS= read -r l; do add LIN-CAP Medium "File capability set" "$l"; done < <(getcap -r / 2>/dev/null | head -30)
fi

# docker socket exposure
[ -w /var/run/docker.sock ] && [ "$(id -u)" -ne 0 ] && add LIN-DOCKER-SOCK High "Docker socket writable by current user (root-equivalent)" "/var/run/docker.sock"

{
  printf '{"host":"%s","collectedUtc":"%s","findings":[' "$(hostname)" "$(date -u +%FT%TZ)"
  (IFS=,; printf '%s' "${findings[*]:-}")
  printf ']}\n'
} > "$OUT"
echo "[+] Linux audit -> $OUT (${#findings[@]} finding(s); read-only)"
