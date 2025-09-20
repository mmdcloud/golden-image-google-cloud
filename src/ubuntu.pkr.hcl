packer {
  required_plugins {
    googlecompute = {
      source  = "github.com/hashicorp/googlecompute"
      version = "~> 1"
    }
  }
}

source "googlecompute" "nginx" {
  project_id              = "encoded-alpha-457108-e8"
  source_image            = "ubuntu-2004-focal-v20220204"
  image_name              = "packer-putrisinu-nginx-{{timestamp}}"
  image_family            = "packer-putrisinu-nginx"  
  image_storage_locations = ["us-central1"]
  image_labels = {
    "os" : "ubuntu"
    "application" : "nginx"
  }
  ssh_username       = "packer-sa"  
  instance_name      = "packer-nginx-image-build"
  zone               = "us-central1-b"    
  metadata = {
    block-project-ssh-keys = "true"
  }
  tags = ["nginx", "packer"]
}

build {
  sources = [
    "source.googlecompute.nginx"
  ]

  // provisioner "file" {
  //   source      = "scripts"
  //   destination = "/tmp/"
  // }

  provisioner "shell" {
    inline = [
      #!/bin/bash
      "sudo apt-get update",
      "sudo apt-get install -y nginx",
      "curl -sL https://deb.nodesource.com/setup_20.x -o nodesource_setup.sh",
      "sudo bash nodesource_setup.sh",
      "sudo apt install nodejs -y"
      # ubuntu-harden.sh
      # Advanced Ubuntu hardening script (idempotent-ish).
      # TARGET: Ubuntu 20.04 / 22.04 / 24.04 LTS (may work on other debians with tweaks)
      # REVIEW before running. Test in staging first.
      set -euo pipefail
      IFS=$'\n\t'

      ### CONFIGURATION — Review & adjust these ###
      ADMIN_USER="admin"                # ensure this user exists and you have a session as them
      ALLOW_SSH_FROM=""                 # CIDR (e.g. "203.0.113.0/24") or leave empty to allow all (not recommended)
      SSH_PORT=2222                     # change to your chosen ssh port (ensure firewall allows)
      ENABLE_UNATTENDED_UPGRADES=true
      TIMEZONE="UTC"
      DISABLE_ROOT_LOGIN=true
      LOCKDOWN_SSH_PASSWORD_AUTH=false  # true = disable password login (recommend using SSH keys)
      MAX_PASSWORD_AGE=90
      MIN_PASSWORD_LEN=14
      REQUIRE_DIGIT=true
      REQUIRE_UPPER=true
      REQUIRE_LOWER=true
      REQUIRE_SYMBOL=true

      BACKUP_DIR="/root/hardening-backups-$(date +%F_%T)"
      LOGFILE="/var/log/hardening-$(date +%F).log"

      ### Helpers ###
      log() { echo "[$(date -Iseconds)] $*"; echo "[$(date -Iseconds)] $*" >> "${LOGFILE}"; }
      ensure_root() {
        if [ "$EUID" -ne 0 ]; then
          echo "This script must be run as root. Use sudo." >&2
          exit 1
        fi
      }
      backup_file() {
        local f=$1
        mkdir -p "$BACKUP_DIR"
        if [ -f "$f" ]; then
          cp -a "$f" "${BACKUP_DIR}/$(basename $f).bak"
        fi
      }

      ensure_root
      mkdir -p "$(dirname "$LOGFILE")"
      log "Starting Ubuntu hardening script"
      log "Backup dir: $BACKUP_DIR"

      ### 0) Basic safety: ensure admin user exists and we won't lock ourselves out ###
      if ! id -u "$ADMIN_USER" >/dev/null 2>&1; then
        log "Admin user '$ADMIN_USER' does not exist. Creating..."
        adduser --gecos "" "$ADMIN_USER"
        usermod -aG sudo "$ADMIN_USER"
        log "Created user $ADMIN_USER; please set a secure password for them now."
      fi

      ### 1) Update system and install required packages ###
      log "Updating apt repos and installing required packages..."
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get upgrade -y
      apt-get install -y \
        unattended-upgrades apt-listchanges fail2ban ufw auditd audispd-plugins passwd pwquality \
        apparmor apparmor-utils rsyslog logrotate debsums unattended-upgrades \
        haveged resolvconf cryptsetup-bin

      # Optional: enable entropy daemon
      systemctl enable --now haveged || true

      ### 2) Timezone & basic locale ###
      timedatectl set-timezone "${TIMEZONE}" || true

      ### 3) Enable and configure unattended-upgrades (security-only) ###
      if [ "$ENABLE_UNATTENDED_UPGRADES" = true ]; then
        log "Configuring unattended-upgrades"
        dpkg-reconfigure -f noninteractive unattended-upgrades || true
        # Ensure config enforces security updates
        backup_file /etc/apt/apt.conf.d/50unattended-upgrades
        cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
      Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
        // Uncomment the following to enable updates from the -updates repository
        // "${distro_id}:${distro_codename}-updates";
      };
      Unattended-Upgrade::Automatic-Reboot "true";
      Unattended-Upgrade::Automatic-Reboot-Time "02:00";
      EOF
        systemctl enable --now unattended-upgrades
      fi

      ### 4) SSH hardening ###
      log "Hardening SSH configuration"
      backup_file /etc/ssh/sshd_config
      # Keep a copy to revert quickly if you get locked out
      cp -a /etc/ssh/sshd_config "${BACKUP_DIR}/sshd_config.pre-harden"

      # Minimal secure config
      cat > /etc/ssh/sshd_config <<EOF
      Port ${SSH_PORT}
      AddressFamily any
      ListenAddress 0.0.0.0
      Protocol 2
      PermitRootLogin ${DISABLE_ROOT_LOGIN:-yes}
      MaxAuthTries 4
      LoginGraceTime 30
      PermitEmptyPasswords no
      ChallengeResponseAuthentication no
      PasswordAuthentication ${LOCKDOWN_SSH_PASSWORD_AUTH:+no}
      PubkeyAuthentication yes
      PermitUserEnvironment no
      UseDNS no
      AllowAgentForwarding no
      AllowTcpForwarding no
      X11Forwarding no
      ClientAliveInterval 300
      ClientAliveCountMax 2
      KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
      Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
      MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
      PermitTunnel no
      AcceptEnv LANG LC_*
      UsePAM yes
      EOF

      # Ensure admin user key-based access — create .ssh dir if not present
      if [ ! -d "/home/${ADMIN_USER}/.ssh" ]; then
        mkdir -p "/home/${ADMIN_USER}/.ssh"
        chown "${ADMIN_USER}:${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"
        chmod 700 "/home/${ADMIN_USER}/.ssh"
      fi

      # Restart SSHd safely (do not exit on failure)
      log "Restarting sshd"
      sshd -t && systemctl reload sshd || { log "sshd test failed; restoring previous config"; cp "${BACKUP_DIR}/sshd_config.pre-harden" /etc/ssh/sshd_config; systemctl restart sshd; exit 1; }

      ### 5) UFW firewall rules ###
      log "Configuring UFW firewall"
      backup_file /etc/ufw/ufw.conf
      ufw default deny incoming
      ufw default allow outgoing
      # Allow loopback
      ufw allow in on lo
      # Allow SSH from specific CIDR if provided, else from all (you should set ALLOW_SSH_FROM)
      if [ -n "$ALLOW_SSH_FROM" ]; then
        ufw allow from ${ALLOW_SSH_FROM} to any port ${SSH_PORT} proto tcp comment 'SSH access'
      else
        ufw allow ${SSH_PORT}/tcp comment 'SSH access (OPEN - consider setting ALLOW_SSH_FROM)'
      fi
      # Allow essential services (HTTP/HTTPS) - comment out if not needed
      ufw allow 80/tcp comment 'HTTP'
      ufw allow 443/tcp comment 'HTTPS'
      ufw --force enable
      systemctl enable --now ufw

      ### 6) Fail2Ban basic config ###
      log "Configuring fail2ban"
      backup_file /etc/fail2ban/jail.local
      cat > /etc/fail2ban/jail.local <<EOF
      [DEFAULT]
      bantime = 1h
      findtime = 10m
      maxretry = 5
      backend = systemd

      [sshd]
      enabled = true
      port = ${SSH_PORT}
      filter = sshd
      logpath = /var/log/auth.log
      maxretry = 5
      EOF
      systemctl enable --now fail2ban

      ### 7) PAM & password policies ###
      log "Setting password complexity and aging policies (pwquality & pam)"
      backup_file /etc/security/pwquality.conf
      cat > /etc/security/pwquality.conf <<EOF
      minlen = ${MIN_PASSWORD_LEN}
      dcredit = ${REQUIRE_DIGIT:+-1}
      ucredit = ${REQUIRE_UPPER:+-1}
      lcredit = ${REQUIRE_LOWER:+-1}
      ocredit = ${REQUIRE_SYMBOL:+-1}
      minclass = 4
      EOF

      # Configure password aging for all users (except system accounts)
      log "Setting default password aging (skipping system accounts)"
      for user in $(awk -F: '($3 >= 1000 && $1 != "nobody"){print $1}' /etc/passwd); do
        chage --maxdays ${MAX_PASSWORD_AGE} "$user" || true
      done

      # Enforce PAM password attempts and lockout
      backup_file /etc/pam.d/common-auth
      if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
        cat > /etc/pam.d/common-auth <<'EOF'
      auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900
      auth [success=1 default=bad] pam_unix.so nullok_secure try_first_pass
      auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
      account required pam_faillock.so
      EOF
      fi

      ### 8) Kernel hardening via sysctl ###
      log "Applying kernel/network sysctl hardening"
      backup_file /etc/sysctl.d/99-hardening.conf
      cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
      # Network hardening
      net.ipv4.ip_forward = 0
      net.ipv4.conf.all.send_redirects = 0
      net.ipv4.conf.default.send_redirects = 0
      net.ipv4.conf.all.accept_redirects = 0
      net.ipv4.conf.default.accept_redirects = 0
      net.ipv4.conf.all.accept_source_route = 0
      net.ipv4.conf.default.accept_source_route = 0
      net.ipv6.conf.all.accept_redirects = 0
      net.ipv6.conf.default.accept_redirects = 0

      # TCP settings
      net.ipv4.tcp_syncookies = 1
      net.ipv4.tcp_timestamps = 0

      # IPv6 (disable if not used)
      net.ipv6.conf.all.disable_ipv6 = 0

      # Source route / ICMP
      net.ipv4.icmp_echo_ignore_broadcasts = 1

      # Buffer overflows
      fs.suid_dumpable = 0
      kernel.randomize_va_space = 2

      # File max
      fs.protected_hardlinks = 1
      fs.protected_symlinks = 1
      EOF
      sysctl --system

      ### 9) Mount options and fstab hardening ###
      log "Harden /tmp and other mounts (using tmpfs where appropriate)"
      # Ensure /tmp is mounted with noexec,nosuid,nodev (if acceptable)
      backup_file /etc/fstab
      if ! mount | grep -q " on /tmp "; then
        mkdir -p /tmp
        chmod 1777 /tmp
        # Add line if not present; this sets noexec,nosuid,nodev (be careful with apps that require exec in /tmp)
        if ! grep -q " /tmp " /etc/fstab; then
          echo "tmpfs /tmp tmpfs rw,nodev,nosuid,noexec,mode=1777 0 0" >> /etc/fstab || true
          mount -o remount /tmp || true
        fi
      fi

      ### 10) Auditd: base rules for kernel auditing ###
      log "Configuring auditd rules"
      backup_file /etc/audit/audit.rules
      cat > /etc/audit/audit.rules <<'EOF'
      # Generated audit rules - basic set
      -D
      -b 8192
      # Keep logs
      -f 1

      # Monitor system calls for changes
      -w /etc/passwd -p wa -k identity
      -w /etc/shadow -p wa -k identity
      -w /etc/group -p wa -k identity
      -w /etc/gshadow -p wa -k identity
      -w /etc/sudoers -p wa -k scope
      -w /etc/ssh/sshd_config -p wa -k sshd
      # Monitor suid/sgid programs
      -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k suid
      # Kernel module loading
      -w /sbin/insmod -p x -k modules
      -w /sbin/rmmod -p x -k modules
      # Monitor changes to audit config
      -w /etc/audit/ -p wa -k auditconfig
      EOF
      systemctl restart auditd

      ### 11) AppArmor — enforce default profiles ###
      log "Ensuring AppArmor is enabled and enforce mode for loaded profiles"
      systemctl enable --now apparmor || true
      aa-status || true
      # Try to enforce loaded profiles (best-effort)
      for p in $(apparmor_status --profiles 2>/dev/null | awk '/\/etc/|\/var/{print $1}' || true); do
        aa-enforce "$p" || true
      done

      ### 12) Remove unnecessary packages & enable package integrity checks ###
      log "Removing commonly unused packages (telnet rsh rexec) and enabling debsums cron"
      apt-get remove -y --purge telnetd rsh-client rsh-redone-client talk openssh-server-legacy 2>/dev/null || true
      # Ensure debsums cron exists to verify package integrity (install if missing)
      if ! dpkg -l | grep -q debsums; then
        apt-get install -y debsums
      fi
      # Create a daily integrity check
      cat > /etc/cron.daily/debsums <<'EOF'
      #!/bin/sh
      /usr/bin/debsums -s || true
      EOF
      chmod +x /etc/cron.daily/debsums

      ### 13) Secure GRUB bootloader (require password to edit) ###
      log "Securing GRUB configuration (set a password manually after reviewing)"
      backup_file /etc/default/grub
      # Note: We do NOT write a password here. The admin must create a hash using grub-mkpasswd-pbkdf2
      # Example manual steps (documented):
      cat > "${BACKUP_DIR}/GRUB_INSTRUCTIONS.txt" <<'EOF'
      To secure GRUB:
      1) Run: grub-mkpasswd-pbkdf2
      2) Copy the generated hash (pbkdf2).
      3) Add to /etc/grub.d/40_custom:
        set superusers="root"
        password_pbkdf2 root <hash>
      4) Then run:
        update-grub
      5) Reboot to verify.
      (Do this interactively; not automated in script to avoid lockouts.)
      EOF

      ### 14) Find and report SUID/SGID binaries and optionally remove risky ones ###
      log "Listing SUID/SGID binaries (manual review recommended)"
      find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print > "${BACKUP_DIR}/suid_sgid_files.txt" || true
      log "SUID/SGID list saved to ${BACKUP_DIR}/suid_sgid_files.txt"

      ### 15) Enable rsyslog & central logging (basic) ###
      log "Configuring rsyslog for reliable logging"
      systemctl enable --now rsyslog

      ### 16) Kernel & package auto-updates (optional) ###
      log "Setting unattended upgrade for kernel packages (if desired)"
      # This was partially handled earlier via unattended-upgrades config.

      ### 17) File permissions & world-writable files check ###
      log "Hardening file permissions: identifying world-writable files (except /tmp)"
      find / -xdev -type f -perm -0002 -not -path "/tmp/*" -not -path "/var/tmp/*" > "${BACKUP_DIR}/world_writable_files.txt" || true
      log "World-writable files saved to ${BACKUP_DIR}/world_writable_files.txt"

      ### 18) SSH known_hosts and authorized_keys fallback notice ###
      log "Ensure at least one working SSH authorized_key is present for $ADMIN_USER before you invalidate password auth."

      ### 19) Enable FIPS / disk encryption (notes) ###
      cat > "${BACKUP_DIR}/NOTES_FIPS_DISK_ENCRYPTION.txt" <<'EOF'
      - For FIPS: Ubuntu requires enabling FIPS modules and possibly using an OS image built with FIPS. This script does not enable FIPS automatically.
      - For full disk LUKS encryption: provision during instance creation or re-partition and migrate; not safe to apply via script.
      EOF

      ### 20) Final housekeeping & restart services as needed ###
      log "Reloading services to apply changes"
      systemctl daemon-reload || true
      systemctl restart sshd || true
      systemctl restart rsyslog || true
      systemctl restart fail2ban || true
      systemctl restart ufw || true

      log "Hardening finished. Backups and lists stored in: ${BACKUP_DIR}"
      log "Please review ${BACKUP_DIR} for backups and artifacts"

      cat <<EOF

      HARDENING COMPLETE (partial). IMPORTANT next steps (manual):
      1) Verify SSH access in a separate terminal BEFORE closing your session.
      2) Manually create a GRUB password as instructed in ${BACKUP_DIR}/GRUB_INSTRUCTIONS.txt
      3) Review ${BACKUP_DIR}/suid_sgid_files.txt and ${BACKUP_DIR}/world_writable_files.txt for risky binaries/files.
      4) Test application functionality (web apps, databases) — mount options and noexec may break some apps.
      5) Configure central logging (rsyslog -> remote log host or cloud logging) and log retention.
      6) Configure backup & restore for /etc and VM images.
      7) Consider adding: CIS benchmark checks, AIDE/Tripwire, OS-level runtime protection (e.g., Falco) and intrusion detection.
      8) Optional: integrate with your configuration management (Ansible/Chef) & IaC pipelines.

      Log saved: ${LOGFILE}
      Backups: ${BACKUP_DIR}

      EOF

      // "sudo sh /tmp/scripts/nginx.sh",
      // "sudo rm -rf /tmp/scripts",
      // "sudo apt-get update && sudo apt-get install software-properties-common -y",
      // "sudo apt-add-repository -y --update ppa:ansible/ansible",
      // "sudo apt-get update",
      // "sudo apt-get install ansible -y"
    ]
  }

  // provisioner "ansible-local" {
  //   playbook_file = "ansible/playbook.yaml"
  //   role_paths = [
  //     "ansible/roles/CIS-Ubuntu-20.04-Ansible"
  //   ]
  // }

  // provisioner "shell" {
  //   inline = [
  //     "sudo apt remove ansible -y"
  //   ]
  // }
}

