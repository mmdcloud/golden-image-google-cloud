packer {
  required_plugins {
    googlecompute = {
      source  = "github.com/hashicorp/googlecompute"
      version = "~> 1"
    }
  }
}

source "googlecompute" "nginx" {
  project_id              = "orbital-bee-455915-h5"
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
      "sudo apt-get update",
      "sudo apt-get install -y nginx",
      "curl -sL https://deb.nodesource.com/setup_20.x -o nodesource_setup.sh",
      "sudo bash nodesource_setup.sh",
      "sudo apt install nodejs -y"
      // "sudo sh /tmp/scripts/nginx.sh",
      // "sudo rm -rf /tmp/scripts",
      // "sudo apt-get update && sudo apt-get install software-properties-common -y",
      // "sudo apt-add-repository -y --update ppa:ansible/ansible",
      // "sudo apt-get update",
      // "sudo apt-get install ansible -y"

      # Exit on error
      set -e
      
      # Update and upgrade system packages
      sudo apt-get update
      sudo apt-get -y upgrade
      
      # Install essential security packages
      sudo apt-get install -y fail2ban ufw unattended-upgrades apt-listchanges
      
      # Harden SSH configuration
      sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
      
      sudo bash -c 'cat > /etc/ssh/sshd_config' <<EOL
      Port 22
      Protocol 2
      HostKey /etc/ssh/ssh_host_ed25519_key
      HostKey /etc/ssh/ssh_host_rsa_key
      Ciphers aes256-ctr,aes192-ctr,aes128-ctr
      MACs hmac-sha2-512,hmac-sha2-256
      KexAlgorithms curve25519-sha256@libssh.org
      SyslogFacility AUTH
      LogLevel VERBOSE
      PermitRootLogin no
      StrictModes yes
      PubkeyAuthentication yes
      PasswordAuthentication no
      ChallengeResponseAuthentication no
      UsePAM yes
      AllowTcpForwarding no
      X11Forwarding no
      PrintMotd no
      ClientAliveInterval 300
      ClientAliveCountMax 2
      MaxAuthTries 3
      EOL
      
      sudo systemctl reload sshd
      
      # Set up a new admin user
      read -p "Enter new admin username: " adminuser
      sudo adduser $adminuser
      sudo usermod -aG sudo $adminuser
      
      # Lock root account
      sudo passwd -l root
      
      # Configure Unattended Upgrades
      sudo dpkg-reconfigure --priority=low unattended-upgrades
      
      # Enable UFW firewall
      sudo ufw default deny incoming
      sudo ufw default allow outgoing
      sudo ufw allow 22/tcp
      sudo ufw enable
      
      # Enable and start fail2ban
      sudo systemctl enable fail2ban
      sudo systemctl start fail2ban
      
      # Set file permissions for /home directories
      sudo chmod 750 /home/*
      
      # Disable core dumps
      echo '* hard core 0' | sudo tee -a /etc/security/limits.conf
      echo 'fs.suid_dumpable = 0' | sudo tee -a /etc/sysctl.conf
      sudo sysctl -p
      
      # Remove unnecessary packages
      sudo apt-get autoremove --purge -y
      
      echo "Basic hardening complete. Review and customize further as needed."

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

