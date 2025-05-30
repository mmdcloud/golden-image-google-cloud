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

