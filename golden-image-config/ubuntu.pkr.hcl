source "googlecompute" "nginx" {
  project_id              = var.project_id
  source_image            = "ubuntu-2004-focal-v20220204"
  image_name              = "packer-putrisinu-nginx-{{timestamp}}"
  image_family            = "packer-putrisinu-nginx"  
  image_storage_locations = ["us-east1"]
  image_labels = {
    "os" : "ubuntu"
    "application" : "nginx"
  }
  ssh_username       = "packer-sa"
  instance_name      = "packer-nginx-image-build"
  zone               = "us-east1-b"
  network            = "projects/golden-images-svpc/global/networks/golden-images-svpc"
  subnetwork         = "projects/golden-images-svpc/regions/us-east1/subnetworks/subnet-us-east1"
  network_project_id = "golden-images-svpc"
  use_internal_ip    = true
  omit_external_ip   = true
  use_iap            = true
  use_os_login       = true
  metadata = {
    block-project-ssh-keys = "true"
  }
  tags = ["nginx", "packer"]
}

build {
  sources = [
    "source.googlecompute.nginx"
  ]

  provisioner "file" {
    source      = "scripts"
    destination = "/tmp/"
  }

  provisioner "shell" {
    inline = [
      "sudo sh /tmp/scripts/nginx.sh",
      "sudo rm -rf /tmp/scripts",
      "sudo apt-get update && sudo apt-get install software-properties-common -y",
      "sudo apt-add-repository -y --update ppa:ansible/ansible",
      "sudo apt-get update",
      "sudo apt-get install ansible -y"
    ]
  }

  provisioner "ansible-local" {
    playbook_file = "ansible/playbook.yaml"
    role_paths = [
      "ansible/roles/CIS-Ubuntu-20.04-Ansible"
    ]
  }

  provisioner "shell" {
    inline = [
      "sudo apt remove ansible -y"
    ]
  }
}

