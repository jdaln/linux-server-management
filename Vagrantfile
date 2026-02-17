Vagrant.configure("2") do |config|
  # CI/local testing can override the playbook used by the Ansible provisioner.
  # Order of precedence:
  # 1) TEST_PLAYBOOK env var (recommended)
  # 2) testing/being_tested.yml (legacy CI/local workflow)
  # 3) testing/test-new-version-hardening.yml (default)
  test_playbook =
    ENV["TEST_PLAYBOOK"] ||
    (File.exist?("testing/being_tested.yml") ? "testing/being_tested.yml" : "testing/test-new-version-hardening.yml")

  # Optional plugins: keep Vagrant usable even if local plugins are not installed.
  # CI should install any required plugins explicitly.
  if Vagrant.has_plugin?("vagrant-vbguest")
    config.vbguest.installer_options = { allow_kernel_upgrade: true }
  end

  config.vm.provider "virtualbox" do |vb|
    vb.customize ["modifyvm", :id, "--uart1", "0x3F8", "4"]
    vb.customize ["modifyvm", :id, "--uartmode1", "disconnected"]
  end

  config.vm.define "bookworm_vlan" do |bookworm_vlan|
    bookworm_vlan.vm.box = "debian/bookworm64"
    bookworm_vlan.ssh.insert_key = true
    bookworm_vlan.vm.hostname = "bookworm-vlan"
    bookworm_vlan.vm.boot_timeout = 600
    if Vagrant.has_plugin?("vagrant-vbguest")
      bookworm_vlan.vbguest.auto_update = false
    end
    bookworm_vlan.vm.provision "shell",
      inline: "ip link set dev eth0 down; ip link set eth0 name eth0.101; ip link set dev eth0.101 up; dhclient -r eth0.101; dhclient eth0.101",
      upload_path: "/var/tmp/vagrant-shell"
    bookworm_vlan.vm.provision "shell",
      inline: "apt-get update && apt-get remove -y dkms && apt-get -y install dkms && DEBIAN_FRONTEND=noninteractive apt-get -y install python3 python3-apt curl",
      upload_path: "/var/tmp/vagrant-shell"
    bookworm_vlan.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = test_playbook
      a.extra_vars = {
        "ansible_become_pass" => "vagrant",
        "ansible_python_interpreter" => "/usr/bin/python3",
        "sshd_admin_net" => ["0.0.0.0/0"],
        "sshd_allow_groups" => ["vagrant", "sudo", "debian", "ubuntu"],
        "system_upgrade" => "false",
        "manage_aide" => "false"
      }
    end
  end

  config.vm.define "bookworm" do |bookworm|
    bookworm.vm.box = "debian/bookworm64"
    if Vagrant.has_plugin?("vagrant-disksize")
      bookworm.disksize.size = '25GB'
    end
    bookworm.ssh.insert_key = true
    bookworm.vm.hostname = "bookworm"
    bookworm.vm.boot_timeout = 600
    if Vagrant.has_plugin?("vagrant-vbguest")
      bookworm.vbguest.auto_update = false
    end
    bookworm.vm.provision "shell",
      inline: "apt-get update && apt-get remove -y dkms && apt-get -y install dkms && DEBIAN_FRONTEND=noninteractive apt-get -y install python3 python3-apt curl",
      upload_path: "/var/tmp/vagrant-shell"
    bookworm.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = test_playbook
      a.extra_vars = {
        "ansible_become_pass" => "vagrant",
        "ansible_python_interpreter" => "/usr/bin/python3",
        "sshd_admin_net" => ["0.0.0.0/0"],
        "sshd_allow_groups" => ["vagrant", "sudo", "debian", "ubuntu"],
        "system_upgrade" => "false",
     }
    end
  end

  config.vm.define "jammy" do |jammy|
    jammy.vm.box = "ubuntu/jammy64"
    jammy.ssh.insert_key = true
    jammy.vm.hostname = "jammy"
    jammy.vm.boot_timeout = 600
    jammy.vm.provision "shell",
      inline: "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install python3 python3-apt curl",
      upload_path: "/var/tmp/vagrant-shell"
    jammy.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = test_playbook
      a.extra_vars = {
        "sshd_admin_net" => ["0.0.0.0/0"],
        "sshd_allow_groups" => ["vagrant", "sudo", "ubuntu"],
        "ansible_python_interpreter" => "/usr/bin/python3",
      }
     end
   end

  config.vm.define "noble" do |noble|
    noble.vm.box = "bento/ubuntu-24.04"
    noble.ssh.insert_key = true
    noble.vm.hostname = "noble"
    noble.vm.boot_timeout = 600
    noble.vm.provision "shell",
      inline: "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install python3 python3-apt curl",
      upload_path: "/var/tmp/vagrant-shell"
    noble.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = test_playbook
      a.extra_vars = {
        "sshd_admin_net" => ["0.0.0.0/0"],
        "sshd_allow_groups" => ["vagrant", "sudo", "ubuntu"],
        "ansible_python_interpreter" => "/usr/bin/python3",
      }
     end
   end

  config.vm.define "debian13" do |debian13|
    debian13.vm.box = "bento/debian-13"
    debian13.ssh.insert_key = true
    debian13.vm.hostname = "debian13"
    debian13.vm.boot_timeout = 600
    if Vagrant.has_plugin?("vagrant-vbguest")
      debian13.vbguest.auto_update = false
    end
    debian13.vm.provision "shell",
      inline: "apt-get update && apt-get remove -y dkms && apt-get -y install dkms && DEBIAN_FRONTEND=noninteractive apt-get -y install python3 python3-apt curl",
      upload_path: "/var/tmp/vagrant-shell"
    debian13.vm.provision "ansible" do |a|
      a.verbose = "v"
      a.limit = "all"
      a.playbook = test_playbook
      a.extra_vars = {
        "ansible_become_pass" => "vagrant",
        "ansible_python_interpreter" => "/usr/bin/python3",
        "sshd_admin_net" => ["0.0.0.0/0"],
        "sshd_allow_groups" => ["vagrant", "sudo", "debian", "ubuntu"],
        "system_upgrade" => "false",
        "manage_aide" => "false"
      }
    end
  end

end
