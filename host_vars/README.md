## Host Variables Directory

This directory contains Ansible host variables organized by individual host. Host variables are applied to specific hosts and take precedence over group variables in Ansible's variable precedence hierarchy.

For more information read [docs/inventory.md](docs/inventory.md)

# Specific configurations for Docker Hosts

## Overview

Below is an example configuration for hosts that will run Docker rootless. These hosts require specific hardening adjustments to be compatible with Docker's requirements.

## Example Configuration

Create or update your host_vars file (e.g., `host_vars/your-docker-host/vars.yml`):

```yaml
---
# Host-specific configuration for Docker hosts
# Based on configuration for submariner-remote-node-testing

# === USER MANAGEMENT ===
MANAGE_USERS: true
SSH_USERLIST:
  - username: admin
    admin: true
    public_key: ssh-ed25519 AAAA... your-key-here
    initialpassword: <generate-secure-password>
  - username: developer
    admin: false
    public_key: ssh-ed25519 AAAA... dev-key-here
    non_admin_allowed_commands: "/usr/bin/docker, /usr/bin/docker-compose"
    initialpassword: <generate-secure-password>

# === SESSION MANAGEMENT ===
LOGIND_HARDENING:
  killuserprocesses: true
  killexcludeusers: ["root", "dockeruser"]  # Don't kill Docker user processes
  idleaction: "lock"
  idleactionsec: "60min"
  removeipc: true

# === SSH CONFIGURATION ===
MANAGE_SSH: true
SSHD_ADMIN_NET: 
  - "0.0.0.0/0"  # Adjust to your management network
SSHD_MAX_AUTH_TRIES: 10
SSHD_LOGIN_GRACE_TIME: 60
SSHD_TIMEOUT_SECS: 3600

# === FIREWALL CONFIGURATION ===
MANAGE_UFW: true
UFW_OUTGOING_TRAFFIC:
  - { "port": 22, "proto": "tcp" }    # SSH
  - 53                                # DNS
  - { "port": 80, "proto": "tcp" }    # HTTP - if needed
  - { "port": 443, "proto": "tcp" }   # HTTPS - if needed
  - { "port": 123, "proto": "udp" }   # NTP
  # Add container registry ports if needed
  - { "port": 5000, "proto": "tcp" }  # Docker registry port example

# === SYSTEM UPDATES ===
AUTO_UPDATES_OPTIONS:
  enabled: true
  only_security: true
  reboot: true
  reboot_from_time: "02:00"
  reboot_time_margin_mins: 20
  custom_origins: '' # here you may add what you need

# === SECURITY HARDENING ===
DISABLE_WIRELESS: true
DISABLE_ROOT_ACCOUNT: true

# === DOCKER CONFIGURATION ====================================
DOCKER_USER: "dockeruser"
DOCKER_COMPOSE: true
DOCKER_ALLOW_PRIVILEGED_PORTS: false
DOCKER_ROOTFUL_ENABLED: false
DOCKER_ROOTFUL: false
DOCKER_ROOTFUL_OPTS: false
DOCKER_UNATTENDED_UPGRADES: true
DOCKER_USER_BASHRC: true

# === PACKAGE MANAGEMENT ===
MANDATORY_PACKAGES: 
  - nano # this is your choice
  - ufw
  - git # this is your choice
  - curl # this is your choice
  - jq  # Useful for Docker API queries

# === AUDIT AND LOGGING ===
AUDITD_ACTION_MAIL_ACCT: your-email@example.com

```

## Deployment Steps

### 1. Create Host Vars File

```bash
mkdir -p host_vars/your-docker-host
cp host_vars/README-DOCKER-HOSTS.md host_vars/your-docker-host/vars.yml
# Edit the file with your specific configuration
```

### 2. Add to Inventory

```ini
# inventories/production/inventory
[docker-hosts]
your-docker-host ansible_host=192.168.1.100
```

### 3. Run Hardening Playbook

```bash
ansible-playbook -i inventories/production/inventory setup-playbook.yml \
  --limit your-docker-host
```

### 4. Run Docker Installation
Before that you will need to change you bash `$ANSIBLE_USER` to your actual user (instead of the bootstrap one), if needed.
```bash
ansible-playbook -i inventories/production/inventory install-docker-rootless.yml \
  --limit your-docker-host
```

### 5. Verify Installation

```bash
# SSH to the host
ssh admin@your-docker-host

# Switch to Docker user
sudo -u dockeruser -i

# Test Docker
docker run hello-world
docker run -d --name nginx -p 8080:80 nginx
curl http://localhost:8080
```

## Security Considerations

### Recommended Additional Security / TODOs

1. **Network Segmentation**: Place Docker hosts in isolated network
2. **Container Image Scanning**: Use tools like Trivy or Clair
3. **Registry Security**: Use private registry with authentication
4. **Runtime Security**: Consider Falco or similar tools
5. **Centralized Logging**: Forward Docker logs to secure log server

## Troubleshooting

### Docker Service Won't Start

```bash
# Check AppArmor
sudo aa-status | grep slirp4netns
sudo journalctl | grep -i apparmor | grep slirp4netns

# Check procfs
mount | grep proc

# Check Docker logs
sudo -u dockeruser journalctl --user -u docker -n 50
```

### Containers Can't Access Network

```bash
# Test slirp4netns
sudo -u dockeruser /usr/bin/slirp4netns --help

# Check firewall
sudo ufw status verbose

# Check Docker network
sudo -u dockeruser docker network ls
sudo -u dockeruser docker network inspect bridge
```

### Permission Errors

```bash
# Check Docker user groups
groups dockeruser

# Should include: dockeruser procfs-access

# Check file permissions
ls -la /home/dockeruser/bin/
ls -la /home/dockeruser/.config/systemd/user/
```

## Advanced: Kubernetes with Docker

If running Kubernetes (like microk8s) on the same host, you'll need additional firewall rules:

```yaml
POST_RUN_EXTRA_COMMANDS: |
  # Kubernetes networking
  ufw allow in on cni0
  ufw allow in on flannel.1
  ufw allow in on cali+
  ufw allow in on vxlan.calico
  
  # Kubernetes API
  ufw allow 6443/tcp
  ufw allow 16443/tcp
  
  # Kubernetes pod networking
  ufw route allow in on cali+ out on vxlan.calico
  ufw route allow in on vxlan.calico out on cali+
```

## References

- [Docker Rootless Mode Documentation](https://docs.docker.com/engine/security/rootless/)
- [konstruktoid.hardening Role](https://github.com/konstruktoid/ansible-role-hardening)
- [konstruktoid.docker_rootless Role](https://github.com/konstruktoid/ansible-role-docker-rootless)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [AppArmor Documentation](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)

