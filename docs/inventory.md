# Inventory Management Guide

This guide covers the organization and management of Ansible inventories for the linux-server-management project, including host organization, variable management, and environment separation.

## Table of Contents

- [Current Structure](#current-structure)
- [Inventory Organization](#inventory-organization)
- [Group Variables](#group-variables)
- [Host Variables](#host-variables)
- [Environment Management](#environment-management)
- [Best Practices](#best-practices)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## Current Structure

The project uses environment-based inventory organization with the following structure:

```
├── inventories/
│   ├── production/             # Production environment
│   │   └── inventory
│   ├── staging/               # Staging environment
│   │   └── inventory  
│   └── development/           # Development environment
│       └── inventory
├── group_vars/
│   ├── all.yml                # Global variables
│   ├── dev/                   # Development environment
│   │   └── vars.yml
│   ├── bastion-servers/       # Bastion server group
│   └── web-servers/           # Web server group
└── host_vars/                 # Host-specific variables
```

## Inventory Organization

### Basic Inventory Format

The project uses INI-style inventory format:

```ini
# inventories/environment/inventory
[group_name]
hostname1                    ansible_host=IP_ADDRESS
hostname2                    ansible_host=IP_ADDRESS

[group_name:vars]
group_variable=value

[parent_group:children]
child_group1
child_group2
```

### Environment-Based Organization

Each environment has its own inventory directory:

#### Production Environment (`production/`)
```ini
[web_servers]
web-prod-01                  ansible_host=IP_ADDRESS1
web-prod-02                  ansible_host=IP_ADDRESS2

[database_servers]
db-prod-01                   ansible_host=IP_ADDRESS3

[production:children]
web_servers
database_servers

[production:vars]
# Environment-specific variables
environment=production
```

#### Development Environment
Development configurations are managed through `group_vars/dev/` with appropriate inventory files.

### Host Naming Conventions

- **Descriptive names**: Use meaningful hostnames that indicate purpose
- **Consistent format**: Follow pattern `service-type-identifier`
- **Environment indicators**: Include environment in hostname when appropriate

Examples:
- `web-prod-01` - Production web server instance 01
- `bastion-server-prod` - Production bastion server
- `db-staging-01` - Staging database server instance 01

## Group Variables

Group variables are organized by environment and function in the `group_vars/` directory.

### Global Variables (`group_vars/all.yml`)

Contains variables that apply to all environments:

```yaml
---
# Default values for variables that will apply to all deployments

# Common settings
ansible_user: "{{ ansible_ssh_user | default('ubuntu') }}"
ansible_ssh_common_args: '-o StrictHostKeyChecking=yes'

# Default port settings
ssh_port: 22
```

### Environment-Specific Variables

Each environment directory contains configuration specific to that environment:

#### Development Environment (`group_vars/dev/vars.yml`)

```yaml
---
# Development environment configuration
GENERALINITIALPASSWORD: This1sMyF1rstPass  # Use Ansible Vault in production

SSH_USERLIST:
  - username: admin_user
    admin: true
    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
  
  - username: seppo
    admin: false
    non_admin_allowed_commands: "/usr/bin/apt update, /usr/bin/apt upgrade"
    public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAC..."

# Environment-specific settings
AUTO_UPDATES_OPTIONS: true
MANAGE_UFW: true
DISABLE_WIRELESS: false
```

### Functional Group Variables

Variables for specific server functions:

#### Bastion Servers (`group_vars/bastion-servers/`)
```yaml
---
# Bastion server specific configuration
SSHD_ALLOW_TCP_FORWARDING: true
SSHD_MAX_AUTH_TRIES: 3
SSHD_LOGIN_GRACE_TIME: 30

# Enhanced logging for bastion servers
AUDITD_ACTION_MAIL_ACCT: "admin@example.com"
```

#### Web Servers (`group_vars/web-servers/`)
```yaml
---
# Web servers configuration
MANAGE_SSH: true
MANAGE_UFW: true
SESSION_TIMEOUT: 900

# Web-specific settings
nginx_worker_processes: auto
ssl_protocols: "TLSv1.2 TLSv1.3"
```

## Host Variables

Host-specific variables are stored in the `host_vars/` directory, named after the hostname.

### Example: `host_vars/web-prod-01.yml`
```yaml
---
# Host-specific configuration for web-prod-01

# Network configuration
internal_ip: IP_ADDRESS1

# Service-specific settings
nginx_worker_connections: 1024
max_upload_size: "10M"

# Host-specific users (if different from group)
SSH_USERLIST:
  - username: webuser
    admin: false
    non_admin_allowed_commands: "/bin/systemctl restart nginx, /bin/systemctl reload nginx"
```

## Environment Management

### Creating a New Environment

1. **Create inventory directory**:
   ```bash
   mkdir -p inventories/new-environment
   ```

2. **Create inventory file**:
   ```ini
   # inventories/new-environment/inventory
   [web_servers]
   web-01                       ansible_host=192.168.1.10
   web-02                       ansible_host=192.168.1.11
   
   [database_servers]
   db-01                        ansible_host=192.168.1.20
   
   [new_environment:children]
   web_servers
   database_servers
   ```

3. **Create environment variables**:
   ```bash
   mkdir -p group_vars/new-environment
   ```

4. **Configure environment variables**:
   ```yaml
   # group_vars/new-environment/vars.yml
   ---
   # Environment-specific configuration
   environment: new-environment
   
   SSH_USERLIST:
     - username: env_admin
       admin: true
       public_key: "ssh-ed25519 AAAAC3..."
   
   # Environment settings
   AUTO_UPDATES_OPTIONS: true
   MANAGE_UFW: true
   ```

### Environment Separation Strategies

#### Variable Precedence
Ansible variable precedence (highest to lowest):
1. Extra vars (`-e` command line)
2. Task vars
3. Block vars
4. Role and include vars
5. Set_facts
6. Registered vars
7. **Host vars** (`host_vars/`)
8. **Group vars** (`group_vars/`)
9. Default vars

#### Secure Variable Management
```yaml
# group_vars/production/vault.yml (encrypted)
---
$ANSIBLE_VAULT;1.1;AES256
66386439653634336465663...

# group_vars/production/vars.yml (plain)
---
GENERALINITIALPASSWORD: "{{ vault_initial_password }}"
database_password: "{{ vault_db_password }}"
```

## Best Practices

### 1. Inventory Organization
- **One inventory per environment**: Separate production, staging, development
- **Logical grouping**: Group hosts by function (web, database, monitoring)
- **Descriptive names**: Use clear, consistent naming conventions
- **Documentation**: Comment complex inventory structures

### 2. Variable Management
- **Use Ansible Vault**: Encrypt sensitive variables
- **Environment separation**: Keep environment-specific variables separate
- **Avoid hardcoding**: Use variables for all configurable values
- **Default values**: Provide sensible defaults in group_vars/all.yml

### 3. Security Practices
- **SSH key management**: Store public keys in variables, never private keys
- **Least privilege**: Grant minimal necessary permissions
- **Vault encryption**: Encrypt passwords, API keys, certificates
- **Regular rotation**: Rotate passwords and keys regularly

### 4. Maintainability
- **Version control**: Track all inventory changes in git
- **Testing**: Test inventory changes in non-production first
- **Documentation**: Document custom variables and their purposes
- **Validation**: Use ansible-inventory to validate syntax

## Examples

### Complete Environment Setup

#### 1. Inventory File (`inventories/staging/inventory`)
```ini
[web_servers]
web-staging-01               ansible_host=192.168.10.10
web-staging-02               ansible_host=192.168.10.11

[database_servers]
db-staging-01                ansible_host=192.168.10.20

[bastion_servers]
bastion-staging              ansible_host=203.0.113.10

[staging:children]
web_servers
database_servers
bastion_servers

[staging:vars]
environment=staging
```

#### 2. Environment Variables (`group_vars/staging/vars.yml`)
```yaml
---
# Staging environment configuration
GENERALINITIALPASSWORD: "{{ vault_staging_initial_password }}"

SSH_USERLIST:
  - username: staging_admin
    admin: true
    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
  
  - username: developer
    admin: false
    non_admin_allowed_commands: "NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/systemctl status *"
    public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAC..."

# Staging-specific settings
AUTO_UPDATES_OPTIONS: false  # Manual updates in staging
MANAGE_UFW: true
DISABLE_WIRELESS: true
REBOOT_UBUNTU: false  # Prevent automatic reboots
```

#### 3. Vault File (`group_vars/staging/vault.yml`)
```bash
# Create encrypted vault
ansible-vault create group_vars/staging/vault.yml

# Content (when decrypted):
---
vault_staging_initial_password: "StagingPass123!"
vault_db_admin_password: "DbAdminStaging456!"
```

### Running Playbooks with Inventory

```bash
# Run against specific environment
ansible-playbook -i inventories/staging/inventory \
                 -l web_servers \
                 setup-playbook.yml \
                 --ask-vault-pass

# Run against specific host
ansible-playbook -i inventories/production/inventory \
                 -l web-prod-01 \
                 setup-playbook.yml \
                 -u admin_user \
                 -K

# Test connectivity
ansible all -i inventories/staging/inventory -m ping
```

## Troubleshooting

### Common Issues

#### 1. Host Not Found
**Error**: `Could not match supplied host pattern`
**Solutions**:
- Verify hostname in inventory file
- Check group membership
- Use `ansible-inventory --list` to debug

#### 2. Variable Not Defined
**Error**: `'variable_name' is undefined`
**Solutions**:
- Check variable precedence
- Verify file paths and naming
- Use `ansible-inventory --host hostname` to check variables

#### 3. SSH Connection Issues
**Error**: `SSH connection failed`
**Solutions**:
- Verify `ansible_host` IP address
- Check SSH key permissions
- Test manual SSH connection
- Verify user has SSH access

### Debugging Commands

```bash
# List all hosts and groups
ansible-inventory -i inventories/environment/inventory --list

# Show variables for specific host
ansible-inventory -i inventories/environment/inventory --host hostname

# Test connectivity
ansible all -i inventories/environment/inventory -m ping

# Run with verbose output
ansible-playbook -vvv -i inventories/environment/inventory playbook.yml

# Syntax check
ansible-playbook --syntax-check -i inventories/environment/inventory playbook.yml
```

### Variable Debugging

```yaml
# Add to playbook for debugging
- name: Display all variables for debugging
  debug:
    var: hostvars[inventory_hostname]
  tags: debug

- name: Display specific variable
  debug:
    msg: "SSH_USERLIST contains {{ SSH_USERLIST | length }} users"
  tags: debug
```

## Advanced Topics

### Dynamic Inventories

For cloud environments, consider dynamic inventories:

```bash
# AWS EC2 dynamic inventory
pip install boto3
ansible-inventory -i aws_ec2.yml --list
```

### Inventory Plugins

Configure inventory plugins in `ansible.cfg`:

```ini
[inventory]
enable_plugins = ini, yaml, script, auto
```

### Ansible Tower/AWX Integration

For enterprise environments, integrate with Ansible Tower/AWX for:
- Centralized inventory management
- Role-based access control
- Automated inventory sync
- Audit trails

## Conclusion

Proper inventory management is crucial for maintaining organized, secure, and scalable Ansible deployments. Follow the practices outlined in this guide to ensure your infrastructure remains manageable as it grows.

For questions or improvements to this documentation, please open an issue in the project repository. 