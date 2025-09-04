# Ansible Role: users_add

An Ansible role for automated user account management with SSH key configuration and flexible sudo permissions.

## Integration with Security Hardening

This role is designed to work seamlessly with security hardening roles like [konstruktoid.hardening](https://github.com/konstruktoid/ansible-role-hardening). The recommended workflow is:

1. **First**: Use `users_add` to create user accounts with SSH keys and sudo permissions
2. **Second**: Apply `konstruktoid.hardening` to implement CIS-based security hardening

```yaml
# Recommended integration pattern
- name: Create user accounts
  include_role:
    name: users_add
  vars:
    users_add_userlist: "{{ SSH_USERLIST }}"

- name: Apply security hardening
  include_role:
    name: konstruktoid.hardening
  vars:
    manage_users: true  # Enables SSH security policies for created users
    sshd_allow_users: "{{ SSH_USERLIST | map(attribute='username') | list }}"
```

This separation follows the single responsibility principle: `users_add` handles user lifecycle management while hardening roles handle security policies.

## Description

This role creates and manages user accounts on Linux systems with the following features:
- Individual user groups for better security isolation
- SSH public key authentication setup
- Flexible sudo permissions (full admin or limited commands)
- Forced password change on first login
- Secure password handling with hash encryption

## Requirements

- **Ansible Version**: 2.9 or higher
- **Target Systems**: Ubuntu 20.04+, Debian 10+
- **Collections**: 
  - `ansible.builtin` (included with Ansible)
  - `ansible.posix` (install via `ansible-galaxy collection install ansible.posix`)
- **Privileges**: Role must be run with `become: true` (sudo/root access)

## Role Variables

### Required Variables

#### `users_add_userlist`
List of user objects to create. Each user object requires specific attributes.

**Type**: List of dictionaries
**Required**: Yes

**User Object Structure**:
```yaml
users_add_userlist:
  - username: "john_doe"              # Required: Username for the account
    public_key: "ssh-rsa AAAAB3N..."  # Required: SSH public key string
    admin: true                       # Required: Boolean, true for full sudo access
    initialpassword: "temp_pass123"   # Optional: User-specific initial password
    non_admin_allowed_commands: "NOPASSWD: /usr/bin/apt update, /usr/bin/apt upgrade"  # Optional: Limited sudo commands for non-admin users
```

#### `GENERALINITIALPASSWORD`
Default initial password for users when `initialpassword` is not specified per user.

**Type**: String
**Required**: Yes
**Security Note**: Use Ansible Vault to encrypt this variable

### Variable Details

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `users_add_userlist` | List | Yes | `[]` | List of user objects to create |
| `GENERALINITIALPASSWORD` | String | Yes | None | Default password for new users |

### User Object Attributes

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `username` | String | Yes | System username (alphanumeric, underscores, hyphens) |
| `public_key` | String | Yes | Complete SSH public key string |
| `admin` | Boolean | Yes | `true` for full sudo access, `false` for limited access |
| `initialpassword` | String | No | User-specific initial password (overrides `GENERALINITIALPASSWORD`) |
| `non_admin_allowed_commands` | String | No | Sudo commands allowed for non-admin users |

## Dependencies

- **Ansible Collections**:
  - `ansible.posix` (for `authorized_key` module)

Install with:
```bash
ansible-galaxy collection install ansible.posix
```

## Example Playbook Usage

### Basic Usage
```yaml
---
- name: Manage user accounts
  hosts: servers
  become: true
  vars:
    GENERALINITIALPASSWORD: "ChangeMe123!"  # Use Ansible Vault in production
    users_add_userlist:
      - username: "alice"
        public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... alice@laptop"
        admin: true
      - username: "bob"
        public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... bob@desktop"
        admin: false
        non_admin_allowed_commands: "NOPASSWD: /usr/bin/apt update, /usr/bin/apt upgrade"
  
  roles:
    - users_add
```

### Advanced Usage with Vault
```yaml
---
- name: Secure user management
  hosts: production
  become: true
  vars_files:
    - vault.yml  # Contains encrypted GENERALINITIALPASSWORD
  vars:
    users_add_userlist:
      - username: "devops_user"
        public_key: "{{ vault_devops_ssh_key }}"
        admin: true
        initialpassword: "{{ vault_devops_initial_password }}"
      - username: "monitor_user"
        public_key: "{{ vault_monitor_ssh_key }}"
        admin: false
        non_admin_allowed_commands: "NOPASSWD: /bin/systemctl status *, /usr/bin/journalctl"
  
  tasks:
    - name: Create user accounts
      include_role:
        name: users_add
      when: manage_users | default(true)
```

### Integration with Group Variables
```yaml
# group_vars/production/users.yml
users_add_userlist:
  - username: "admin1"
    public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..."
    admin: true
  - username: "developer1"
    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
    admin: false
    non_admin_allowed_commands: "NOPASSWD: /usr/bin/git, /usr/bin/docker"

# group_vars/production/vault.yml (encrypted)
GENERALINITIALPASSWORD: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  66386...
```

## Security Features

### Password Policy
- Initial passwords are SHA-512 hashed
- Users must change password on first login
- Passwords are only set during account creation (`update_password: on_create`)

### SSH Configuration
- SSH public keys are properly formatted and validated
- Each key includes a descriptive comment
- Supports multiple key types (RSA, ED25519, ECDSA)

### Sudo Configuration
- **Admin users**: Full sudo access (`ALL=(ALL) ALL`)
- **Non-admin users**: Limited commands as specified
- Individual sudoers files in `/etc/sudoers.d/` for easy management
- All sudoers modifications are validated with `visudo`

## Role Behavior

### What the Role Does

1. **Group Creation**: Creates a primary group matching the username
2. **User Account**: Creates user with specified username and settings
3. **SSH Keys**: Installs public keys in `~/.ssh/authorized_keys`
4. **Sudo Setup**: Configures appropriate sudo permissions
5. **Password Policy**: Sets initial password and forces change on first login

### Idempotency

This role is fully idempotent:
- Users are only created if they don't exist
- SSH keys are added only if not present
- Sudo files are created/updated only when needed
- Password changes only trigger on first login

### File Modifications

The role modifies these system files:
- `/etc/passwd` - User account creation
- `/etc/group` - Group creation
- `/etc/shadow` - Password hash storage
- `/home/[username]/.ssh/authorized_keys` - SSH public keys
- `/etc/sudoers.d/[username]` - Individual sudo permissions
- `/etc/sudoers` - Ensures includedir directive

## Testing

### Prerequisites for Testing
```bash
# Install testing dependencies
pip install ansible molecule[docker]
ansible-galaxy collection install ansible.posix
```

### Manual Testing with Vagrant
```yaml
# test-playbook.yml
---
- name: Test users_add role
  hosts: all
  become: true
  vars:
    GENERALINITIALPASSWORD: "TestPassword123!"
    users_add_userlist:
      - username: "testuser"
        public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDG... test@example.com"
        admin: false
        non_admin_allowed_commands: "NOPASSWD: /usr/bin/whoami"
  
  roles:
    - users_add
  
  post_tasks:
    - name: Verify user creation
      ansible.builtin.user:
        name: testuser
        state: present
      check_mode: true
      register: user_check
    
    - name: Verify SSH key installation
      ansible.builtin.stat:
        path: /home/testuser/.ssh/authorized_keys
      register: ssh_key_check
    
    - name: Display test results
      ansible.builtin.debug:
        msg: 
          - "User exists: {{ not user_check.changed }}"
          - "SSH keys installed: {{ ssh_key_check.stat.exists }}"
```

### Validation Commands
```bash
# After running the role, verify:
# 1. User account exists
getent passwd username

# 2. User group exists  
getent group username

# 3. SSH key is installed
sudo cat /home/username/.ssh/authorized_keys

# 4. Sudo permissions are correct
sudo cat /etc/sudoers.d/username

# 5. Password aging is set
sudo chage -l username
```

## Common Issues and Troubleshooting

### Issue: SSH Key Authentication Fails
**Cause**: Malformed public key or incorrect permissions
**Solution**: 
- Verify public key format (should start with key type like `ssh-rsa`)
- Check file permissions: `~/.ssh/` (700), `authorized_keys` (600)

### Issue: User Cannot Use Sudo
**Cause**: Sudoers file syntax error or missing includedir
**Solution**:
- Check `/var/log/auth.log` for sudo errors
- Verify `/etc/sudoers` includes `#includedir /etc/sudoers.d`
- Validate sudoers syntax: `sudo visudo -f /etc/sudoers.d/username`

### Issue: Password Change Not Enforced
**Cause**: Password aging not properly set
**Solution**:
- Check with `sudo chage -l username`
- Manually set if needed: `sudo chage -d 0 username`

## Author Information

This role was customized from older playbooks for the linux-server-management project.
