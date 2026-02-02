# Security Best Practices Guide

This guide covers security best practices in Linux server management with a trait towards Ansible. It is a good start for anyone considering their infra security and contains inspiration for future improvment ideas for this repo and beyond.

## Table of Contents

- [Security Philosophy](#security-philosophy)
- [Ansible Security](#ansible-security)
- [SSH and Authentication](#ssh-and-authentication)
- [User and Access Management](#user-and-access-management)
- [System Hardening](#system-hardening)
- [Network Security](#network-security)
- [Secrets Management](#secrets-management)
- [Monitoring and Auditing](#monitoring-and-auditing)
- [Compliance and Standards](#compliance-and-standards)
- [Incident Response](#incident-response)
- [Security Checklist](#security-checklist)

## Security Philosophy

### Defense in Depth (aka. multi-layer security)
This project implements multiple layers of security controls:
- **Physical Security**: Secure data centers and hardware
- **Network Security**: Firewalls, network segmentation, VPNs
- **Host Security**: System hardening, access controls, monitoring
- **Application Security**: Secure configurations, least privilege
- **Data Security**: Encryption at rest and in transit
- **Operational Security**: Secure procedures, incident response

### Zero Trust Principles
- **Never Trust, Always Verify**: Authenticate and authorize every connection
- **Least Privilege Access**: Grant minimum necessary permissions
- **Assume Breach**: Design systems to limit damage from compromises
- **Continuous Monitoring**: Monitor all activities and maintain visibility

## Ansible Security

### Secure Playbook Development

#### Variable Security
```yaml
# BAD: Hardcoded sensitive values
database_password: "plaintext_password"

# GOOD: Use Ansible Vault
database_password: "{{ vault_database_password }}"

# GOOD: Environment variables for CI/CD
api_key: "{{ lookup('env', 'API_KEY') }}"
```

#### Task Security Best Practices
```yaml
# Use become only when necessary
- name: Install package
  package:
    name: nginx
  become: true  # Only when root is required

# Validate inputs
- name: Create user
  user:
    name: "{{ username }}"
  when: 
    - username is defined
    - username | length > 0
    - username is match('^[a-z][a-z0-9_-]*$')

# Use no_log for sensitive operations
- name: Set password
  user:
    name: "{{ username }}"
    password: "{{ password | password_hash('sha512') }}"
  no_log: true

# Validate file permissions
- name: Create config file
  template:
    src: config.j2
    dest: /etc/app/config
    owner: app
    group: app
    mode: '0600'  # Restrict access
```

#### Connection Security
```yaml
# ansible.cfg - Secure connection settings
[defaults]
host_key_checking = True
ssh_args = -o ControlMaster=auto -o ControlPersist=60s -o StrictHostKeyChecking=yes
timeout = 30

[ssh_connection]
ssh_args = -o StrictHostKeyChecking=yes -o PasswordAuthentication=no
control_path_dir = ~/.ansible/cp
```

### Ansible Vault Usage

#### Creating Encrypted Files
```bash
# Create new encrypted file
ansible-vault create group_vars/production/vault.yml

# Encrypt existing file
ansible-vault encrypt sensitive_vars.yml

# Edit encrypted file
ansible-vault edit group_vars/production/vault.yml

# Decrypt for viewing (avoid this in production)
ansible-vault view group_vars/production/vault.yml
```

#### Vault File Structure
```yaml
# group_vars/production/vault.yml (encrypted)
---
vault_database_password: "SecureDBPassword123!"
vault_api_key: "sk-1234567890abcdef"
vault_ssl_private_key: |
  -----BEGIN PRIVATE KEY-----
  MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...
  -----END PRIVATE KEY-----

# group_vars/production/vars.yml (plain text)
---
database_password: "{{ vault_database_password }}"
api_key: "{{ vault_api_key }}"
ssl_private_key: "{{ vault_ssl_private_key }}"
```

#### Vault Key Management
```bash
# Use password file (secure on control machine)
echo 'MySecureVaultPassword' > ~/.vault_pass
chmod 600 ~/.vault_pass
export ANSIBLE_VAULT_PASSWORD_FILE=~/.vault_pass

# Use key script for integration
cat > vault_key.sh << 'EOF'
#!/bin/bash
# Retrieve vault password from secure key management system
vault kv get -field=password secret/ansible/vault
EOF
chmod +x vault_key.sh
export ANSIBLE_VAULT_PASSWORD_FILE=./vault_key.sh
```

## SSH and Authentication

### SSH Key Management

#### Key Generation Best Practices
```bash
# Generate strong SSH key pair
ssh-keygen -t ed25519 -C "username@hostname-$(date +%Y%m%d)"

# For older systems requiring RSA
ssh-keygen -t rsa -b 4096 -C "username@hostname-$(date +%Y%m%d)"

# Use key passphrases
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_project -C "project_access"
```

#### SSH Client Configuration
```bash
# ~/.ssh/config
Host production-servers
    HostName %h.example.com
    User deploy
    IdentityFile ~/.ssh/id_ed25519_production
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    UserKnownHostsFile ~/.ssh/known_hosts_production

Host bastion-server
    HostName bastion.example.com
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_ed25519_admin
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

#### SSH Server Hardening (Applied by konstruktoid.hardening)
```yaml
# SSH configuration enforced by hardening role
sshd_config_settings:
  Protocol: 2
  PermitRootLogin: no
  PasswordAuthentication: no
  ChallengeResponseAuthentication: no
  UsePAM: yes
  X11Forwarding: no
  PrintMotd: no
  ClientAliveInterval: 600
  ClientAliveCountMax: 0
  MaxAuthTries: 3
  MaxSessions: 2
  LoginGraceTime: 30
  AllowGroups: ssh-users
```

### Multi-Factor Authentication

This playbook implements TOTP-based 2FA using Google Authenticator PAM module.

#### How It Works

1. **First Login**: User authenticates with SSH key, then sees QR code for 2FA enrollment
2. **Enrollment**: User scans QR code with authenticator app (Aegis, Google Authenticator, Authy, Bitwarden, etc..., etc.)
3. **Subsequent Logins**: User provides SSH key + 6-digit TOTP code

#### Configuration

2FA is enabled globally via the `ENABLE_2FA` variable:
```yaml
ENABLE_2FA: true
```

Secrets are stored centrally in `/var/lib/google-authenticator/` (root-owned, mode 0700).

#### Security Features

- **Token reuse prevention**: Each code can only be used once (`-d` flag)
- **Rate limiting**: Max 3 attempts per 30 seconds (`-r 3 -R 30`)
- **Time window**: Accepts 3 codes to handle clock skew (`-w 3`)
- **Emergency codes**: 5 one-time backup codes generated

#### Admin Recovery Process

If a user loses their 2FA device or needs to re-enroll:

```bash
# Remove the user's 2FA secret file
sudo rm /var/lib/google-authenticator/username

# On next SSH login, the user will be prompted to set up 2FA again
```

#### SSH with MFA Configuration
```bash
# /etc/ssh/sshd_config additions
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```

## User and Access Management

### User Account Security

#### Account Creation Best Practices
```yaml
# Secure user creation with users_add role
users_add_userlist:
  - username: "john_doe"
    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... john@secure-laptop"
    admin: false  # Principle of least privilege
    non_admin_allowed_commands: "NOPASSWD: /usr/bin/systemctl status *, /usr/bin/journalctl -f"
    # Specific, limited sudo commands only
```

#### Password Policies
```yaml
# PAM password quality settings (managed by hardening role)
pwquality_settings:
  minlen: 14          # Minimum password length
  minclass: 3         # Minimum character classes
  maxrepeat: 2        # Maximum repeated characters
  maxsequence: 3      # Maximum sequence length
  dcredit: -1         # Require digits
  ucredit: -1         # Require uppercase
  lcredit: -1         # Require lowercase
  ocredit: -1         # Require special characters
```

### Privilege Escalation Controls

#### Sudo Configuration Best Practices
```bash
# Individual sudoers files (/etc/sudoers.d/username)
# Full admin access
john_admin ALL=(ALL) ALL

# Limited access examples where needed
backup_user ALL=(root) NOPASSWD: /usr/bin/rsync, /bin/tar
monitor_user ALL=(root) NOPASSWD: /usr/bin/systemctl status *, /usr/bin/journalctl
web_user ALL=(www-data) NOPASSWD: /usr/bin/systemctl reload nginx

# Restrict dangerous commands where needed
operator_user ALL=(ALL) ALL, !/bin/su, !/usr/bin/sudo, !/bin/bash, !/bin/sh
```

#### Service Account Management for software with dedicated users (not yet implemented)
```yaml
# Service accounts with minimal privileges
- name: Create application service account
  user:
    name: app_service
    system: yes
    shell: /bin/false      # No shell access
    home: /var/lib/app     # Dedicated home directory
    create_home: yes
  become: true

- name: Set application directory permissions
  file:
    path: /var/lib/app
    owner: app_service
    group: app_service
    mode: '0750'           # Limited access
```

## System Hardening

### CIS Benchmark Compliance

The project implements CIS (Center for Internet Security) benchmarks through the konstruktoid.hardening role:

#### Level 1 Controls (Automated)
- Remove unnecessary software packages
- Configure network parameters
- Configure logging and auditing
- Configure access, authentication and authorization
- Configure system maintenance

#### Level 2 Controls (Advanced Security)
- Additional access restrictions
- Advanced auditing configuration
- Enhanced logging
- Network security configurations

#### Custom Hardening Extensions (ideas)
```yaml
# Additional hardening beyond CIS baseline
security_extensions:
  # Kernel security
  kernel_parameters:
    kernel.dmesg_restrict: 1
    kernel.kptr_restrict: 2
    kernel.unprivileged_bpf_disabled: 1
    
  # Network security
  network_parameters:
    net.ipv4.tcp_syncookies: 1
    net.ipv4.conf.all.rp_filter: 1
    net.ipv6.conf.all.disable_ipv6: 1
    
  # File system security
  filesystem_parameters:
    fs.suid_dumpable: 0
    fs.protected_hardlinks: 1
    fs.protected_symlinks: 1
```

### File System Security

#### Mount Options Security
```bash
# Secure mount options (managed by hardening role)
/tmp tmpfs defaults,nodev,nosuid,noexec 0 0
/var/tmp tmpfs defaults,nodev,nosuid,noexec 0 0
/dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0
```

#### File Permissions Audit
```bash
# Find files with dangerous permissions
find / -perm -4000 -type f 2>/dev/null    # SUID files
find / -perm -2000 -type f 2>/dev/null    # SGID files
find / -perm -002 -type f 2>/dev/null     # World-writable files
find / -nouser -o -nogroup 2>/dev/null    # Orphaned files
```

## Network Security

### Firewall Configuration

#### UFW (Uncomplicated Firewall) Setup
```yaml
# Basic UFW configuration via hardening role
ufw_configuration:
  default_incoming: deny
  default_outgoing: allow
  default_routed: deny
  
ufw_rules:
  - rule: allow
    port: '22'
    proto: tcp
    src: '192.168.1.0/24'    # Restrict SSH to specific networks
  
  - rule: allow
    port: '80'
    proto: tcp
  
  - rule: allow
    port: '443'
    proto: tcp
  
  - rule: deny
    port: '23'               # Deny telnet
    proto: tcp
```

#### Advanced Network Security
```bash
# Disable unused network protocols
echo 'install dccp /bin/true' >> /etc/modprobe.d/blacklist-rare-network.conf
echo 'install sctp /bin/true' >> /etc/modprobe.d/blacklist-rare-network.conf
echo 'install rds /bin/true' >> /etc/modprobe.d/blacklist-rare-network.conf

# Network monitoring
netstat -tuln | grep LISTEN     # Check listening ports
ss -tuln                        # Modern alternative to netstat
```

### Network Segmentation

#### VLAN and Network Design
```
Production Network: 10.0.1.0/24
- Web servers: 10.0.1.10-50
- Database servers: 10.0.1.60-80
- Application servers: 10.0.1.90-120

Management Network: 10.0.2.0/24
- Bastion hosts: 10.0.2.10-20
- Monitoring: 10.0.2.30-40
- Backup systems: 10.0.2.50-60

DMZ Network: 10.0.3.0/24
- Load balancers: 10.0.3.10-20
- Reverse proxies: 10.0.3.30-40
```

## Secrets Management

### Sensitive Data Classification

#### Data Classification Levels
1. **Public**: Information that can be shared publicly
2. **Internal**: Information for internal use only
3. **Confidential**: Sensitive business information
4. **Restricted**: Highly sensitive information requiring special handling

#### Secrets Inventory
```yaml
secrets_classification:
  public:
    - Application configurations (non-sensitive)
    - Public SSL certificates
    - Documentation
    
  internal:
    - Internal API endpoints
    - Service discovery configurations
    - Non-production credentials
    
  confidential:
    - Database passwords
    - API keys
    - SSL private keys
    - Production credentials
    
  restricted:
    - Root certificates
    - Master encryption keys
    - Recovery codes
```

### Secrets Rotation

#### Automated Rotation Strategy
```bash
#!/bin/bash
# Example secrets rotation script

rotate_database_password() {
    local new_password=$(openssl rand -base64 32)
    
    # Update password in vault
    ansible-vault edit group_vars/production/vault.yml
    
    # Apply to systems
    ansible-playbook -i production update-db-password.yml \
        --ask-vault-pass \
        -e "new_db_password=${new_password}"
    
    # Verify connectivity
    ansible production -m shell -a "mysql -u app -p${new_password} -e 'SELECT 1'"
}

# Schedule rotation (crontab)
# 0 2 1 * * /opt/scripts/rotate_secrets.sh >> /var/log/rotation.log 2>&1
```

### External Secrets Management

#### Integration with HashiCorp Vault
```yaml
# Vault integration example
- name: Retrieve secret from Vault
  uri:
    url: "{{ vault_url }}/v1/secret/data/myapp"
    method: GET
    headers:
      X-Vault-Token: "{{ vault_token }}"
  register: vault_response

- name: Use secret in task
  template:
    src: config.j2
    dest: /etc/app/config
  vars:
    db_password: "{{ vault_response.json.data.data.password }}"
  no_log: true
```

## Monitoring and Auditing

### System Auditing

#### Auditd Configuration
```bash
# /etc/audit/rules.d/audit.rules
# Monitor authentication
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity

# Monitor privilege escalation
-w /bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation

# Monitor network configuration
-w /etc/sysconfig/network -p wa -k network_config
-w /etc/hosts -p wa -k network_config

# Monitor file access
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /var/log/ -p wa -k log_access
```

#### Log Management
```yaml
# Centralized logging configuration
rsyslog_configuration:
  # Forward logs to central server
  forward_logs: true
  log_server: "log-collector.example.com:514"
  
  # Local log retention
  log_retention_days: 90
  
  # Log rotation
  log_rotation:
    daily: true
    compress: true
    max_age: 30
```

### Security Monitoring

#### File Integrity Monitoring
```bash
# AIDE (Advanced Intrusion Detection Environment)
aide --init                    # Initialize database
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check                   # Check for changes

# Tripwire alternative - simple checksum monitoring
find /etc /bin /sbin /usr/bin /usr/sbin -type f -exec sha256sum {} \; > /var/lib/checksums.db
```

#### Real-time Monitoring
```yaml
# Example monitoring tasks
- name: Check for failed SSH attempts
  shell: grep "Failed password" /var/log/auth.log | tail -10
  register: failed_ssh
  changed_when: false

- name: Alert on suspicious activity
  mail:
    subject: "Security Alert: Failed SSH attempts on {{ inventory_hostname }}"
    body: "{{ failed_ssh.stdout }}"
    to: security@example.com
  when: failed_ssh.stdout_lines | length > 5
```

### Vulnerability Management

#### Automated Security Updates
```yaml
# Unattended upgrades configuration
unattended_upgrades:
  enabled: true
  origins_patterns:
    - "origin=Ubuntu,archive=${distro_codename}-security"
    - "o=Ubuntu,a=${distro_codename}-updates"
  
  package_blacklist:
    - kernel*  # Exclude kernel updates (require manual reboot)
  
  automatic_reboot: false
  email_notifications: "admin@example.com"
```

#### Vulnerability Scanning
```bash
# Local vulnerability assessment
lynis audit system               # Security audit tool
chkrootkit                      # Rootkit detection
rkhunter --check               # Rootkit hunter

# Network vulnerability scanning
nmap -sV --script vuln target_host
```

## Compliance and Standards

### Regulatory Compliance

#### Common Frameworks
- **SOC 2**: Service Organization Control 2
- **ISO 27001**: Information Security Management
- **PCI DSS**: Payment Card Industry Data Security Standard
- **GDPR**: General Data Protection Regulation
- **HIPAA**: Health Insurance Portability and Accountability Act

#### Compliance Mapping
```yaml
controls_mapping:
  access_control:
    frameworks: [SOC2, ISO27001, PCI_DSS]
    implementations:
      - SSH key-based authentication
      - Multi-factor authentication
      - Principle of least privilege
      - Regular access reviews
  
  encryption:
    frameworks: [SOC2, ISO27001, PCI_DSS, GDPR]
    implementations:
      - TLS 1.3 for data in transit
      - AES-256 for data at rest
      - SSH encryption for management
      - Ansible Vault for secrets
  
  logging_monitoring:
    frameworks: [SOC2, ISO27001, PCI_DSS]
    implementations:
      - Centralized log collection
      - Real-time monitoring
      - Audit trail maintenance
      - Security event alerting
```

### Documentation Requirements

#### Security Documentation
1. **Security Policies**: High-level security requirements
2. **Procedures**: Step-by-step security operations
3. **Standards**: Technical security configurations
4. **Guidelines**: Security best practices and recommendations

#### Required Documentation
- Asset inventory and classification
- Risk assessment and treatment
- Incident response procedures
- Business continuity planning
- Security awareness training records
- Vulnerability management reports

## Incident Response

### Incident Response Plan

#### Phase 1: Preparation
- Establish incident response team
- Create communication channels
- Prepare investigation tools
- Document escalation procedures

#### Phase 2: Identification
```bash
# Quick incident detection commands
who                                    # Current users
last                                   # Login history
ps aux | grep -E "(nc|netcat)"       # Check for suspicious processes
netstat -tuln | grep LISTEN          # Check listening ports
find /tmp -name ".*" -type f          # Hidden files in tmp
```

#### Phase 3: Containment
```bash
# Emergency containment actions
# Block suspicious IP
ufw deny from suspicious_ip

# Disable compromised user account
usermod -L compromised_user

# Kill suspicious processes
pkill -f suspicious_process

# Isolate system from network
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
```

#### Phase 4: Eradication and Recovery
```yaml
# Recovery playbook example
- name: Emergency security response
  hosts: compromised_systems
  tasks:
    - name: Reset compromised passwords
      user:
        name: "{{ item }}"
        password: "{{ lookup('password', '/tmp/new_passwords/' + item) | password_hash('sha512') }}"
      loop: "{{ compromised_users }}"
      no_log: true
    
    - name: Update all packages
      package:
        name: "*"
        state: latest
      
    - name: Restart security services
      systemd:
        name: "{{ item }}"
        state: restarted
      loop:
        - ssh
        - ufw
        - auditd
```

### Forensics and Evidence Collection

#### Digital Evidence Collection
```bash
# System information collection
hostname > /tmp/incident_data/hostname.txt
uname -a > /tmp/incident_data/system_info.txt
date > /tmp/incident_data/collection_time.txt

# Network information
netstat -tuln > /tmp/incident_data/network_connections.txt
arp -a > /tmp/incident_data/arp_table.txt
route -n > /tmp/incident_data/routing_table.txt

# Process information
ps aux > /tmp/incident_data/processes.txt
lsof > /tmp/incident_data/open_files.txt

# Log collection
cp /var/log/auth.log /tmp/incident_data/
cp /var/log/syslog /tmp/incident_data/
cp /var/log/audit/audit.log /tmp/incident_data/
```

## Security Checklist

### Pre-Deployment Security Checklist

#### Infrastructure Security
- [ ] Network segmentation implemented
- [ ] Firewall rules configured and tested
- [ ] VPN access configured for remote management
- [ ] Physical security measures in place
- [ ] Backup and recovery procedures tested

#### System Security
- [ ] Operating systems fully patched
- [ ] Unnecessary services disabled
- [ ] Strong authentication mechanisms enabled
- [ ] File system permissions properly configured
- [ ] Audit logging enabled and configured

#### Application Security
- [ ] Secure configuration templates validated
- [ ] Secrets properly encrypted with Ansible Vault
- [ ] Service accounts configured with minimal privileges
- [ ] Security scanning completed
- [ ] Penetration testing performed

### Ongoing Security Maintenance

#### Daily Tasks
- [ ] Review security alerts and logs
- [ ] Monitor failed authentication attempts
- [ ] Check system resource usage
- [ ] Verify backup completion
- [ ] Update threat intelligence feeds

#### Weekly Tasks
- [ ] Review user access and permissions
- [ ] Analyze security metrics and trends
- [ ] Update security tools and signatures
- [ ] Conduct vulnerability scans
- [ ] Review and update documentation

#### Monthly Tasks
- [ ] Conduct security risk assessment
- [ ] Review and test incident response procedures
- [ ] Perform access certification reviews
- [ ] Update security awareness training
- [ ] Conduct tabletop exercises

#### Quarterly Tasks
- [ ] Comprehensive security audit
- [ ] Penetration testing assessment
- [ ] Review and update security policies
- [ ] Business continuity plan testing
- [ ] Third-party security assessments

### Security Metrics and KPIs

#### Security Metrics to Track
```yaml
security_metrics:
  technical:
    - Mean time to patch (MTTP)
    - Number of critical vulnerabilities
    - Failed authentication attempts
    - Security incidents per month
    - System uptime and availability
  
  operational:
    - Security training completion rate
    - Incident response time
    - Access review completion rate
    - Policy compliance percentage
    - Security tool effectiveness
  
  business:
    - Cost of security incidents
    - Customer trust metrics
    - Regulatory compliance status
    - Security ROI measurements
    - Business continuity metrics
```

## Security Configuration Decisions

This section documents where our configuration (this repo's defaults) deviates from standard CIS benchmarks and the operational rationale behind these decisions.

### Relaxed Settings from CIS Defaults

| Setting | CIS/Standard | Our Setting | Rationale | Risk Assessment |
|---------|-------------|-------------|-----------|-----------------|
| SSH Login Grace Time | 30s | 60s | User requires additional time to type complex passwords, reducing authentication failures | **Low Risk**: Minimal exposure increase, improves user experience |
| Session Timeout | 300-600s | 900s (15 min) | User frequently annoyed by re-authentication when switching tasks, reducing productivity | **Low Risk**: Acceptable trade-off for operational efficiency |


### Maintained CIS Compliance

All critical security controls remain at CIS standards:
- ✅ Strong SSH ciphers and MACs
- ✅ No root login permitted  
- ✅ No password authentication (key-based only)
- ✅ No X11/TCP forwarding
- ✅ Proper audit logging
- ✅ UFW firewall with default deny
- ✅ System hardening via konstruktoid.hardening

## Conclusion

Security is an ongoing process requiring continuous attention, monitoring, and improvement. This guide provides a comprehensive foundation for implementing and maintaining security in your linux-server-management infrastructure.

### Key Takeaways

1. **Implement Defense in Depth**: Multiple layers of security controls
2. **Follow Least Privilege**: Grant minimal necessary access
3. **Automate Security**: Use automation for consistent security implementation
4. **Monitor Continuously**: Maintain visibility into system activities
5. **Plan for Incidents**: Prepare for security events before they occur
6. **Stay Current**: Keep systems patched and security knowledge updated

### Additional Resources

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [konstruktoid Security Hardening](https://github.com/konstruktoid/ansible-role-hardening)
