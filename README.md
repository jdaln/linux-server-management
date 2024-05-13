# deb-server-management
Server management playbooks

### Pre-requisites
Pre-requisite commands depends on your OS.

#### Mac OS
Then, install the software needed to launch this and its automatic testing:
```
brew install vagrant
brew install --cask virtualbox
```

### Before running anything from this repository
Before running anything from this repository, install the following (after the Pre-requisites specific to your OS)
```
pip install -r requirements.txt
ansible-galaxy install -r requirements.yml
```

### Testing

You may test the playbooks on the latest Debian Bookworm and Ubuntu Jammy. For this, run:
```
ansible-galaxy install -r testing/requirements.yml
vagrant up
```

### Using
Before launching this, make sure that you have connected to your targets at least once via SSH so that the ssh fingerprint is authorized.
The `ask-pass`
To run the setup playbook use:
```
BASTION_USER="YOUR_USERNAME_TO_SSH_WITH"
ansible-playbook -i inventories/mip-cscs/inventory -l GROUP_OR_HOST_NAME -u $BASTION_USER setup-playbook.yml
```