Securing your AlmaLinux 9 server by disabling direct root login and switching to a dedicated user is one of the most effective ways to prevent brute-force attacks.

---

## Part 1: Hardening SSH Access

### 1. Create a New Sudo User

Before disabling root access, you need a user that can perform administrative tasks. Replace `adminuser` with your preferred username.

```bash
# Create the user
adduser adminuser

# Set a strong password
passwd adminuser

# Add the user to the wheel group (allows sudo access)
usermod -aG wheel adminuser

```

### 2. Test Sudo Access

**Do not close your root session yet.** Open a new terminal window and try to log in as the new user:

```bash
ssh adminuser@your_server_ip
# Once logged in, test sudo:
sudo whoami
# It should return "root"

```

### 3. Disable Root Login and Password Authentication

Now that you have a working sudo user, edit the SSH configuration file:

```bash
sudo vi /etc/ssh/sshd_config

```

Find and modify the following lines (remove the `#` if they are commented out):

* `PermitRootLogin no`
* `PasswordAuthentication yes` (Change to `no` if you have already set up **SSH Keys**, which is even more secure).

### 4. Restart SSH Service

Apply the changes:

```bash
sudo systemctl restart sshd

```

From now on, you must log in as `adminuser` and use `sudo` for administrative tasks.

---

## Part 2: Installing LXD on AlmaLinux 9

LXD is a powerful container and virtual machine manager. On AlmaLinux, it is best installed via **Snap**, as it isn't in the default `dnf` repositories.

### 1. Enable EPEL and Install Snapd

Snap is required to get the latest stable version of LXD.

```bash
# Install EPEL repository
sudo dnf install epel-release -y

# Install snapd
sudo dnf install snapd -y

# Enable the snap communication socket
sudo systemctl enable --now snapd.socket

# Create a symbolic link for classic snap support
sudo ln -s /var/lib/snapd/snap /snap

```

**Note:** You may need to log out and log back in (or restart) to ensure snap paths are updated correctly.

### 2. Install LXD

Now, install the LXD package via snap:

```bash
sudo snap install lxd

```

### 3. Initialize LXD

LXD needs to be configured (storage pools, network bridges, etc.). Run the interactive init tool:

```bash
sudo /snap/bin/lxd init

```

* For most users, pressing **Enter** to accept the default values is sufficient.
* It will ask about creating a "dir" or "zfs" storage pool; "dir" is the simplest for testing, while "zfs" or "lvm" is better for production.

### 4. Add Your User to the LXD Group

To manage containers without typing `sudo` every time:

```bash
sudo usermod -aG lxd adminuser
# Apply group changes without logging out
newgrp lxd

```

### 5. Launch Your First Container

Test your installation by launching a small Alpine Linux container:

```bash
lxc launch images:alpine/edge my-container
# Check status
lxc list

```

---

### Security Summary

| Action | Security Benefit |
| --- | --- |
| **Disable Root Login** | Prevents attackers from targeting the one username guaranteed to exist on every system. |
| **Use Sudo** | Provides an audit trail of which user performed which administrative action. |
| **LXD Containers** | Isolates applications so that a breach in one service doesn't compromise the entire host OS. |
