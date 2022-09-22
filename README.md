# wireguard-manager
This is a service that will manage all the clients on a wireguard VPN network.  This tool is designed to keep track of 
all the clients connected to each WireGuard VPN and store metadata about each of them.  It also supports managing 
the WireGuard server remotely via SSH when clients are added or deleted.

The assumed architecture is that each VPN contains a single WireGuard Server that coordinates communication with 
multiple clients.

## Wireguard Server Management
The WireGuard Manager can be configured to add/delete clients on the server remotely via ssh.  To use this the 
wireguard server must allow for incoming SSH connections and the SSH private key must be saved in the ~/.ssh/ 
directory.

The SSH key must have the appropriate permissions.  Use the following command to set this:
```
chmod 700 ~/.ssh/{filename}
```

You can test the SSH connection using the following command:
```
ssh -i ~/.ssh/{ssh_key_filename} {username}@{wireguard_server_address} 'sudo wg'
```