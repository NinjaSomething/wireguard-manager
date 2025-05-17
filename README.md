# wireguard-manager
This is a service that will manage all the clients on a Wireguard VPN network.  This tool is designed to keep track of 
all the clients connected to each WireGuard VPN and store metadata about each of them in the form of tags.  If an SSH key is 
provided for the server, this will add and remove clients from the Wireguard server automatically.

The assumed architecture is that each VPN contains a single WireGuard Server that coordinates communication with 
multiple clients.

The public docker image can be found [here](https://gallery.ecr.aws/g0d6f2g5/wireguard-manager).

## Deployment
Instructions for deploying the Wireguard Manager can be found [here](docs/DEPLOYMENT.md).

## User Guide
Instructions for using the Wireguard Manager can be found [here](docs/USAGE.md).

## Local Development
If you wish to contribute to this project, instructions for running the services locally can be found 
[here](docs/DEVELOPMENT.md).
