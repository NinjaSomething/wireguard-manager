# User Guide
This document provides a comprehensive guide on how to use the Wireguard Manager. The Wireguard Manager is a service that 
manages clients on a Wireguard VPN network, allowing you to add, remove, and list clients easily. It also provides 
functionality for tagging clients with metadata.  The tags are useful for organizing clients and keeping track of who has
access to the VPN.

## Wireguard VPN Server
Start by adding a Wireguard VPN server.  When you do this give the VPN a unique name. If you include 
an SSH key, the Wireguard Manager will automatically manage changes to the clients on the VPN server.  If you do not 
include an SSH key, you can add clients to the Wireguard Manager, and tag them with meta-data, but you will need to 
manually manage changes to the clients on the wireguard server yourself.

The Wireguard Manager has an endpoint for importing peers from the wireguard server into the Manager.  This is a quick way
to import existing peers into the manager.  All imported peers will be tagged with 'imported'.

Removing a server from the manager will not change anything on the wireguard server itself.  

## Wireguard Client
The Wireguard Manager has endpoints for adding, removing, and listing clients.  When you add a client, you can also tag it 
with metadata.  There are no restrictions on the tags you can use, so you can use them to organize clients in any way you 
like.  The current implementation includes the following features:
* Adding/Removing a peer
* Listing all peers on the VPN server.
* Getting a peer by IP address.
* Getting all peers by tag.
* Getting the wg.conf file for a peer.
* Generate new public/private keys for a peer.  You will need to update the newly created private key on the peer itself.
