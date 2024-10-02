# Swarm ACT Integration for User-Based Access Control

## Overview

This package provides an implementation to integrate Swarm's Access Control Trie (ACT) with a user-based access control mechanism. It addresses the limitation of the native Swarm ACT, which is node-based and lacks user-level granularity, by enabling access control initialized with a user's key and allowing users to be added as grantees.

## Background

The Access Control Trie (ACT) in Swarm provides a way to manage access permissions for resources stored on the Swarm network. However, the native implementation of ACT is node-based, meaning access control is managed at the node level rather than the user level. This poses a challenge for user-centric and fine-grained access control.

### Problem with Native Swarm ACT

- **Node-Based Access Control**: Swarm's native ACT operates on nodes, not users, limiting the ability to control access at a user level.
- **Lack of User Concept**: Without user keys, it's challenging to implement user-specific permissions and sharing capabilities.
- **Limited Collaboration**: Users cannot be added as grantees directly.

## Solution

This package overcomes the limitations by:

- **Initializing ACT with User Keys**: It uses a user's private key to initialize the access control mechanism.
- **User-Based Grantees**: Allows any user to be added as a grantee by their public key.
- **Mapping User Identities**: Bridges the gap between node-based ACT and user-centric applications by mapping user identities to the ACT.
- 
## How It Works

- **User Initialization**: By initializing the ACT with a user's private key, the access control is tied to the user's identity.
- **Grantee Management**: Public keys of grantees are stored and managed, allowing specific users to be granted or revoked access.
- **Data Encryption**: Data references are encrypted and managed through Swarm's upload and download handlers, ensuring only authorized users can access the data.

## Code Structure

- **ACT Struct**: Core struct holding the access control controller, user's public key, and the PutGetter client.
- **Functions**:
    - `New`: Initializes the ACT instance.
    - `CreateGrantee`: Adds grantees to the access list.
    - `GetGrantees`: Retrieves the list of current grantees.
    - `RevokeGrant`: Revokes access for specific grantees.
    - `HandleUpload`: Manages the upload process with access control.
    - `HandleDownload`: Manages the download process, ensuring access permissions.

## Installation

```bash
go get github.com/asabya/swarm_act
```

Ensure that you have Go installed and set up on your system.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License.
