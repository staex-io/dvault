# dVault

This project is intended to improve **security** and usability of **secret data delivering** to the edge and make a distributed chain of trust.

This theme is very crucial for the IIoT and DePIN sector. There are a lot of new devices set up every day with various purposes, from home to industrial. IIoT area is expected to have billions of devices in the near future. To have secure and automated infrastructure for secret data (such as certificates or API tokens) distribution and rotation is important for proper, healthy and secure work of any project or company. Here we come with the dVault solution for DePIN to improve remote access to drones, vehicles and robots and communication between them.

| Problem | Solution |
| - | - |
| There is **no secure** and decentralized solution to distribute private data across devices. Centralized solutions **can’t work** in an **honest and transparent** way and **require infrastructure**. | Decentralized **no-infrastructure** way, to **securely distribute** private data utilizes the  smart contracts for **integrity** and IPFS to **avoid infrastructure**. |

**Benefits**

- **Activity history** is publicity available and **immutable**.
- **No centralized** and managed **infrastructure**.
- User doesn’t need to trust third-party company, transparent **integrity**.
- **Distributed responsibility**.

## Use-cases

Here are real examples of such system usage.

### SSH keys rotation

To have a remote access to drones, vehicles or robots some companies use SSH protocol.

The simplest way to improve overall system security while working with SSH - often keys rotation. Rotation flow is quite straightforward:

1. Issue new SSH key pair
2. Sign issued key pair with certificate authority key pair
3. Deliver new key pair to device
4. Revoke old key pair

With our system such flow can be done frequently and securely.

## How it works

We show how it works using SSH use-case.

In simple words, we propose a way to generate a new key pair for any client or server by the admin user. Sign them using the Certificate Authority (CA). Then, using Diffie-Hellman key exchange, encrypt this key pair and distribute it through IPFS. To verify the integrity of the key pair, customer can use the smart contract. It can notify clients about new key pair availability through the smart contract and claim key pair hashes. After downloading it from IPFS and decryption, client can apply key pair locally (for example new SSH key pair or SSH CA). With such an approach, the **client** can be **sure** that this **key pair belongs** to the **particular admin** and can **trust** it. And by **encrypted way** of distribution **keys** can be **rotated often** to **improve** overall **system security.** Last but not least, everything can be done **without centralized servers** and **doesn't require** to have **own infrastructure.**

**Such system can work with any type of certificates or logic which require to distribute private information over the network. For example with TLS certificates.**

**Advantages of such an approach:**

1. All actions with certificate authorities and key pairs are publicity available.
2. System activity history is immutable.
3. Safe distribution of new certificates and key pairs.
4. Fast certificates and key pairs rotation.
5. Doesn't require centralized or cloud infrastructure at all.
6. Distributed trust model to improve fault tolerance against system security violation.
7. Even if your root certificate authority will be hacked it can be changed quickly.
8. Certificates and key pairs storage is distrusted.
9. Smart contracts are publicity available, everyone can check integrity logic and how system works.
10. Only user which has smart contract private key can issue or revoke certificate, not centralized third-party layer.

## Future work

There are some use-cases for future work.

### Avoid centralized SSH certificate authority

By utilizing smart contracts, it is possible to avoid using SSH certificate authority but keep the same security level for SSH communication. Every device trusts the smart contract and the admin public key that is interacting with the smart contract. So we can deliver a new key pair through a smart contract and IPFS to the device. And devices can apply this new key pair using the `authorized_keys` file. This can be done on every device, its like trusted public keys exchange. With such an approach, systems can have distributed certificate authority (smart contract) instead of centralized one.

### IIoT device access

For example user has an IIoT device and user needs access to it for 5 minutes only. User can issue new temporary SSH (or other) key pair, deliver it to the device and after doing some work revoke it. So it is easy and fast device access solution with secure rollback flow to avoid accessing device by hacker while it doesn't need remote access.

### Microservices communication

Microservices require secure communication with each other. With DPKI solution we can provide new key pair for every microservice deployed to the cloud and distribute it public key to other microservice. With such an approach communication between microservice will be secure and automatically initiated.
