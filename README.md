# Privrouter Project
Privacy-Focused virtual routing software using bare linux ip stack and bash shell.

# Goal
To protect individuals privacy and take control of your network routes, has advanced enterprise features that a router would have.

Disclaimer: I'm not responsible for any use of this product with wrong intentions or for criminal activity, this is a project to help people achiving some privacy at network level.
You should have some linux system administration skills, network knowledge (ports and protocols) in order to fully take advantage of this software.

# Configuration Directory Structure
This is the directory structure for privrouter before being decrypted and after is unlocked.
  - Encrypted: means that privrouter volume has not been intialized yet and needs a password.
  - Running: a correct password was given and is initializing or running.

After decryption, privrouter will mount its filesystem on /tmp pseudo-filesystem to prevent data from being stored on permanent storage to prevent leaks. Also the filesystem its ext2 so no journaling available there also. After power is cutted to the system no data is recoverable or can be collected.

# 
