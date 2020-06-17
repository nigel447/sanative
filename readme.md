## Security code for native android applications

### A novel attempt to create a sucure channel over http  

### Verify  
server / client share a  private key, client ecdsa signs the public key and sends 
the signature, server verifies and stores a client nonce in a session map.  

### Message with signature and 2FA  
messages sent with nonce then  authenticated with signature and time based 2fa code


