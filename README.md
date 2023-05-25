# mdTLS (Middlebox-delegated TLS)
## Research Overview
We propose mdTLS protocol to improve performance based on the [middlebox-aware TLS (maTLS)](https://github.com/middlebox-aware-tls), one of the most secure TLS protocols. We found out that the computational complexity of mdTLS is about twice as low as that of maTLS.

### Stage 0. Generating certificates phase
Server generates its certificate as in original TLS.
1. Server sends Certificate Signing Request (CSR) to Certificate Authority (CA).
2. CA verifies CSR, creates pre-certificates, and submits to CT Log server to get Signed Certificate Timestamps (SCT).
3. CA issues certificate to the server with SCTs from CT Log servers.

### Stage 1. Handshake Phase
![mdTLS_handshake_v0 4_for black background](https://github.com/thyun1121/mdTLS/assets/18222806/38700908-3e32-43c5-acae-8fb61ba9dc8c)
- In mdTLS, middlebox is a proxy signer of server. Therefore, delegation process is required.
- Since middlebox, generates its certificate by proxy signing server's certificate, we excluded MT Log server and CA for middlebox which were described in maTLS. This makes certificate generation and verification more efficient.
- Client has to verify two types of signature, one is original signature and the other is proxy signature. In order to verify proxy signature, client needs proxy public keys, which are generated according to the proxy signature verification method.
- Proxy signature is also used in Security Parameter Blocks by middlebox.
### Stage 2. Record Phase
![mdTLS_record_darkmode_v0 2](https://github.com/thyun1121/mdTLS/assets/18222806/f7b48a8e-af9a-4ca2-9450-c4c3857a9556)
- Client and server sends request and response with Modification Log, as maTLS, to check whether payload has been changed while being transmission.

## Security Evaluation
We verified that our proposal meets newly defined security goals as well as those verified by maTLS.
We used [Tamarin prover](http://tamarin-prover.github.io/) to evaluate security of mdTLS, and we verified that the mdTLS protocol meets the security goals: *Authentication*, *Secrecy*, and *Integrity*.

### Formal Specification
mdTLS is specified based on TLS Handshake and Record phases under the assumption that there are three entities: client, server, and one middlebox. The role of each entity is as follows.
- Since we specified server-only authentication based on TLS v1.2 as a premise, only the server can generate its certificate from CA.
- The middlebox acts as a delegated proxy signer by the server, and the middlebox creates its certificate by proxy signing the server's certificate.
- Client, the verifier, verifies signatures of server and middlebox to clarify whether both middlebox and server are legitimate entities.
- When the handshake is completed, each segment exchanges messages using different TLS session keys according to maTLS.

### Formal Verification
We defined nine security lemmas and one source lemma for security verification.
Six security lemmas are from maTLS and three other security lemmas are newly added to prove the security property of proxy signature, which are *Verifiability*, *Strong-Unforgeability*, and *Strong-Identifiability*.  They are defined as first-order logic-based formulas called lemma. If Tamarin failed to verify the lemmas, it would generate a graph showing a trace that leads to the contradiction.


### Commands for verification
- Command mode
  - To prove all lemmas in theory, execute command `$ tamarin-prover --prove mdTLS.spthy`
- Interactive mode
  - For GUI mode, execute command `$ tamarin-prover interactive mdTLS.spthy`  then, point your browser to http://localhost:3001

### Results of verifications
On AWS EC2 c5a.24xlarge instance, verifying all lemmas takes 96 minutes in command mode.
- 96 vCPUs, 192 GiB Memories
- Ubuntu 22.05.2 LTS
  #### > Command mode
   ![mdTLS_tamarin_verified_command](https://github.com/thyun1121/mdTLS/assets/18222806/2483cdb3-01aa-4cb2-89e0-967197897642)
