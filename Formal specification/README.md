## Formal Specification
mdTLS is specified based on TLS Handshake and Record phases under the assumption that there are three entities: client, server, and one middlebox. The role of each entity is as follows.
- Since we specified server-only authentication based on TLS v1.2 as a premise, only the server can generate its certificate from CA.
- The middlebox acts as a delegated proxy signer by the server, and the middlebox creates its certificate by proxy signing the server's certificate.
- Client, the verifier, verifies signatures of server and middlebox to clarify whether both middlebox and server are legitimate entities.
- When the handshake is completed, each segment exchanges messages using different TLS session keys according to maTLS.
### Handshake phase
Handshake phase is responsible for establishing a secure connection among entities. During handshake phase, a number of messages are exchanged among entities. Specific steps in handshake phase is divided into 9 steps as below. Each step is formally specified in forms of "rules" which is a basic function in tamarin prover.
- Client Hello
- MB Client Hello
- Server Hello
- MB Server Hello
- Client Finished
- MB Client Finished
- Server Finished
- MB Server Finished
- Client Complete
### Record phase
Record phase is responsible for data exchange in secure connection when established in handshake phase. It consists of only 1 step and also specified in forms of "rules".
-MB Server Reply Modification
