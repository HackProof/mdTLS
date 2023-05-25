## What we verified in Lemma
  ### - Server Authentication
   If the client and server share the same nonce value after the handshake is completed, the client believes the server is authenticated
 
  ### - Middlebox Authentication
When the handshake between the client and middlebox is finished, the client can authenticate the middlebox through nonces

  ### - Middlebox Path Integrity
By establishing the order of middleboxes, endpoints can realize where the message should flow next

  ### - Middlebox Path Secrecy
When the handshake is completed, sessions between all entities must be established with one of the client's cipher suites

  ### -  Modification Accountability
When the client receives a response message from the server, the client can check whether middleboxes modified the message

  ### -  Data Authentication
When the client receives a message, the client believes the message is from the server's original message during the record phase

  ### -  Verifiability
Whenever a client receives a proxy signature, this has to be sent by the middlebox, the proxy signer. Furthermore, from the warrant in proxy signature, the client has to verify whether the middlebox is a delegated proxy signer

  ### -  Strong-Unforgeability
The proxy signer’s secret key, which is used to generate the proxy signature, must not be revealed. Otherwise, the proxy signature can be forged by an adversary

  ### -  Strong-Identifiability
  The identification of a proxy signer can be proved by its public key. When the client confirms the proxy s
