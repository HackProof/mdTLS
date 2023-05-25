## Formal Verification
We defined nine security lemmas and one source lemma for security verification.
Six security lemmas are from maTLS and three other security lemmas are newly added to prove the security property of proxy signature. They are defined as first-order logic-based formulas called lemma. If Tamarin failed to verify the lemmas, it would generate a graph showing a trace that leads to the contradiction. After succeeding to verify lemmas, we capture the results of formal verification for each lemmas.  
> **※ Commands for verification**
> > ✓   To prove all lemmas in theory, execute command `$ tamarin-prover --prove mdTLS.spthy` in command mode  
> > ✓   To prove all lemmas in theory, execute command `$ tamarin-prover interactive mdTLS.spthy` in GUI(interactive) mode, then redirect your browser to http://localhost:3001  


### Security lemmas
We verified that our protocol meets nine security goals through security lemmas as below.
- Existing security lemmas in maTLS
  - Server/Middlebox Authentication, Middbox Path Secrecy/Integrity, Data Authentication, Modification Accountability
- New security lemmas in mdTLS
  - Verifiability, Strong identifiability/unforgeability

### Source lemmas
Partial deconstruction occurs when Tamarin cannot recognize the type of variables in formal specifications. This leads Tamarin not to prove correctly because it has no information about them. To solve this issue, a source lemma is essential because it serves information about where this data came from and defined. Therefore, we wrote a source lemma to let Tamarin knows the source of these problematic variables.
