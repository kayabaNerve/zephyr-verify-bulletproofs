# Zephyr Verify Bulletproofs

This is an independent verification of the claims within
https://x.com/demand_answer/status/1868950596461772922. While there could be a
flaw in the methodology present here, it would appear to confirm the
allegations.

Transactions with invalid range proofs (invalid Bulletproofs(+)) would cause
inflation of the supply to arbitrary amounts, with no way to know what the
actual supply is (other than whoever made these transactions coming forward
with the answers and proof). The transactions alleged to have invalid range
proofs all had ZEPH outputs, meaning only the ZEPH supply would have been
compromised by these.

This tool does not look to see if any other transactions also had invalid range
proofs. This tool solely verifies the transactions alleged to have invalid
range proofs and a pair of others as a sanity check.
