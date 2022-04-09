# Manta Fee Relayer Spec

Status: Draft

## Motivation

In order to publish a private transaction on Manta Network, clients must pay a MANTA-denominated fee from a public account. Without mitigation, this is a significant privacy leak.

For example: suppose Alice purchases some DOT on a centralized exchange. Suppose she wants to dissociate this DOT from her KYC identity. Happily, if Alice deposits her DOT into Manta Network's shielded asset pool and executes a private transfer (either to herself or to someone else), an observer can't tell how much pDOT Alice owns. But if Alice ever withdraws DOT from the shielded asset pool to a public address, the DOT again becomes connected to her KYC identity—assuming Alice doesn't somehow have non-KYC'ed public MANTA, she must pay her transaction fee from a public account linked to her KYC identity.

## Concept

Alice wants to execute a private transaction without paying a public fee and leaking privacy. She asks a Manta node serving as a "fee relayer" to pay her public transaction fee instead. Alice's transaction includes a private payment to compensate the fee relayer. Alice benefits from enhanced privacy, and the fee relayer nets a small profit.

## Vulnerabilities and Mitigations

### IP Logging

Clients should only submit transactions to fee relayers over anonymous network protocols like Tor, in order to prevent the association of public addresses with IP addresses.

---

### Transaction Batch Cherrypicking

A single human-meaningful transaction usually requires a batch of protocol-level transactions, since these protocol-level transactions can only consume some small constant number of utxos (see [manta-pay spec](https://github.com/Manta-Network/spec/blob/main/manta-pay/spec.pdf)). A malicious fee relayer might publish only those parts of a batch which are necessary for the relayer to receive its relay fee, and ignore the rest.

To mitigate this attack, clients should construct batches such that the transaction which pays the fee relayer comes last in the batch's "dependency chain." If a batch is constructed correctly, the fee relayer will receive payment only if all of the transactions composing the batch are successfully executed.

---

### Double Spend Fee Wasting Attack

A malicious client can simultaneously trick many naive fee relayers into publishing mutually exclusive "double spend" transactions and thus wasting fees:

1. The malicious client constructs many valid but incompatible transactions—all have some utxo input(s) in common.
2. The malicious client simultaneously sends each fee relayer a different malicious transaction.
3. Each fee relayer verifies the transaction it has received, and determines that the transaction is valid.
4. Each fee relayer signs and publishes the transaction it received, committing to pay a public transaction fee.
5. Whichever transaction makes it into a block first is successfully executed. The one lucky relayer receives its relay fee as normal.
6. All of the other fee relayers are surprised to see their transactions fail within the same block. They have wasted a fee without compensation.

Fee relayers can partially mitigate this attack by monitoring their Manta node for published transactions and checking the void numbers in these published transactions against the void numbers in the transactions they would relay. Any duplicate void number indicates a malicious transaction.

However, a fee relayer may not see a duplicate void number until it has already published its malicious transaction and committed to paying a fee, due to network latency. To further mitagate this attack, each relayer should wait for some random interval after receiving a transaction such that any two nodes who receive a transaction at the same time are unlikely to publish their transactions within the same window of network latency. In practice, relayers might randomly delay publishing transactions by up to a second or two.

---

### DDOS

Fee relayers are relatively vulnerable to DDOS attacks. First, since fee relayers expect requests over anonymous protocols like Tor, they cannot simply throttle attacking IPs as e.g. Cloudflare does. Second, it takes orders of magnitude more time to reject a spam relay transaction than to build a spam relay transaction. Transactions must contain zero knowledge proofs, and although ZKPs are quick to verify, invalid spam ZKPs can be constructed even more quickly, simply by taking valid ZKPs and changing bits.

Fee relayers can mitigate DDOS attacks with a [HashCash](https://en.wikipedia.org/wiki/Hashcash)-style approach; they can require clients to do some tiny proof-of-work exercise similar in cost to ZKP validation (a few milliseconds of computation on a normal device), in order to increase the cost of spam generation relative to spam rejection.


## Optional Features

### Fee Payment in Currencies Besides MANTA

Fee relayers may choose to accept relay fees in currencies besides MANTA, setting implicit exchange rates as they deem appropriate. Even though relaying mint transactions provides no privacy benefit, users who don't own MANTA may want to relay mint transactions for the sake of convenience alone.

## Alternatives

Unlike Manta Network, ZCash and Monero require private fee payment. This is likely the more elegant solution, and there is no reason Manta couldn't do this in principle. But in practice, the engineering problem is unfeasible. Private fees would require Manta Network's consensus to support both unsigned transactions (to remove the public fee requirement) and atomic batching (to prevent on-chain transaction execution without fee payment), which we anticipate will be difficult in combination. It is probably better to add a little application-level complexity than to hack Substrate consensus code we don't understand well.
