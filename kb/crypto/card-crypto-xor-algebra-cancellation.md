# Cancel XOR terms algebraically before attacking any key

**First useful action.** Write the ciphertext equations symbolically and cancel repeated terms before
guessing a single key byte.

```bash
python3 - <<'PY'
# illustration: c1 = p1 ^ k, c2 = p2 ^ k  =>  c1 ^ c2 = p1 ^ p2   (key cancels)
c1 = bytes.fromhex('<CIPHERTEXT_1_HEX>')
c2 = bytes.fromhex('<CIPHERTEXT_2_HEX>')
x  = bytes(a ^ b for a, b in zip(c1, c2))
print(x.hex()); print(x)
PY
```

Expected: a value with the key eliminated, which is now a plaintext-versus-plaintext problem where
language structure is available. If the two ciphertexts differ in length, the model does not hold as
stated — align them or discard the hypothesis.

## Symptoms

- The challenge exposes several values encrypted with the same keystream (two messages, a known plaintext
  pair, or a "here is the ciphertext and here is a partial decryption" pair).
- The key is unknown but appears in more than one equation.
- Key recovery looks infeasible while a plaintext-difference problem looks tractable.

## Prerequisites and assumptions

- All operands normalized to bytes of equal length and aligned at the same keystream offset.
- The operation really is XOR: an additive or modular operation does not cancel this way.
- The repository rule that maths happen offline; nothing here touches a live service.

## Diagnostic sequence

1. Represent each ciphertext as an expression over unknown plaintexts and the shared key.
2. Cancel: an unknown keystream appearing in two equations disappears under XOR
   (`c1 ^ c2 = p1 ^ p2`). Look for the same cancellation opportunity with a known plaintext
   (a crib) — that directly yields keystream bytes.
3. Work on the reduced problem, where linguistic structure or a crib applies to a plaintext difference
   rather than to a key.
4. Recover the key from one known plaintext byte, then decrypt the remaining messages.
5. Confirm by decrypting *all* messages coherently. A partial recovery that only fixes the pair you
   started from is a coincidence check, not a break.

If cancellation reduces the problem to a single unknown → solve it. If it does not reduce at all →
the messages are not keystream-aligned (different keyss, different offsets, or per-message nonces);
re-read the source for the construction rather than trying more algebra.

## Commands and interpretation

| Command | Reads as | Means |
|---|---|---|
| ciphertext pair with equal length | aligned byte streams | Cancellation applies |
| `c1 ^ c2` output containing readable text | plaintext-difference is linguistic | Structure present: recover keystream from one side |
| `c1 ^ c2` output unstructured | both plaintexts non-linguistic (binary/compressed) | Cancellation still valid, but you need another lever |
| crib XOR ciphertext | keystream bytes directly | Known plaintext is the cheapest form of cancellation |

## Failure modes and things teams stopped doing

- Brute-forcing before simplifying. If the key cancels, the search space was never the obstacle; teams
  lose whole clock cycles on this in timed events.
- XORing at the wrong level (hex characters versus decoded bytes, or differing offsets). Offsets are the
  most common silent error: shift by one byte and every equation is meaningless.
- Assuming XOR for an additive cipher. `c = p + k mod n` behaves differently and can be attacked
  separately, but treating it as XOR wastes the time spent on the wrong algebra.
- Treating a key recovered from one pair as universal without checking the other messages. Nonce reuse
  patterns differ; verify per message.

## Evidence status

- **Status:** source-supported but untested.
- **What we actually ran:** nothing in this session; the snippet illustrates the algebra and was not
  executed. XOR properties are sourced from the cryptography course we cite; the decision rules here are
  our adaptation of repository draft CRYPTO-005.

## Sources

- `src-cryptohack-intro-401bf309` — XOR properties as a documented primitive, including the
  self-cancelling behaviour this card exploits.
- `src-cyberchef-magic-source-2a3dcc0a` — the reminder that an XOR-shaped result produced by tooling still needs
  independent structural confirmation.
