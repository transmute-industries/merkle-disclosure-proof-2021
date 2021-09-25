import { getProofs, verifyProofs, deriveProofs } from '../merkle';

const messages = ['zero', 'one', 'two'];

// a proof must disclose some nonces to verifier..
it('cannot verify proofs without derivation', async () => {
  const proof = getProofs(messages);
  expect(verifyProofs(messages, proof.proofs, proof.root)).toBe(false);
});

it('can verify derived proofs', async () => {
  const proof = getProofs(messages);
  const derivedProofs = deriveProofs(
    [1],
    proof.proofs,
    messages,
    proof.rootNonce
  );
  expect(verifyProofs([messages[1]], derivedProofs, proof.root)).toBe(true);
});
