import { getProofs, verifyProofs, deriveProofs } from '../merkle';

const messages = ['zero', 'one', 'two'];

// cannot verify without derivation
it('can generate proofs for messages', async () => {
  const proof = getProofs(messages);
  expect(verifyProofs(messages, proof.proofs, proof.root)).toBe(false);
});

it('holder derives proofs for some messages', async () => {
  const proof = getProofs(messages);
  const derivedProofs = deriveProofs(
    [1],
    proof.proofs,
    messages,
    proof.rootNonce
  );
  expect(verifyProofs([messages[1]], derivedProofs, proof.root)).toBe(true);
});

it('verifier checks root signature, then verifies derived proofs for some messages', async () => {
  const proof = getProofs(messages);
  const derivedProofs = deriveProofs(
    [1],
    proof.proofs,
    messages,
    proof.rootNonce
  );
  expect(verifyProofs([messages[1]], derivedProofs, proof.root)).toBe(true);
});
