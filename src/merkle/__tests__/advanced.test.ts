import { getProofs, verifyProofs, deriveProofs } from '../merkle';

const messages = ['zero', 'one', 'two'];

it('issuer generates proofs for messages and signs root', async () => {
  const proof = getProofs(messages);
  expect(verifyProofs(messages, proof.proofs, proof.root)).toBe(true);
});

it('holder derives proofs for some messages', async () => {
  const proof = getProofs(messages);
  const derivedProofs = deriveProofs([1], proof.proofs);
  expect(verifyProofs([messages[1]], derivedProofs, proof.root)).toBe(true);
});

it('verifier checks root signature, then verifies derived proofs for some messages', async () => {
  const proof = getProofs(messages);
  const derivedProofs = deriveProofs([1], proof.proofs);
  expect(verifyProofs([messages[1]], derivedProofs, proof.root)).toBe(true);
});
