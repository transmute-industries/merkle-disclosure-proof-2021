import { getProofs, verifyProofs, deriveProofs } from '../merkle';

const messages = [
  'zero',
  'one',
  'two',
  'three',
  'four',
  'five',
  'six',
  'seven',
  'eight',
  'nine',
  'ten',
];

it('cannot verify without derivation', async () => {
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
