import { getProofs, verifyProofs, deriveProofs } from '../merkle';

const messages = ['zero', 'one', 'two'];

// a proof must disclose some nonces to verifier..
it('cannot verify proofs without derivation', async () => {
  const proof = getProofs(messages);
  expect(verifyProofs(messages, proof.proofs, proof.root)).toBe(false);
});

describe('can verify derived proofs', () => {
  it('one', async () => {
    const proof = getProofs(messages);
    const derivedProofs = deriveProofs(
      [1],
      proof.proofs,
      messages,
      proof.rootNonce
    );
    expect(verifyProofs([messages[1]], derivedProofs, proof.root)).toBe(true);
  });

  it('one and two', async () => {
    const proof = getProofs(messages);
    const derivedProofs = deriveProofs(
      [1, 2],
      proof.proofs,
      messages,
      proof.rootNonce
    );
    expect(
      verifyProofs([messages[1], messages[2]], derivedProofs, proof.root)
    ).toBe(true);
  });

  it('zero and two', async () => {
    const proof = getProofs(messages);
    const derivedProofs = deriveProofs(
      [0, 2],
      proof.proofs,
      messages,
      proof.rootNonce
    );
    expect(
      verifyProofs([messages[0], messages[2]], derivedProofs, proof.root)
    ).toBe(true);
  });
});
