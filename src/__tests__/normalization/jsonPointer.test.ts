import { JsonWebKey, MerkleDisclosureProof2021 } from '../..';

import { keys, credentials, proofs, documentLoader } from '../../__fixtures__';

describe('MerkleDisclosureProof2021', () => {
  it('createProof', async () => {
    const key = await JsonWebKey.from(keys.key0 as any);
    const suite = new MerkleDisclosureProof2021({
      key,
      normalization: 'jsonPointer',
      date: '2021-08-22T19:36:43Z',
    });
    const proof = await suite.createProof({
      document: { ...credentials.credential0 },
      purpose: {
        update: (proof: any) => {
          proof.proofPurpose = 'assertionMethod';
          return proof;
        },
      },
      documentLoader,
    });
    // console.log(JSON.stringify(proof, null, 2));
    expect(proof).toEqual(proofs.proof2);
  });

  it('verifyProof', async () => {
    const suite = new MerkleDisclosureProof2021();
    const result = await suite.verifyProof({
      document: { ...credentials.credential0 },
      proof: { ...proofs.proof2 },
      purpose: {
        update: (proof: any) => {
          proof.proofPurpose = 'assertionMethod';
          return proof;
        },
      },
      documentLoader,
    });
    expect(result.verified).toEqual(true);
  });

  it('verifyProof fails when tampered', async () => {
    const suite = new MerkleDisclosureProof2021();
    const result = await suite.verifyProof({
      document: { ...credentials.credential0, newProperty: 'cool' },
      proof: { ...proofs.proof2 },
      purpose: {
        update: (proof: any) => {
          proof.proofPurpose = 'assertionMethod';
          return proof;
        },
      },
      documentLoader,
    });
    expect(result.verified).toEqual(false);
  });
});
