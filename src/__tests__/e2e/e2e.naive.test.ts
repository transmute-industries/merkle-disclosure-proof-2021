import { JsonWebKey, MerkleDisclosureProof2021 } from '../..';

import { keys, credentials, documentLoader } from '../../__fixtures__';

describe.skip('naive e2e', () => {
  let proof0: any;
  it('create', async () => {
    const key = await JsonWebKey.from(keys.key0 as any);
    const suite = new MerkleDisclosureProof2021({
      key,
      date: '2021-08-22T19:36:43Z',
      rootNonce: 'urn:uuid:d84cd789-4626-488d-834b-ceb075250d50',
    });

    proof0 = await suite.createProof({
      document: { ...credentials.credential1 },
      purpose: {
        update: (proof: any) => {
          proof.proofPurpose = 'assertionMethod';
          return proof;
        },
      },
      documentLoader,
    });
    console.log(JSON.stringify(proof0, null, 2));
  });

  it('derive full and verify', async () => {
    const suite = new MerkleDisclosureProof2021();
    const derived = await suite.deriveProof({
      inputDocumentWithProof: {
        ...credentials.credential1,
        proof: proof0,
      },
      outputDocument: { ...credentials.credential1 },
    });
    const result = await suite.verifyProof({
      document: derived.document,
      proof: derived.proof,
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

  it('derive partial and verify', async () => {
    const suite = new MerkleDisclosureProof2021();

    const outputDocument: any = { ...credentials.credential1 };
    delete outputDocument.credentialSubject.nickName;
    // delete outputDocument['@context'][2].nickName;

    const derived = await suite.deriveProof({
      inputDocumentWithProof: {
        ...credentials.credential1,
        proof: proof0,
      },
      outputDocument,
    });

    console.log(JSON.stringify(derived, null, 2));
    const result = await suite.verifyProof({
      document: derived.document,
      proof: derived.proof,
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

  // it('createProof', async () => {
  //   const key = await JsonWebKey.from(keys.key0 as any);
  //   const suite = new MerkleDisclosureProof2021({
  //     key,
  //     date: '2021-08-22T19:36:43Z',
  //     rootNonce: 'urn:uuid:d84cd789-4626-488d-834b-ceb075250d50',
  //   });
  //   const proof = await suite.createProof({
  //     document: { ...credentials.credential0 },
  //     purpose: {
  //       update: (proof: any) => {
  //         proof.proofPurpose = 'assertionMethod';
  //         return proof;
  //       },
  //     },
  //     documentLoader,
  //   });
  //   // console.log(JSON.stringify(proof, null, 2));
  //   expect(proof).toEqual(proofs.proof0);
  // });
  // describe('verifyProof', () => {
  //   it('should fail without derivation', async () => {
  //     const suite = new MerkleDisclosureProof2021();
  //     const result = await suite.verifyProof({
  //       document: { ...credentials.credential0 },
  //       proof: { ...proofs.proof0 },
  //       purpose: {
  //         update: (proof: any) => {
  //           proof.proofPurpose = 'assertionMethod';
  //           return proof;
  //         },
  //       },
  //       documentLoader,
  //     });
  //     expect(result.verified).toEqual(false);
  //   });
  //   it('should succeed with derivation', async () => {
  //     const suite = new MerkleDisclosureProof2021();
  //     const derived = await suite.deriveProof({
  //       inputDocumentWithProof: {
  //         ...credentials.credential0,
  //         proof: { ...proofs.proof0 },
  //       },
  //       outputDocument: { ...credentials.credential0 },
  //     });
  //     const result = await suite.verifyProof({
  //       document: derived.document,
  //       proof: derived.proof,
  //       purpose: {
  //         update: (proof: any) => {
  //           proof.proofPurpose = 'assertionMethod';
  //           return proof;
  //         },
  //       },
  //       documentLoader,
  //     });
  //     expect(result.verified).toEqual(true);
  //   });
  // });
  // it('verifyProof fails when tampered', async () => {
  //   const suite = new MerkleDisclosureProof2021();
  //   const result = await suite.verifyProof({
  //     document: { ...credentials.credential0, newProperty: 'cool' },
  //     proof: { ...proofs.proof0 },
  //     purpose: {
  //       update: (proof: any) => {
  //         proof.proofPurpose = 'assertionMethod';
  //         return proof;
  //       },
  //     },
  //     documentLoader,
  //   });
  //   expect(result.verified).toEqual(false);
  // });
});
