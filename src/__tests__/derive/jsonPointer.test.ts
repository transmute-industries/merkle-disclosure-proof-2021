import { MerkleDisclosureProof2021 } from '../..';

import { credentials, proofs, documentLoader } from '../../__fixtures__';

it('can derive and verify', async () => {
  const suite = new MerkleDisclosureProof2021();
  const inputDocumentWithProof = {
    ...credentials.credential0,
    proof: proofs.proof2,
  };
  const outputDocument = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      {
        alsoKnownAs: 'https://www.w3.org/ns/activitystreams#alsoKnownAs',
      },
    ],
    id: 'http://example.edu/credentials/3732',
    type: ['VerifiableCredential'],
    issuer: 'https://example.edu/issuers/14',
    issuanceDate: '2010-01-01T19:23:24Z',
  };

  const derivationResult = await suite.deriveProof({
    inputDocumentWithProof,
    outputDocument,
    documentLoader,
  });

  const result = await suite.verifyProof({
    document: {
      ...derivationResult.document,
    },
    proof: { ...derivationResult.proof },
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
