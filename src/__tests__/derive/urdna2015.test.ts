import { MerkleDisclosureProof2021 } from '../..';

import { credentials, proofs, documentLoader } from '../../__fixtures__';

it.skip('can derive and verify', async () => {
  const suite = new MerkleDisclosureProof2021();
  const inputDocumentWithProof = {
    ...credentials.credential1,
    proof: { ...proofs.proof3 },
  };
  const outputDocument = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://w3id.org/security/suites/merkle-jws-2021/v1',
      {
        // alsoKnownAs: 'https://www.w3.org/ns/activitystreams#alsoKnownAs',
        nickName: 'https://www.w3.org/ns/activitystreams#nickName',
      },
    ],
    id: 'http://example.edu/credentials/3732',
    type: ['VerifiableCredential'],
    issuer: 'https://example.edu/issuers/14',
    issuanceDate: '2010-01-01T19:23:24Z',
    credentialSubject: {
      // alsoKnownAs: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
      nickName: 'Bob',
    },
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
