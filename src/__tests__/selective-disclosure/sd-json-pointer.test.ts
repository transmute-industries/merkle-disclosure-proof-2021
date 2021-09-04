import { JsonWebKey, MerkleDisclosureProof2021 } from '../..';

import { keys, documentLoader } from '../../__fixtures__';

describe('MerkleDisclosureProof2021 with Json Pointer', () => {
  let proof: any;
  let derivationResult: any;
  const doc = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://w3id.org/security/suites/merkle-jws-2021/v1',
      {
        alsoKnownAs: 'https://www.w3.org/ns/activitystreams#alsoKnownAs',
        nickName: 'https://www.w3.org/ns/activitystreams#nickName',
      },
    ],
    id: 'http://example.edu/credentials/3732',
    type: ['VerifiableCredential'],
    issuer: 'https://example.edu/issuers/14',
    issuanceDate: '2010-01-01T19:23:24Z',
    credentialSubject: {
      alsoKnownAs: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
      nickName: 'Bob',
    },
  };

  it('createProof', async () => {
    const key = await JsonWebKey.from(keys.key0 as any);
    const suite = new MerkleDisclosureProof2021({
      key,
      normalization: 'jsonPointer',
      date: '2021-08-22T19:36:43Z',
    });
    proof = await suite.createProof({
      document: {
        ...doc,
      },
      purpose: {
        update: (proof: any) => {
          proof.proofPurpose = 'assertionMethod';
          return proof;
        },
      },
      documentLoader,
    });
  });

  it('verifyProof', async () => {
    const suite = new MerkleDisclosureProof2021();
    const result = await suite.verifyProof({
      document: { ...doc },
      proof: { ...proof },
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

  it('deriveProof', async () => {
    const suite = new MerkleDisclosureProof2021();
    derivationResult = await suite.deriveProof({
      inputDocumentWithProof: { ...doc, proof },
      outputDocument: {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://w3id.org/security/suites/merkle-jws-2021/v1',
          {
            alsoKnownAs: 'https://www.w3.org/ns/activitystreams#alsoKnownAs',
            // nickName: 'https://www.w3.org/ns/activitystreams#nickName',
          },
        ],
        id: 'http://example.edu/credentials/3732',
        type: ['VerifiableCredential'],
        issuer: 'https://example.edu/issuers/14',
        issuanceDate: '2010-01-01T19:23:24Z',
        credentialSubject: {
          alsoKnownAs: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
          //   nickName: 'Bob',
        },
      },
      documentLoader,
    });
  });

  it('verify with selective disclosure', async () => {
    const suite = new MerkleDisclosureProof2021();
    // console.log(JSON.stringify(derivationResult, null, 2));
    const result = await suite.verifyProof({
      document: { ...derivationResult.document },
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
});
