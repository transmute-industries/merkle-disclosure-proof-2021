import { JsonWebKey, MerkleDisclosureProof2021 } from '../..';

import { keys, documentLoader } from '../../__fixtures__';

// let proof: any;

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

let documentWithProof: any;
let derivedDocumentWithProof: any;

describe.skip('MerkleDisclosureProof2021 with URDNA 2015', () => {
  it('createProof', async () => {
    const suite = new MerkleDisclosureProof2021({
      key: await JsonWebKey.from(keys.key0 as any),
      normalization: 'urdna2015',
      date: '2021-08-22T19:36:43Z',
      rootNonce: 'urn:uuid:d84cd789-4626-488d-834b-ceb075250d50',
    });

    const proof = await suite.createProof({
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

    expect(proof).toBeDefined();

    const normalizedDoc = await suite.normalize({
      document: { ...doc },
      documentLoader,
    });

    documentWithProof = { ...normalizedDoc, proof };
  });

  it('deriveProof', async () => {
    const suite = new MerkleDisclosureProof2021();
    derivedDocumentWithProof = await suite.deriveProof({
      inputDocumentWithProof: documentWithProof,
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
        type: 'VerifiableCredential',
        credentialSubject: {
          id: 'urn:bnid:_:c14n0',
          alsoKnownAs: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
          // nickName: 'Bob',
        },
        issuanceDate: '2010-01-01T19:23:24Z',
        issuer: 'https://example.edu/issuers/14',
      },
      documentLoader,
    });
  });

  it('verify with selective disclosure', async () => {
    const suite = new MerkleDisclosureProof2021();
    // console.log(JSON.stringify(derivationResult, null, 2));
    const result = await suite.verifyProof({
      document: { ...derivedDocumentWithProof.document },
      proof: { ...derivedDocumentWithProof.proof },
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
