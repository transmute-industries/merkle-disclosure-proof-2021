import { JsonWebKey, MerkleDisclosureProof2021 } from '../..';

import { keys, proofs, documentLoader } from '../../__fixtures__';

describe('MerkleDisclosureProof2021', () => {
  it('createProof', async () => {
    const key = await JsonWebKey.from(keys.key0 as any);
    const suite = new MerkleDisclosureProof2021({
      key,
      normalization: 'urdna2015',
      date: '2021-08-22T19:36:43Z',
      rootNonce: 'urn:uuid:d84cd789-4626-488d-834b-ceb075250d50',
    });
    const proof = await suite.createProof({
      document: {
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
      },
      purpose: {
        update: (proof: any) => {
          proof.proofPurpose = 'assertionMethod';
          return proof;
        },
      },
      documentLoader,
    });
    // console.log(JSON.stringify(proof));
    expect(proof).toEqual(proofs.proof3);
  });

  let derivationResult: any;

  it('can derive', async () => {
    const suite = new MerkleDisclosureProof2021();
    const inputDocumentWithProof = {
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
      proof: { ...proofs.proof3 },
    };
    const outputDocument = {
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
        // nickName: 'Bob',
      },
    };
    derivationResult = await suite.deriveProof({
      inputDocumentWithProof,
      outputDocument,
      documentLoader,
    });
    expect(derivationResult).toBeDefined();
    expect(derivationResult.document).toEqual({
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/security/suites/merkle-jws-2021/v1',
        {
          alsoKnownAs: 'https://www.w3.org/ns/activitystreams#alsoKnownAs',
        },
      ],
      id: 'http://example.edu/credentials/3732',
      type: 'VerifiableCredential',
      credentialSubject: {
        id: 'urn:bnid:_:c14n0',
        alsoKnownAs: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
      },
      issuanceDate: '2010-01-01T19:23:24Z',
      issuer: 'https://example.edu/issuers/14',
    });
  });

  describe('verify with full disclosure', () => {
    it('should fail without derivation', async () => {
      const suite = new MerkleDisclosureProof2021();
      const result = await suite.verifyProof({
        document: {
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
        },
        proof: { ...proofs.proof3 },
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

    it('should succeed with derivation', async () => {
      const suite = new MerkleDisclosureProof2021();
      const inputDocumentWithProof = {
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
        proof: { ...proofs.proof3 },
      };
      const outputDocument = {
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
      derivationResult = await suite.deriveProof({
        inputDocumentWithProof,
        outputDocument,
        documentLoader,
      });
      const result = await suite.verifyProof({
        document: derivationResult.document,
        proof: derivationResult.proof,
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

  it('verify with selective disclosure', async () => {
    const suite = new MerkleDisclosureProof2021();

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

  it('verifyProof fails when tampered', async () => {
    const suite = new MerkleDisclosureProof2021();
    const result = await suite.verifyProof({
      document: {
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
        },
        newProperty: 'cool',
      },
      proof: { ...proofs.proof3 },
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
