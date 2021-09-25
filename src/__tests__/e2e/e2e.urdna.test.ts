import { JsonWebKey, MerkleDisclosureProof2021 } from '../..';

import { keys, credentials, documentLoader } from '../../__fixtures__';

describe('urdna e2e', () => {
  let proof0: any;
  let inputDocumentWithProof: any;
  it('create', async () => {
    const key = await JsonWebKey.from(keys.key0 as any);
    const suite = new MerkleDisclosureProof2021({
      key,
      date: '2021-08-22T19:36:43Z',
      rootNonce: 'urn:uuid:d84cd789-4626-488d-834b-ceb075250d50',
      normalization: 'urdna2015',
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
    inputDocumentWithProof = {
      ...(await suite.normalize({
        document: {
          ...credentials.credential1,
        },
        documentLoader,
      })),
      proof: proof0,
    };
    expect(inputDocumentWithProof).toEqual({
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/security/suites/merkle-jws-2021/v1',
        {
          alsoKnownAs: 'https://www.w3.org/ns/activitystreams#alsoKnownAs',
          nickName: 'https://www.w3.org/ns/activitystreams#nickName',
        },
      ],
      id: 'http://example.edu/credentials/3732',
      type: 'VerifiableCredential',
      credentialSubject: {
        id: 'urn:bnid:_:c14n0',
        alsoKnownAs: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
        nickName: 'Bob',
      },
      issuanceDate: '2010-01-01T19:23:24Z',
      issuer: 'https://example.edu/issuers/14',
      proof: {
        type: 'MerkleDisclosureProof2021',
        created: '2021-08-22T19:36:43Z',
        verificationMethod:
          'did:key:z6MktxqTMmhYnpEmAWztj18MjKcX4pmKpiuJAoWCtiL4WjbD#z6MktxqTMmhYnpEmAWztj18MjKcX4pmKpiuJAoWCtiL4WjbD',
        proofPurpose: 'assertionMethod',
        normalization: 'urdna2015',
        proofs:
          'eJzNzkeOm1AAANC7zJZINBvD8mN6x9h8IMrC9F5M+3D6KEfIYqS5wNP7/QWi5U1e+XtLfsYiqINDoFOqsld/VsdU4rhiVJrejZDBggl4nWekdXuWAUCkZkYtWE1abE+jcaF80ndLxIiBN4PHuoNYKnWtIMM297GU1GUqeu1IBdDuMXJErjzpOub3vFfoCMRu+07258Yx5uiEMAiHyI8VAktph5PXzYJ29CgprvgQ7devL2Aec3BB97RuiMPiC3Y+UIfueuHvF7uAXqzTMt7x5lgo9U8ph43aME0jPxkwbDAYNTVVCBczibIw9vkW3/G5IG6onJcU8O2xdPwtTI9A0poqmMNpez2G3FXXJnxxtTDIUbq4K80q31l2OHyP3zOw+OayMXz7yvnP2G1Uxhz7w4tQtWr7ebaVktE/pfzYn3eqhkUiGz0kqwAq2U1h1JaP8AgofVLWhfHq7xMLZhDr4DIngm8oh1wbufmsCGudWGaEcZlD05mBKyKcDhXBA1IG3tP1Bf3IAe2EYjZkrtXmu1fo3AimpTxPk3YzER5c/b9lgcKGaHKNrmPYGDRA4Qmco+JO3HvXCqTAnnO7UsoBBf1PKb9oU2USXb8iOORrOeSW2de2fIpojV2V0jkeQLAuMHvlwOBDsSRCMuKsms9u09Ih0xRLmsEibFGSsZ+K524Ybb6A7yxLFIlv4UZXFHscIk5neEkmTTFWKBw/4QcvzrQ7YqnSLtFPKWdRrzEOdU7zaR+vhhaoEkr+27Pr3ao+o+drlHxAOxBVD2THsIi5Wg42KBf2dPTAttMSWM1BcoO7I7qxBDqrh7F6Ahkx70vFpUc1UwJubbChlueoGsxwtgZtWhJlbhObNtUO/jVsqkmLZONvi1hN4vDxaRQhIfa9bYHdeWFoWoVt5lSTkHxnQ5hVTNu2cVLXUxCeV9V5a6uYu/0JV7+gj7LTbSkagou0/xf95y/9ilPx',
        rootNonce: 'urn:uuid:d84cd789-4626-488d-834b-ceb075250d50',
        jws:
          'eyJhbGciOiJFZERTQSJ9.Ilk3ZUloYVNNaXZWYmJLUXRwaStrMHlFc2xGamlKd3A3WDltY1lSdDQ4WGM9Ig.ZXlKaGJHY2lPaUpGWkVSVFFTSXNJbUkyTkNJNlptRnNjMlVzSW1OeWFYUWlPbHNpWWpZMElsMTkuLmdnRE1FTlVfOVF6aU1YT2FLR2phTmowT3hGM0Q2dHFIS1JRM0ljQjhQVW51cDczNlJ4anJqVW1hbERwQ3N0Qno0ZjBkdzluTlpQZnZxcHZielY1NERR',
      },
    });
  });

  it('derive full and verify', async () => {
    const suite = new MerkleDisclosureProof2021();
    const derived = await suite.deriveProof({
      inputDocumentWithProof,
      outputDocument: credentials.credential1,
      documentLoader,
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

  it('derive selective and verify', async () => {
    const suite = new MerkleDisclosureProof2021();

    const outputDocument: any = JSON.parse(
      JSON.stringify(credentials.credential1)
    );
    delete outputDocument.credentialSubject.nickName;
    delete outputDocument['@context'][2].nickName;

    const derived = await suite.deriveProof({
      inputDocumentWithProof,
      outputDocument,
      documentLoader,
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
    expect(derived).toEqual({
      document: {
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
      proof: {
        type: 'MerkleDisclosureProof2021',
        created: '2021-08-22T19:36:43Z',
        verificationMethod:
          'did:key:z6MktxqTMmhYnpEmAWztj18MjKcX4pmKpiuJAoWCtiL4WjbD#z6MktxqTMmhYnpEmAWztj18MjKcX4pmKpiuJAoWCtiL4WjbD',
        proofPurpose: 'assertionMethod',
        normalization: 'urdna2015',
        proofs:
          'eJzNlsmO6kYUht+lt1yJmofsTDPPNA0GR1nUaIwNhmayifLuqV5lQxZRpKurkhflRUnn0z+c3/98s9nFFOXF2Wl5NO7ttzejFGNUGU8dI5iJcKSzmBEqjNFOcGABBtRTSwWHxHqvjEYOQ4kJFxq//fjnzflXWfrwZpRcFaSt9wJ+ndLNflO3sUXZ7La+DE62K2V66ufHRVKNRXSOlofl2O6L524TVXA4SYroNsGd4jnOF3Hvid+nnQYoW5PNx+0R6e5uNEzhtvDrhoWjHkpWj2oQxbNjA56qRe88GjXWx9YyHVWRXhTKPD7vkk1O82282ZbJWvdBw+K57N3u03iWfOyQTL9A8fbXjxdkHKYOQOkE4hhbyZVj1mDlkfUGCwCUMgAhCgQjgZeG3nuIPTbEQReA6ZdkJvVlQ6p3u89BPW2l4lJXh+p9lK4fZJbGSz3CveahNTml/f2vSwYFBFh4ZRHFxFGoFBIMUuu/WXlvHeAMO86VJ0wQQLUwBEAOHCQaECFektnmg5zlee+TReU93pyGA9sHi8YE7NLx48L1e/OSAl7tLlcbtYr6emjxra033WGebS7b8331UfrF4JZvV3LfLnuJvS5uWPR/LhkroadKBgZIKusR9JBqKkmwD8fKCiKpVkYGd7CgKBdAIciwEdI6SywFL8nMZfOh1SWatnJyZ61i5Vtfp8MdOVY/PpZJld2Gj+ezyPoO/7pkEJRcKqIwRMpqzBnUGjuhkMUcIhCuykJvhcTaIk6RdogSIQXzkmGG3EsyH4/Pd7SPU9MbH2OYbeK+4302KFpJM4n6R7Pbp+PV8f0sokukRxG5mPZ63K97+7GffGZgejsLdor1zseT+SVadKom3vbby6jrInWmq3idzKPiXGmxZTS7rxc0nnPACrRcDruPiWl/yP3/J4M1JMZzya1RXAMkiQNa0mAkYriCxGvmGfYGuvAXUBm0E8QlNTaYMaTtSzIrPBkwMxrRKi79bVf66eS4n/WeneqmFwM0kq0ojm7X2K18NG5tOzuwhYmc7luOn6+HajLp7DBrJI1r35yO5/TzMR4X/hr9XDKKaAi/xQJp+KDD0irsQuwQoLkSQCqGEUGcKRMyCALCQjJrjoSz0ghMX5LpIti8b+84Q6KuO03smjto8vSUVdvT1/armT7todbdbEiSX5cMCnXsmQ8e4SKMD5wWCDGnPBAwaARA6LUxzIW09YwbB02gqAghyAmI5GvNuOQ4ZHP0PF+es3qV4zbaxd21Ws72j2n2dVquh6hXx7NNZ7CMXF1eO36wK2fR7iqe89FmNrO7aJrXUJaLR4XzaRu7fXnKPqNexRTJpK2zC2o3p/c4R9fP02DMymcxxpNpF03uZ2Hz7BG9ntYwbnWoE6yZhFwiEqJVG+qtVw4Dj3iICRbSNCwsSBkeKhkRCqwx3FJq/2XaGcptau4tfu1k5075tcZVUrX1enm/xocnYRgP4sLNs3Pb/NxpgQ7NCrhglEDMOf9eNKy2GiGNvwOCMQGNQ15D4FAwAVBM8u8+5gZ4gV7vHe3LoDG830/nwe3Zbn/SwVwNbx2/OD7j2zrF9e4wmnWTckO6j/82wR9/A+TWVJA=',
        jws:
          'eyJhbGciOiJFZERTQSJ9.Ilk3ZUloYVNNaXZWYmJLUXRwaStrMHlFc2xGamlKd3A3WDltY1lSdDQ4WGM9Ig.ZXlKaGJHY2lPaUpGWkVSVFFTSXNJbUkyTkNJNlptRnNjMlVzSW1OeWFYUWlPbHNpWWpZMElsMTkuLmdnRE1FTlVfOVF6aU1YT2FLR2phTmowT3hGM0Q2dHFIS1JRM0ljQjhQVW51cDczNlJ4anJqVW1hbERwQ3N0Qno0ZjBkdzluTlpQZnZxcHZielY1NERR',
      },
    });
  });
});
