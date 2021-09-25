import { JsonWebKey, MerkleDisclosureProof2021 } from '../..';

import { keys, credentials, documentLoader } from '../../__fixtures__';

describe('naive e2e', () => {
  let proof0: any;
  let inputDocumentWithProof: any;
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
    inputDocumentWithProof = {
      ...credentials.credential1,
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
      type: ['VerifiableCredential'],
      issuer: 'https://example.edu/issuers/14',
      issuanceDate: '2010-01-01T19:23:24Z',
      credentialSubject: {
        alsoKnownAs: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
        nickName: 'Bob',
      },
      proof: {
        type: 'MerkleDisclosureProof2021',
        created: '2021-08-22T19:36:43Z',
        verificationMethod:
          'did:key:z6MktxqTMmhYnpEmAWztj18MjKcX4pmKpiuJAoWCtiL4WjbD#z6MktxqTMmhYnpEmAWztj18MjKcX4pmKpiuJAoWCtiL4WjbD',
        proofPurpose: 'assertionMethod',
        normalization: 'naive',
        proofs:
          'eJzN1Leus1gABOB3+VtWIsOhPGSOjYkmrbYATLABk0x8+r37CFtcydV0o68Yzd9/YEzlhL3QOSlKPUvF4q3P+IncOm5+5QM+k/tUcKvRQBT2sDT4T616ceCpWk4WaH4CjVsIxL/7GSoIWLRWslM5cm8D5gIl8MlOr9N+CdmwPT5Lms/zqYMRgZrPGuPYXxuVIR3BdGBkI1kFsj/T3qF3+OndbbhYsatdZ+IlCUutbE/w6pTsz19/oNlWfjOKdBMZtqfF15J1QUQOdGw0CavEmtnnelYNTC7r30IutBdfn62tVQVSWoHHC7AFvorz1mZO735MjzqV2o5thBs0IwEH9pXBk+TYj+nWm7VvSxSCbBJxAx8GPeLNKa3nQvtN8mWzdaY8VPnB7VJTcw6pyxJn4uGIwvN4VKf+k1nZu8f6LeS8anWmvveKsS33KJTuZ2Duw3H3u9AYhuTyNOiuqy44y/xUv5yukDebOl3Ci8djxJO1YJUHxjxzGXEEm5XAtsWUXjxoT/i0lhCwUD/f1JNQP5SgtDkRklZnUh1hPIeEn9pdBPz/JUvDe5bbbX0t8udKg5NUDGoSXpRCX6W4IMr7zs3hnT9nM/oW8gPCBML+bQgUzAbZ8LmBIEr9FE7681h8cP/oIfbKHcGtoM42bjgewLUfydqUWaOVaeiNz4v1ANg96imAIl68GEzR/SbZvC3tdMNphzs/qtEhY+yhSGT3oHVf1LB27nLtYCuhzLh9Czm41jo5zt6Str3o5C2MBYa8BZ28osoJW0Y1cRDny3uiRJh5XGuH880yf55OzO3eAStmu8bhTWeja2p5d4OI7vL3SELfrFpcneXK0a9MGQAJbRPqXwXQ0OwGjnXpTPRzS5iNF1AZreo9gNAT00eoEsjukpDksYneaEx4wrOoQFgGqkWy6D8ymhgJexeEh8hIVft1Okh4yxLLEvNjavyu7omjChET3epvIftiajqGJ30INFYVpkExWKUKKmSqjmbaMnjpWVfPwf1ZgQiZlQHcSdGpeEbtnsKcYKJruCdPcGnoDUxespLVrPrbb5It0pwdhzKPGcPbvX+q645zzOtheZFOvocb8Dmj/EhacPO/hZwSh0zRwI0VgyVWNy9tHH3s4roiIW/wEsdGmWNz27qwOIz9GqEhUcfR9Q5hsSiZkZUYCquWXo/EX2hMHGkGzSqjQcPT1JaCjyxnjtQdHywAylJjKV5chYGsDwtrZ5pgLID+/5ZnuvJXUTSvJFsLtAUw5sQLi8jyM7pMU+AV4/QpqeBtxN9ChuPzhOA9xDvcUVTfAN287x/hvgDKol9gap21+ggdW5nerzH++Rf+O1o8',
        rootNonce: 'urn:uuid:d84cd789-4626-488d-834b-ceb075250d50',
        jws:
          'eyJhbGciOiJFZERTQSJ9.Ino3RERPMmRPaC9HVDBGcFJTUkozWnNzZW1zTmZMeXpaa1ZTYmNZc29QTlk9Ig.ZXlKaGJHY2lPaUpGWkVSVFFTSXNJbUkyTkNJNlptRnNjMlVzSW1OeWFYUWlPbHNpWWpZMElsMTkuLlF3d0FiVGFVVFZTSkdPcXlDbWFIRmJYOUtVYWJsVkhfSWpGZlROWGpCZ1pfTWlYamYxMHk4RkFna2c3WFZWd3l0bThsUUg2UE12UkdmdkRGYXM4REJn',
      },
    });
  });

  it('derive full and verify', async () => {
    const suite = new MerkleDisclosureProof2021();
    const derived = await suite.deriveProof({
      inputDocumentWithProof,
      outputDocument: credentials.credential1,
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
      inputDocumentWithProof: {
        ...credentials.credential1,
        proof: proof0,
      },
      outputDocument,
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
        type: ['VerifiableCredential'],
        issuer: 'https://example.edu/issuers/14',
        issuanceDate: '2010-01-01T19:23:24Z',
        credentialSubject: {
          alsoKnownAs: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
          // nickName: 'Bob',
        },
      },
      proof: {
        type: 'MerkleDisclosureProof2021',
        created: '2021-08-22T19:36:43Z',
        verificationMethod:
          'did:key:z6MktxqTMmhYnpEmAWztj18MjKcX4pmKpiuJAoWCtiL4WjbD#z6MktxqTMmhYnpEmAWztj18MjKcX4pmKpiuJAoWCtiL4WjbD',
        proofPurpose: 'assertionMethod',
        normalization: 'naive',
        proofs:
          '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',
        jws:
          'eyJhbGciOiJFZERTQSJ9.Ino3RERPMmRPaC9HVDBGcFJTUkozWnNzZW1zTmZMeXpaa1ZTYmNZc29QTlk9Ig.ZXlKaGJHY2lPaUpGWkVSVFFTSXNJbUkyTkNJNlptRnNjMlVzSW1OeWFYUWlPbHNpWWpZMElsMTkuLlF3d0FiVGFVVFZTSkdPcXlDbWFIRmJYOUtVYWJsVkhfSWpGZlROWGpCZ1pfTWlYamYxMHk4RkFna2c3WFZWd3l0bThsUUg2UE12UkdmdkRGYXM4REJn',
      },
    });
  });
});
