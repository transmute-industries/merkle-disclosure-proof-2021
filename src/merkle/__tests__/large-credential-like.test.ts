import { createProof, deriveProof, verifyProof } from '../suite';
import { naive } from '../normalization';

import credential from '../__fixtures__/credential-large-0.json';
import disclosedCredential from '../__fixtures__/disclose-large-0.json';
import derivedCredential from '../__fixtures__/derived-large-1.json';

const { objectToMessages, messagesToObject } = naive;

const options = {
  objectToMessages,
  messagesToObject,
  rootNonce: 'urn:uuid:d84cd789-4626-488d-834b-ceb075250d50',
};

it.skip('selective disclosure of large credential', async () => {
  const inputDocument = { ...credential };
  const proof = await createProof(credential, options);
  const outputDocument = { ...disclosedCredential };
  const derived = await deriveProof(
    outputDocument,
    inputDocument,
    proof,
    options
  );
  const { verified } = await verifyProof(
    derived.document,
    derived.proof,
    options
  );
  expect(verified).toBe(true);
  expect({ ...derived.document, proof: derived.proof }).toEqual(
    derivedCredential
  );
});
