import { createProof, deriveProof, verifyProof } from '../suite';

import { naive } from '../normalization';

import { credentials } from '../../__fixtures__';

const { objectToMessages, messagesToObject } = naive;

const options = { objectToMessages, messagesToObject };

const credential = { ...credentials.credential0 };

import derivedCredential from '../__fixtures__/derived-0.json';

it('full disclosure', async () => {
  const inputDocument = { ...credential };
  const proof = await createProof(credential, options);
  const outputDocument = { ...credential };
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
