import { getProofs, verifyProofs, deriveProofs } from '../merkle';

const createProof = async (document: any, options: any) => {
  const { objectToMessages } = options;
  const messages = await objectToMessages(document, options);

  const proof = getProofs(messages, options.rootNonce);
  return {
    type: 'MerkleDisclosureProof2021',
    ...proof,
  };
};

const deriveProof = async (
  outputDocument: any,
  inputDocument: any,
  proof: any,
  options: any
) => {
  const { objectToMessages, messagesToObject } = options;
  const inputMessages = await objectToMessages(inputDocument, options);
  const outputMessages = await objectToMessages(outputDocument, options);

  const outputDocumentFromMessages = await messagesToObject(outputMessages, {
    ...options,
    context: outputDocument['@context'],
  });

  const discloseIndexes = inputMessages
    .map((m: any, i: any) => {
      if (outputMessages.includes(m)) {
        return i;
      }
      return undefined;
    })
    .filter((m: any) => {
      return m !== undefined;
    });

  const disclosedProofs = deriveProofs(
    discloseIndexes,
    proof.proofs,
    inputMessages,
    proof.rootNonce
  );
  const derivedProof = {
    ...proof,
    proofs: disclosedProofs,
  };
  delete derivedProof.rootNonce;
  delete outputDocumentFromMessages.proof;
  return { document: outputDocumentFromMessages, proof: derivedProof };
};

const verifyProof = async (document: any, proof: any, options: any) => {
  const { objectToMessages } = options;
  const messages = await objectToMessages(document, options);
  return { verified: verifyProofs(messages, proof.proofs, proof.root) };
};

export { createProof, deriveProof, verifyProof };
