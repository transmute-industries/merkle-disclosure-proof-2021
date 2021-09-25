// import { MerkleDisclosureProof2021 } from '../..';

import {
  credentials,
  proofs,
  // documentLoader
} from '../../__fixtures__';

it.skip('can derive and verify', async () => {
  // const suite = new MerkleDisclosureProof2021();
  const inputDocumentWithProof = {
    ...credentials.credential1,
    proof: proofs.proof0,
  };
  console.log(JSON.stringify(inputDocumentWithProof, null, 2));

  // const derivationResult = await suite.deriveProof({
  //   inputDocumentWithProof,
  //   outputDocument,
  //   documentLoader,
  //   rootNonce: 'urn:uuid:d84cd789-4626-488d-834b-ceb075250d50',
  // });

  // const result = await suite.verifyProof({
  //   document: {
  //     ...derivationResult.document,
  //   },
  //   proof: { ...derivationResult.proof },
  //   purpose: {
  //     update: (proof: any) => {
  //       proof.proofPurpose = 'assertionMethod';
  //       return proof;
  //     },
  //   },
  //   documentLoader,
  // });
  // expect(result.verified).toEqual(true);
});
