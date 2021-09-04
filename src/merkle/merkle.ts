import crypto from 'crypto';
import pako from 'pako';
import MerkleTools from '@settlemint/merkle-tools';

const sha256 = (data: any) => {
  const v = crypto.createHash('sha256').update(data, 'utf8');
  return v.digest('hex');
};

const directionToBin: any = {
  left: '00',
  right: '01',
};

const binToDirection: any = {
  '00': 'left',
  '01': 'right',
};

function sliceIntoChunks(arr: Buffer, chunkSize: number) {
  const res = [];
  for (let i = 0; i < arr.length; i += chunkSize) {
    const chunk = arr.slice(i, i + chunkSize);
    res.push(chunk);
  }
  return res;
}

// compression to eliminate duplicate leaves from proofs
const compressProofs = (proofs: any[]) => {
  const encodedProofs = proofs
    .map(({ proof }) => {
      return Buffer.concat(
        proof.map((v: any) => {
          const [direction] = Object.keys(v);
          const dir = Buffer.from(directionToBin[direction], 'hex');
          const value = Buffer.from(v[direction], 'hex');
          const binary = Buffer.concat([dir, value]);
          return binary;
        })
      );
    })
    .map(v => {
      return v.toString('base64');
    });

  return Buffer.from(
    pako.deflate(Buffer.from(JSON.stringify(encodedProofs)))
  ).toString('base64');
};

const expandProofs = (proofs: string) => {
  const encodedProofs = JSON.parse(
    Buffer.from(
      pako.inflate(Uint8Array.from(Buffer.from(proofs, 'base64')))
    ).toString()
  );
  return encodedProofs.map((p: any) => {
    const parts = sliceIntoChunks(Buffer.from(p, 'base64'), 33);
    const proof = [];
    for (let i = 0; i < parts.length; i++) {
      const direction = binToDirection[`0${parts[i][0]}`];
      const value = parts[i].slice(1).toString('hex');
      proof.push({
        [direction]: value,
      });
    }
    return { proof };
  });
};

const getProofs = (messages: string[]) => {
  const merkleTools = new MerkleTools();
  const leaves = messages.map(sha256);
  merkleTools.addLeaves(leaves);
  merkleTools.makeTree();
  const proofs = leaves.map((_v, i) => {
    return { proof: merkleTools.getProof(i) };
  });
  const merkleRoot = merkleTools.getMerkleRoot();
  merkleTools.resetTree();

  if (!merkleRoot) {
    throw new Error('could not get merkleRoot.');
  }

  return { root: merkleRoot.toString('hex'), proofs: compressProofs(proofs) };
};

const deriveProofs = (discloseIndexes: number[], proofs: string) => {
  const encodedProofs = JSON.parse(
    Buffer.from(
      pako.inflate(Uint8Array.from(Buffer.from(proofs, 'base64')))
    ).toString()
  );
  const disclosedProofs = encodedProofs.filter((_p: any, i: any) => {
    return discloseIndexes.includes(i);
  });

  return Buffer.from(
    pako.deflate(Buffer.from(JSON.stringify(disclosedProofs)))
  ).toString('base64');
};

const verifyProofs = (messages: string[], proofs: string, root: string) => {
  const merkleTools = new MerkleTools();
  const expandedProofs = expandProofs(proofs);

  if (expandedProofs.length !== messages.length) {
    throw new Error('Number of proofs does not match number of messages');
  }

  const validations = messages.map((m, i) => {
    if (!expandedProofs[i]) {
      console.error('No proof for message: ' + m);
      console.error(JSON.stringify(messages, null, 2));
      console.error(JSON.stringify(expandedProofs, null, 2));
    }
    return merkleTools.validateProof(expandedProofs[i].proof, sha256(m), root);
  });

  return validations.every((v, i) => {
    if (!v) {
      console.log('failed to verify: ' + messages[i]);
    }
    return v;
  });
};

export { getProofs, deriveProofs, verifyProofs };
