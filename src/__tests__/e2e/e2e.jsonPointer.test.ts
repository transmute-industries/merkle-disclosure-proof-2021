import { JsonWebKey, MerkleDisclosureProof2021 } from '../..';

import { keys, credentials, documentLoader } from '../../__fixtures__';

describe('jsonPointer e2e', () => {
  let proof0: any;
  let inputDocumentWithProof: any;
  it('create', async () => {
    const key = await JsonWebKey.from(keys.key0 as any);
    const suite = new MerkleDisclosureProof2021({
      key,
      date: '2021-08-22T19:36:43Z',
      rootNonce: 'urn:uuid:d84cd789-4626-488d-834b-ceb075250d50',
      normalization: 'jsonPointer',
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
        normalization: 'jsonPointer',
        proofs:
          'eJzN1Meus8gWhuF7+aduCVPkYZEx2ASTWz0gm1gmmXD1vc8lnJa25PGSPj2DV+vvP7A0r86Eg0mVg0YzQ0ZMzb7WF6BLSYK9HLYRQe4l+ngrTZhrpoXiBZnvvMpRxzs8Ud/E26bYLeZN8lalCMiZtZ5GBiO8Nht+6Ti6vY+66RTQpnKN3FSXCD9mkl9i3ucoTlNJB8bBxukbKjN6o1/tdhZ39p3iDV6OQqfRvVohZy+4WLI+5Z+//kA+llFJFdJxHDAxzJmLgRwC+pqVA6tFgrgND3g54DZu67eQswuhuMcNKq4PSR61YhfNHWWFyQHueSVMKYmt6TxbmddDfmC4GFWix8zOqt/zorVWy+UfD8bYIRnPL+osN54TMPr8TbJSPm8DprrP+0wHjXleFycQClskWAZoBthJCfdcZWbWmf4Wsp3wia99zEswpt3WjderNmBMOuvyEnRoG+iUkVL/phrUAb1rr5OcPvY1uVaZT/hl1Qc//azKp8yxkf/pSuroexv2GISRsWGsK8jqTl4sJ7rx/QAQfz9erOr28/YhXJxjKVmRo/+XbFZ+zFkBpq3swrGNhnvkQvcroo8PC0PybUtjkC4ifcrtt5Bz4W7xL7+vbFcFkGCzYuBkbZre5yqeQ6UnmAvlrH3p1gMafErYZY5o2aAgHY7WLPAzqI8i9ChWpOAwUSybkGtPFL9Jhp2ysSVWtgFw7rtv8qIW4NemeO2XBaOZiSB8dIsvm/kz/SVk/26Zc/MwR5THsmv1PFudeCiOlYt4rbX5n+tztYZ4MVJY7NmqYzJ3KWdcXguMWqyz70AQ+eNkmNS9zgZxyw8cUx+wZJ8ob3QmedoYra6L4p48Qh5hAu2Nk5+9bnMGBrJz6h0U6L4y5zZPmTmc4Ph5GLYSFlIMgIkd4OdtnUmgRTS/Xab/kcWsVjx0vLCgpnirsoZb8XDfVyBSJo2HFjlHmotHFZL167eQXb8FYECqvGeS7TaBUjleNJeLhb/qVSuf9VMA9kDrKLxB8ejJbu+8ATbNns1SLe8vVRJxFpWFyEX4qOc1vMm5lVe/SYafFXi9KijnwcDctLymfKv71DzqUCKd4X3xcLUcwNBf028hJ7nFXN3ExjBryx6yGhqb6tjZVsO17sMunzUOxeD0SVyBufsyeCraa6dlcJw2JFrQX2q6yaQur64tVeqDJz4vrDNtKE4678PkpsHeR59ZqyhYNPaa3bzDsAgJzEJZHwdylv/Qsi8DcWTe8nZctZh/uACwxRRcjg73mYMlXNgqV6z4rCn2LWQNDNUhxkh5zEYPdEg6JUcjAljjsTt1VPSptODduHsu9muMf/4FHUBlsg==',
        rootNonce: 'urn:uuid:d84cd789-4626-488d-834b-ceb075250d50',
        jws:
          'eyJhbGciOiJFZERTQSJ9.ImJpWWtwYmpJNVRtSGIxcmYwUUxTYjdXNU9WUUNxR1R5Z1lRajRZNE5udjQ9Ig.ZXlKaGJHY2lPaUpGWkVSVFFTSXNJbUkyTkNJNlptRnNjMlVzSW1OeWFYUWlPbHNpWWpZMElsMTkuLlZYVzlBSHhzSWlmOVFuYUJzenJlNW5sa0FaQk9ZX21vTWZKUXkyaUE0ZW9tZnBjcDNXdHZKQURZZ1Mzay12VjZ0UG5taExmYWxNY1g0b0lMSjlRY0JR',
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
      inputDocumentWithProof,
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
        normalization: 'jsonPointer',
        proofs:
          'eJzNl0mv4swZhf9Lb/kk1zxkZwNmvNjQzFEWNTIaXzBgTJT/nupVNuyStHpp2XrlenTOeU/9/Z8/7KEy57JydlJejPvxtx9KEy0BclBSQpihjFjGuJKOcgSdplwgiAUS1kkNAYHUS6U0tk4wDJwhP/76z8z8VpY+zIx9BmY3iG79dHUcZGve0VlxGN3RqKtUtJ+JYwfZhRpdhz6L7SDLy+29zL7tzpbnZJbgw7AzrHvTU7S4pfVOlyg1+eM9NvEGHrJjcj9Ldvq6jrKZi6fUDkjdn+P1M1O2tU2WkspBn8zi7aqWo7r0htVsf6rf7kt8a3iE/to+D1jR35Wzl5Pbbv70P/711wcyiGDgKWZQEiihsswHNo5h6aFBnjFqFbEWKK68d0gEZA4gKbDlwGuv5UcyyTYtPXXdpmliNc4quUXpGjFg/EUMNu1OfZnErSaur/XjzyXjLGBQKICsUDj8OxROSo4CBCmM90Rop5mCgDsmsdXaBVISGs4cVpC5z5oxLdybN8O4N1/GJClPnfOmOtN8rRr0ZXftmybRQ1dVbhZFnFy43Ja7zoJXs8foy7pT/sjnyWTCx6+YbKs9ffs6ke2IvX8vGc61cJxpaLkEAnIeTES4Co8WSa290TSYRtqgKK2Vtk5DT6zC3nHuvMMfyUxVopaDZ9ZaXfW5Pl8BGFwirqtRel+dy/rCNO/q5bA/pk28AMWIyNG1OJDHzizx0u+KVZDWo/f0NromQXLdM/s6rYsojjfjOhLzdtp/kVY+2wyT4oLK5KvZi/68qOonnkMpaNpLN/89GStk0Ao1YWDQAFJYQAAM8IJwayX5JRGjPWFSGaw1gBAZSZ2zgjEX/GQ+ksl2y63MV9HgIe5SHAdwQe6seJSseYp4Tb6n3etK3zvsnZ7+XDLECogQCrLgVJiQsBoib60BCAumHaJKcuMdpBxwSIVC1vwi6LGlNHxJP5Kx7a882S+L3XTeRzEWxl1kOrjdvt+PzvuyG6loHqfmtB/lk3icaDz1tmTpmMZsfc2rdlKhQ+PWCyo6NL7cqBCKPArsfi8ZbiG3hEGkqQpuEtQ7KqBhkjLlZEgbb7hEKoABAFpEtWCESEa088Zgzz6Sic+9WvjIn1Zo9vVaZklnsILg6Pav1j1i/IbxshxuW3UWTvDHksFKOwM1NZ5QH7h4YaETWmqpKFRBTfyXozglv2wFiEVKhIxzIZqtDyvrs5uWX3lWHSfZtbTbdJ4Xidi94bpz3c3LZHCaJuHtz0d+2d7HOnYv8xhFqWz5CqYPF9F7/i7OaLVZXm/jjH4dzKVT2wZG/Unsxc/SHkdc/ZxGrP+49+bvpCwXOEODb0ier8PJ8niVzt6jc9xmxS6rTlbzan2Lr8/JeNpbu+4WoSxqUFgDb7UabFhSt26fyQAaGIQEDiEiOJBQKwA0RUCHlsOcpEZhbDwygRe3ykgDQ9Nh3HsMdVhp4COZ+fKE0KXspy/Tnc6Pq95utthU/p7D/eEx8D8PP9toemGjcj2MO01Bzq/z4hIfjy9TdQ/pa9/vdqAovevIDbyO7CEepja3u99LRjhAmDYslBfurUQaOBfKnUccIuUotsRYGuqgxyGRGQTSCue4Ro4ob5DSn930fKBF0W/33g2PbZYvjv67/7odJ4d1l8wu360F7PsLuhRA/7lkQvYSbXXYRVA7DKhjSATnUA040KH+siAoZYE1XDEhiQJce6WZddA4hCD6SEbZnIO5mkZRXptJ2l+P6/5saupD/DgU67OtBrLcoveSwF5s5/txQjevw+zEIWTjLmuP9n1dp2SUPubT7q4/SfBzH52zady5jZJlrIaDuFiWz2qwo7E7Th9muGjGOe6iqu0PTVPO7v8TN4WCS2FYx2HfCIPDHSHYSwczEUnDnUA64rmxCEATwBkCQvZiEyKahA7IfBjxiUxnmaLOlX+ndQMG22QyR0i426rVnOGSNwLP41MPRO750NGfS8ZKLgUJnUYppwRwniHtg4YIDSYKOcw8NoZBrJGBxErgsAxdmONQAzH3WHwkM0CXXdPZlr1JNS7QKCYzL1mJUX5tXrPDxhW6e4fn62sxj/5/p/3HvwH+5o5M',
        jws:
          'eyJhbGciOiJFZERTQSJ9.ImJpWWtwYmpJNVRtSGIxcmYwUUxTYjdXNU9WUUNxR1R5Z1lRajRZNE5udjQ9Ig.ZXlKaGJHY2lPaUpGWkVSVFFTSXNJbUkyTkNJNlptRnNjMlVzSW1OeWFYUWlPbHNpWWpZMElsMTkuLlZYVzlBSHhzSWlmOVFuYUJzenJlNW5sa0FaQk9ZX21vTWZKUXkyaUE0ZW9tZnBjcDNXdHZKQURZZ1Mzay12VjZ0UG5taExmYWxNY1g0b0lMSjlRY0JR',
      },
    });
  });
});
