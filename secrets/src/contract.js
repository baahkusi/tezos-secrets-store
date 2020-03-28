export const SecretStore = [
    {
      "prim": "storage",
      "args": [
        {
          "prim": "pair",
          "args": [
            { "prim": "map", "args": [ { "prim": "bytes" }, { "prim": "string" } ], "annots": [ "%SecretStore" ] },
            { "prim": "pair", "args": [ { "prim": "bytes", "annots": [ "%hashedProof" ] }, { "prim": "int", "annots": [ "%nonce" ] } ] }
          ]
        }
      ]
    },
    {
      "prim": "parameter",
      "args": [
        {
          "prim": "pair",
          "args": [
            { "prim": "string", "annots": [ "%encryptedData" ] },
            { "prim": "pair", "args": [ { "prim": "bytes", "annots": [ "%nexthashedProof" ] }, { "prim": "bytes", "annots": [ "%proof" ] } ] }
          ]
        }
      ]
    },
    {
      "prim": "code",
      "args": [
        [
          { "prim": "DUP" },
          { "prim": "CDR" },
          { "prim": "SWAP" },
          { "prim": "CAR" },
          { "prim": "SWAP" },
          { "prim": "DUP" },
          { "prim": "DUG", "args": [ { "int": "2" } ] },
          { "prim": "CDR" },
          { "prim": "CAR" },
          { "prim": "SWAP" },
          { "prim": "DUP" },
          { "prim": "DUG", "args": [ { "int": "2" } ] },
          { "prim": "CDR" },
          { "prim": "CDR" },
          { "prim": "BLAKE2B" },
          { "prim": "COMPARE" },
          { "prim": "EQ" },
          {
            "prim": "IF",
            "args": [
              [ [] ],
              [ [ { "prim": "PUSH", "args": [ { "prim": "string" }, { "string": "WrongCondition: sp.blake2b(params.proof) == self.data.hashedProof" } ] }, { "prim": "FAILWITH" } ] ]
            ]
          },
          { "prim": "SWAP" },
          { "prim": "DUP" },
          { "prim": "DUG", "args": [ { "int": "2" } ] },
          { "prim": "CAR" },
          { "prim": "SWAP" },
          { "prim": "DUP" },
          { "prim": "DUG", "args": [ { "int": "2" } ] },
          { "prim": "CAR" },
          { "prim": "PACK" },
          { "prim": "BLAKE2B" },
          { "prim": "MEM" },
          {
            "prim": "IF",
            "args": [
              [
                [
                  { "prim": "PUSH", "args": [ { "prim": "string" }, { "string": "WrongCondition: ~ (self.data.SecretStore.contains(sp.blake2b(sp.pack(params.encryptedData))))" } ] },
                  { "prim": "FAILWITH" }
                ]
              ],
              [ [] ]
            ]
          },
          { "prim": "SWAP" },
          { "prim": "DUP" },
          { "prim": "DUG", "args": [ { "int": "2" } ] },
          { "prim": "DUP" },
          { "prim": "CDR" },
          { "prim": "SWAP" },
          { "prim": "CAR" },
          { "prim": "DIG", "args": [ { "int": "2" } ] },
          { "prim": "DUP" },
          { "prim": "DUG", "args": [ { "int": "3" } ] },
          { "prim": "CAR" },
          { "prim": "SOME" },
          { "prim": "DIG", "args": [ { "int": "3" } ] },
          { "prim": "DUP" },
          { "prim": "DUG", "args": [ { "int": "4" } ] },
          { "prim": "CAR" },
          { "prim": "PACK" },
          { "prim": "BLAKE2B" },
          { "prim": "UPDATE" },
          { "prim": "PAIR" },
          { "prim": "DUG", "args": [ { "int": "2" } ] },
          { "prim": "SWAP" },
          { "prim": "DROP" },
          { "prim": "SWAP" },
          { "prim": "DUP" },
          { "prim": "DUG", "args": [ { "int": "2" } ] },
          { "prim": "DUP" },
          { "prim": "CAR" },
          { "prim": "SWAP" },
          { "prim": "CDR" },
          { "prim": "CAR" },
          { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "1" } ] },
          { "prim": "DIG", "args": [ { "int": "4" } ] },
          { "prim": "DUP" },
          { "prim": "DUG", "args": [ { "int": "5" } ] },
          { "prim": "CDR" },
          { "prim": "CDR" },
          { "prim": "ADD" },
          { "prim": "SWAP" },
          { "prim": "PAIR" },
          { "prim": "SWAP" },
          { "prim": "PAIR" },
          { "prim": "DUG", "args": [ { "int": "2" } ] },
          { "prim": "SWAP" },
          { "prim": "DROP" },
          { "prim": "SWAP" },
          { "prim": "DUP" },
          { "prim": "DUG", "args": [ { "int": "2" } ] },
          { "prim": "DUP" },
          { "prim": "CAR" },
          { "prim": "SWAP" },
          { "prim": "CDR" },
          { "prim": "CDR" },
          { "prim": "DIG", "args": [ { "int": "2" } ] },
          { "prim": "DUP" },
          { "prim": "DUG", "args": [ { "int": "3" } ] },
          { "prim": "CDR" },
          { "prim": "CAR" },
          { "prim": "PAIR" },
          { "prim": "SWAP" },
          { "prim": "PAIR" },
          { "prim": "DUG", "args": [ { "int": "2" } ] },
          { "prim": "DROP", "args": [ { "int": "2" } ] },
          { "prim": "NIL", "args": [ { "prim": "operation" } ] },
          { "prim": "PAIR" }
        ]
      ]
    }
  ];

export function SecretStoreStorage(initialNonce, initialHashedProof) {
    
    const storage = { "prim": "Pair", "args": [ [], { "prim": "Pair", "args": [ { "bytes": `${initialHashedProof}` }, { "int": `${initialNonce}` } ] } ] };
    return storage;
}

export const SecretStoreMichelson = `parameter (pair (pair (string %encryptedData) (bytes %nexthashedProof)) (bytes %proof));
storage   (pair (pair (map %SecretStore bytes string) (bytes %hashedProof)) (int %nonce));
code
  {
    DUP;
    CDR;
    SWAP;
    CAR;
    SWAP;
    DUP;
    DUG 2;
    CADR;
    SWAP;
    DUP;
    DUG 2;
    CDR;
    BLAKE2B;
    COMPARE;
    EQ;
    IF
      {}
      {
        PUSH string "WrongCondition: sp.blake2b(params.proof) == self.data.hashedProof";
        FAILWITH;
      };
    SWAP;
    DUP;
    DUG 2;
    CAAR;
    SWAP;
    DUP;
    DUG 2;
    CAAR;
    PACK;
    BLAKE2B;
    MEM;
    IF
      {
        PUSH string "WrongCondition: ~ (self.data.SecretStore.contains(sp.blake2b(sp.pack(params.encryptedData))))";
        FAILWITH;
      }
      {};
    SWAP;
    DUP;
    DUG 2;
    DUP;
    CDR;
    SWAP;
    CAR;
    DUP;
    CDR;
    SWAP;
    CAR;
    DIG 3;
    DUP;
    DUG 4;
    CAAR;
    SOME;
    DIG 4;
    DUP;
    DUG 5;
    CAAR;
    PACK;
    BLAKE2B;
    UPDATE;
    PAIR;
    PAIR;
    DUG 2;
    SWAP;
    DROP;
    SWAP;
    DUP;
    DUG 2;
    CAR;
    PUSH int 1;
    DIG 3;
    DUP;
    DUG 4;
    CDR;
    ADD;
    SWAP;
    PAIR;
    DUG 2;
    SWAP;
    DROP;
    SWAP;
    DUP;
    DUG 2;
    DUP;
    CDR;
    SWAP;
    CAAR;
    DIG 2;
    DUP;
    DUG 3;
    CADR;
    SWAP;
    PAIR;
    PAIR;
    DUG 2;
    DROP;
    DROP;
    NIL operation;
    PAIR;
  }`;


  export function SecretStoreStorageMichelson(initialNonce, initialHashedProof) {

    const storage = `(Pair (Pair {} ${initialHashedProof}) ${initialNonce})`;
    return storage;
}


const babylonnetCredentials = {
    publicKey: "edpkvC1Ws6wFh8P1F4x5HqnKtpXa7sYoqKAYijjo94iTxGJHMpLpFG",
    privateKey: "edskRzvvZ2CvidixAvNwbVR2S5WgMGr62HPqA7rkxKX51xeTL4dC3GGTBzQFqt5EtaeGMz2MNRVUckLKzFzMU2jRiXaBwRiNwx",
    publicKeyHash: "tz1MQxHDMNUDgBqDPZqxJJK3ucRa2aCy7XRX",
  }

const carthagenetCredentials = {
    publicKey: 'edpkuH4EMzK1jZSU8836SqZKc9RxY2aCKwK2KzPhqobb6zVk5TkTvV',
    privateKey: 'edskRpMHNHjKqbJ1jZZd6oLpLC3jFujmY2nqoc7cxkBDnvhzfbc9zVc4ZZS1czBtXRPsu2A2LeU6DNwvzadQ5xDUVqun1ic4t6',
    publicKeyHash: 'tz1QCRznmbFuix8PkXwgRZ626giv4ENRshWK',
  };


export const credentials = {babylonnet: babylonnetCredentials, carthagenet: carthagenetCredentials}