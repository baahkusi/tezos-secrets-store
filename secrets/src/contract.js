export const SecretStore = [
    {
        prim: "storage",
        args: [
            {
                prim: "pair",
                args: [
                    { prim: "map", args: [{ prim: "bytes" }, { prim: "string" }], annots: ["%SecretStore"] },
                    { prim: "pair", args: [{ prim: "bytes", annots: ["%hashedProof"] }, { prim: "int", annots: ["%nonce"] }] }
                ]
            }
        ]
    },
    {
        prim: "parameter",
        args: [
            {
                prim: "pair",
                args: [
                    { prim: "string", annots: ["%encryptedData"] },
                    { prim: "pair", args: [{ prim: "bytes", annots: ["%nexthashedProof"] }, { prim: "bytes", annots: ["%proof"] }] }
                ]
            }
        ]
    },
    {
        prim: "code",
        args: [
            [
                { prim: "DUP" },
                { prim: "CDR" },
                { prim: "SWAP" },
                { prim: "CAR" },
                { prim: "SWAP" },
                { prim: "DUP" },
                { prim: "DUG", args: [{ int: "2" }] },
                { prim: "CDR" },
                { prim: "CAR" },
                { prim: "SWAP" },
                { prim: "DUP" },
                { prim: "DUG", args: [{ int: "2" }] },
                { prim: "CDR" },
                { prim: "CDR" },
                { prim: "BLAKE2B" },
                { prim: "COMPARE" },
                { prim: "EQ" },
                {
                    prim: "IF",
                    args: [
                        [[]],
                        [[{ prim: "PUSH", args: [{ prim: "string" }, { string: "WrongCondition: sp.blake2b(params.proof) == self.data.hashedProof" }] }, { prim: "FAILWITH" }]]
                    ]
                },
                { prim: "SWAP" },
                { prim: "DUP" },
                { prim: "DUG", args: [{ int: "2" }] },
                { prim: "CAR" },
                { prim: "SWAP" },
                { prim: "DUP" },
                { prim: "DUG", args: [{ int: "2" }] },
                { prim: "CAR" },
                { prim: "PACK" },
                { prim: "BLAKE2B" },
                { prim: "MEM" },
                {
                    prim: "IF",
                    args: [
                        [
                            [
                                { prim: "PUSH", args: [{ prim: "string" }, { string: "WrongCondition: ~ (self.data.SecretStore.contains(sp.blake2b(sp.pack(params.encryptedData))))" }] },
                                { prim: "FAILWITH" }
                            ]
                        ],
                        [[]]
                    ]
                },
                { prim: "SWAP" },
                { prim: "DUP" },
                { prim: "DUG", args: [{ int: "2" }] },
                { prim: "DUP" },
                { prim: "CDR" },
                { prim: "SWAP" },
                { prim: "CAR" },
                { prim: "DIG", args: [{ int: "2" }] },
                { prim: "DUP" },
                { prim: "DUG", args: [{ int: "3" }] },
                { prim: "CAR" },
                { prim: "SOME" },
                { prim: "DIG", args: [{ int: "3" }] },
                { prim: "DUP" },
                { prim: "DUG", args: [{ int: "4" }] },
                { prim: "CAR" },
                { prim: "PACK" },
                { prim: "BLAKE2B" },
                { prim: "UPDATE" },
                { prim: "PAIR" },
                { prim: "DUG", args: [{ int: "2" }] },
                { prim: "SWAP" },
                { prim: "DROP" },
                { prim: "SWAP" },
                { prim: "DUP" },
                { prim: "DUG", args: [{ int: "2" }] },
                { prim: "DUP" },
                { prim: "CAR" },
                { prim: "SWAP" },
                { prim: "CDR" },
                { prim: "CAR" },
                { prim: "PUSH", args: [{ prim: "int" }, { int: "1" }] },
                { prim: "DIG", args: [{ int: "4" }] },
                { prim: "DUP" },
                { prim: "DUG", args: [{ int: "5" }] },
                { prim: "CDR" },
                { prim: "CDR" },
                { prim: "ADD" },
                { prim: "SWAP" },
                { prim: "PAIR" },
                { prim: "SWAP" },
                { prim: "PAIR" },
                { prim: "DUG", args: [{ int: "2" }] },
                { prim: "SWAP" },
                { prim: "DROP" },
                { prim: "SWAP" },
                { prim: "DUP" },
                { prim: "DUG", args: [{ int: "2" }] },
                { prim: "DUP" },
                { prim: "CAR" },
                { prim: "SWAP" },
                { prim: "CDR" },
                { prim: "CDR" },
                { prim: "DIG", args: [{ int: "2" }] },
                { prim: "DUP" },
                { prim: "DUG", args: [{ int: "3" }] },
                { prim: "CDR" },
                { prim: "CAR" },
                { prim: "PAIR" },
                { prim: "SWAP" },
                { prim: "PAIR" },
                { prim: "DUG", args: [{ int: "2" }] },
                { prim: "DROP", args: [{ int: "2" }] },
                { prim: "NIL", args: [{ prim: "operation" }] },
                { prim: "PAIR" }
            ]
        ]
    }
];

export function SecretStoreStorage(initialNonce, initialHashedProof) {
    const storage = { prim: "Pair", args: [[], { prim: "Pair", args: [{ bytes: `${initialHashedProof}` }, { int: `${initialNonce}` }] }] };
    return storage;
}

export const SecretStoreMichelson = `parameter (pair (string %encryptedData) (pair (bytes %nexthashedProof) (bytes %proof)));
storage   (pair (map %SecretStore bytes string) (pair (bytes %hashedProof) (int %nonce)));
code
  {
    DUP;        # pair @parameter @storage : pair @parameter @storage
    CDR;        # @storage : pair @parameter @storage
    SWAP;       # pair @parameter @storage : @storage
    CAR;        # @parameter : @storage
    # Entry point: add_secret # @parameter : @storage
    # sp.verify(sp.blake2b(params.proof) == self.data.hashedProof) # @parameter : @storage
    SWAP;       # @storage : @parameter
    DUP;        # @storage : @storage : @parameter
    DUG 2;      # @storage : @parameter : @storage
    CDAR;       # bytes : @parameter : @storage
    SWAP;       # @parameter : bytes : @storage
    DUP;        # @parameter : @parameter : bytes : @storage
    DUG 2;      # @parameter : bytes : @parameter : @storage
    CDDR;       # bytes : bytes : @parameter : @storage
    BLAKE2B;    # bytes : bytes : @parameter : @storage
    COMPARE;    # int : @parameter : @storage
    EQ;         # bool : @parameter : @storage
    IF
      {}
      {
        PUSH string "WrongCondition: sp.blake2b(params.proof) == self.data.hashedProof"; # string : @parameter : @storage
        FAILWITH;   # FAILED
      }; # @parameter : @storage
    # sp.verify(~ (self.data.SecretStore.contains(sp.blake2b(sp.pack(params.encryptedData))))) # @parameter : @storage
    SWAP;       # @storage : @parameter
    DUP;        # @storage : @storage : @parameter
    DUG 2;      # @storage : @parameter : @storage
    CAR;        # map bytes string : @parameter : @storage
    SWAP;       # @parameter : map bytes string : @storage
    DUP;        # @parameter : @parameter : map bytes string : @storage
    DUG 2;      # @parameter : map bytes string : @parameter : @storage
    CAR;        # string : map bytes string : @parameter : @storage
    PACK;       # bytes : map bytes string : @parameter : @storage
    BLAKE2B;    # bytes : map bytes string : @parameter : @storage
    MEM;        # bool : @parameter : @storage
    IF
      {
        PUSH string "WrongCondition: ~ (self.data.SecretStore.contains(sp.blake2b(sp.pack(params.encryptedData))))"; # string : @parameter : @storage
        FAILWITH;   # FAILED
      }
      {}; # @parameter : @storage
    # self.data.SecretStore[sp.blake2b(sp.pack(params.encryptedData))] = params.encryptedData # @parameter : @storage
    SWAP;       # @storage : @parameter
    DUP;        # @storage : @storage : @parameter
    DUG 2;      # @storage : @parameter : @storage
    DUP;        # @storage : @storage : @parameter : @storage
    CDR;        # pair (bytes %hashedProof) (int %nonce) : @storage : @parameter : @storage
    SWAP;       # @storage : pair (bytes %hashedProof) (int %nonce) : @parameter : @storage
    CAR;        # map bytes string : pair (bytes %hashedProof) (int %nonce) : @parameter : @storage
    DIG 2;      # @parameter : map bytes string : pair (bytes %hashedProof) (int %nonce) : @storage
    DUP;        # @parameter : @parameter : map bytes string : pair (bytes %hashedProof) (int %nonce) : @storage
    DUG 3;      # @parameter : map bytes string : pair (bytes %hashedProof) (int %nonce) : @parameter : @storage
    CAR;        # string : map bytes string : pair (bytes %hashedProof) (int %nonce) : @parameter : @storage
    SOME;       # option string : map bytes string : pair (bytes %hashedProof) (int %nonce) : @parameter : @storage
    DIG 3;      # @parameter : option string : map bytes string : pair (bytes %hashedProof) (int %nonce) : @storage
    DUP;        # @parameter : @parameter : option string : map bytes string : pair (bytes %hashedProof) (int %nonce) : @storage
    DUG 4;      # @parameter : option string : map bytes string : pair (bytes %hashedProof) (int %nonce) : @parameter : @storage
    CAR;        # string : option string : map bytes string : pair (bytes %hashedProof) (int %nonce) : @parameter : @storage
    PACK;       # bytes : option string : map bytes string : pair (bytes %hashedProof) (int %nonce) : @parameter : @storage
    BLAKE2B;    # bytes : option string : map bytes string : pair (bytes %hashedProof) (int %nonce) : @parameter : @storage
    UPDATE;     # map bytes string : pair (bytes %hashedProof) (int %nonce) : @parameter : @storage
    PAIR;       # pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : @parameter : @storage
    DUG 2;      # @parameter : @storage : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    SWAP;       # @storage : @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    DROP;       # @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    # self.data.nonce += 1 # @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    SWAP;       # pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : @parameter
    DUP;        # pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : @parameter
    DUG 2;      # pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    DUP;        # pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    CAR;        # map bytes string : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    SWAP;       # pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : map bytes string : @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    CDAR;       # bytes : map bytes string : @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    PUSH int 1; # int : bytes : map bytes string : @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    DIG 4;      # pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : int : bytes : map bytes string : @parameter
    DUP;        # pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : int : bytes : map bytes string : @parameter
    DUG 5;      # pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : int : bytes : map bytes string : @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    CDDR;       # int : int : bytes : map bytes string : @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    ADD;        # int : bytes : map bytes string : @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    SWAP;       # bytes : int : map bytes string : @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    PAIR;       # pair bytes int : map bytes string : @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    SWAP;       # map bytes string : pair bytes int : @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    PAIR;       # pair (map bytes string) (pair bytes int) : @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce))
    DUG 2;      # @parameter : pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : pair (map bytes string) (pair bytes int)
    SWAP;       # pair (map bytes string) (pair (bytes %hashedProof) (int %nonce)) : @parameter : pair (map bytes string) (pair bytes int)
    DROP;       # @parameter : pair (map bytes string) (pair bytes int)
    # self.data.hashedProof = params.nexthashedProof # @parameter : pair (map bytes string) (pair bytes int)
    SWAP;       # pair (map bytes string) (pair bytes int) : @parameter
    DUP;        # pair (map bytes string) (pair bytes int) : pair (map bytes string) (pair bytes int) : @parameter
    DUG 2;      # pair (map bytes string) (pair bytes int) : @parameter : pair (map bytes string) (pair bytes int)
    DUP;        # pair (map bytes string) (pair bytes int) : pair (map bytes string) (pair bytes int) : @parameter : pair (map bytes string) (pair bytes int)
    CAR;        # map bytes string : pair (map bytes string) (pair bytes int) : @parameter : pair (map bytes string) (pair bytes int)
    SWAP;       # pair (map bytes string) (pair bytes int) : map bytes string : @parameter : pair (map bytes string) (pair bytes int)
    CDDR;       # int : map bytes string : @parameter : pair (map bytes string) (pair bytes int)
    DIG 2;      # @parameter : int : map bytes string : pair (map bytes string) (pair bytes int)
    DUP;        # @parameter : @parameter : int : map bytes string : pair (map bytes string) (pair bytes int)
    DUG 3;      # @parameter : int : map bytes string : @parameter : pair (map bytes string) (pair bytes int)
    CDAR;       # bytes : int : map bytes string : @parameter : pair (map bytes string) (pair bytes int)
    PAIR;       # pair bytes int : map bytes string : @parameter : pair (map bytes string) (pair bytes int)
    SWAP;       # map bytes string : pair bytes int : @parameter : pair (map bytes string) (pair bytes int)
    PAIR;       # pair (map bytes string) (pair bytes int) : @parameter : pair (map bytes string) (pair bytes int)
    DUG 2;      # @parameter : pair (map bytes string) (pair bytes int) : pair (map bytes string) (pair bytes int)
    DROP 2;     # pair (map bytes string) (pair bytes int)
    NIL operation; # list operation : pair (map bytes string) (pair bytes int)
    PAIR;       # pair (list operation) (pair (map bytes string) (pair bytes int))
  } # pair (list operation) (pair (map bytes string) (pair bytes int));`;


  export function SecretStoreStorageMichelson(initialNonce, initialHashedProof) {

    const storage = `(Pair {} (Pair "${initialHashedProof}" ${initialNonce}))`;
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