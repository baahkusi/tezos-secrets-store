export const SecretStore = `[
    {
        "prim": "storage", "args": [
            {
                "prim": "pair", "args": [
                    {
                        "prim": "pair", "args": [
                            {
                                "prim": "map", "args": [
                                    { "prim": "bytes" }, { "prim": "string" }]
                                , "annots": ["%SecretStore"]
                            }, { "prim": "bytes", "annots": ["%hashedProof"] }]
                    }, { "prim": "int", "annots": ["%nonce"] }]
            }]
    },
    {
        "prim": "parameter", "args": [
            {
                "prim": "pair", "args": [
                    {
                        "prim": "pair", "args": [
                            { "prim": "string", "annots": ["%encryptedData"] }, { "prim": "bytes", "annots": ["%nexthashedProof"] }]
                    }, { "prim": "bytes", "annots": ["%proof"] }]
            }]
    },
    {
        "prim": "code", "args": [
            [{ "prim": "DUP" }, { "prim": "CDR" }, { "prim": "SWAP" }, { "prim": "CAR" }, { "prim": "SWAP" }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "CAR" }, { "prim": "CDR" }, { "prim": "SWAP" }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "CDR" }, { "prim": "BLAKE2B" }, { "prim": "COMPARE" }, { "prim": "EQ" },
            {
                "prim": "IF", "args": [
                    [[]], [[{ "prim": "PUSH", "args": [{ "prim": "string" }, { "string": "WrongCondition: sp.blake2b(params.proof) == self.data.hashedProof" }] }, { "prim": "FAILWITH" }]]]
            }, { "prim": "SWAP" }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "CAR" }, { "prim": "CAR" }, { "prim": "SWAP" }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "CAR" }, { "prim": "CAR" }, { "prim": "PACK" }, { "prim": "BLAKE2B" }, { "prim": "MEM" },
            {
                "prim": "IF", "args": [
                    [[{ "prim": "PUSH", "args": [{ "prim": "string" }, { "string": "WrongCondition: ~ (self.data.SecretStore.contains(sp.blake2b(sp.pack(params.encryptedData))))" }] }, { "prim": "FAILWITH" }]], [[]]]
            }, { "prim": "SWAP" }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "DUP" }, { "prim": "CDR" }, { "prim": "SWAP" }, { "prim": "CAR" }, { "prim": "DUP" }, { "prim": "CDR" }, { "prim": "SWAP" }, { "prim": "CAR" }, { "prim": "DIG", "args": [{ "int": "3" }] }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "4" }] }, { "prim": "CAR" }, { "prim": "CAR" }, { "prim": "SOME" }, { "prim": "DIG", "args": [{ "int": "4" }] }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "5" }] }, { "prim": "CAR" }, { "prim": "CAR" }, { "prim": "PACK" }, { "prim": "BLAKE2B" }, { "prim": "UPDATE" }, { "prim": "PAIR" }, { "prim": "PAIR" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "SWAP" }, { "prim": "DROP" }, { "prim": "SWAP" }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "CAR" }, { "prim": "PUSH", "args": [{ "prim": "int" }, { "int": "1" }] }, { "prim": "DIG", "args": [{ "int": "3" }] }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "4" }] }, { "prim": "CDR" }, { "prim": "ADD" }, { "prim": "SWAP" }, { "prim": "PAIR" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "SWAP" }, { "prim": "DROP" }, { "prim": "SWAP" }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "DUP" }, { "prim": "CDR" }, { "prim": "SWAP" }, { "prim": "CAR" }, { "prim": "CAR" }, { "prim": "DIG", "args": [{ "int": "2" }] }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "3" }] }, { "prim": "CAR" }, { "prim": "CDR" }, { "prim": "SWAP" }, { "prim": "PAIR" }, { "prim": "PAIR" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "DROP" }, { "prim": "DROP" },
            {
                "prim": "NIL", "args": [
                    { "prim": "operation" }]
            }, { "prim": "PAIR" }]]
    }]`;

export function SecretStoreStorage(initialNonce, initialHashedProof) {
    return `{
        "prim": "Pair", "args": [
            {
                "prim": "Pair", "args": [
                    [], { "bytes": ${initialNonce} }]
            }, { "int": ${initialHashedProof} }]
    }`;
}