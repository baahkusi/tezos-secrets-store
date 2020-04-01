import smartpy as sp
from random import randint

class SecretStore(sp.Contract):
    def __init__(self, initialNonce, initialHashedProof):
        self.init(
            nonce=initialNonce,
            hashedProof=initialHashedProof,
            SecretStore=sp.list(t=sp.TString),
            )

    @sp.entry_point
    def add_secret(self, params):
        # make sure proof checks out
        sp.verify(sp.blake2b(params.proof) == self.data.hashedProof)
        # add secret to user SecretStore
        self.data.SecretStore.push(params.encryptedData)
        # increment nonce
        self.data.nonce = self.data.nonce + 1
        # set new hashedSecret
        self.data.hashedProof = params.nexthashedProof
        
        
        
        
# Tests
@sp.add_test(name = "SecretStoreStore")
def test():
    key = ''
    initialNonce = 1
    initialHashedProof = sp.blake2b(sp.bytes("0x62436d677a706263382f2b4f4a4d67367478745233513d3d")) # 12345678aabc - UTF-8
    c1 = SecretStore(initialNonce, initialHashedProof)
    # show its representation
    scenario = sp.test_scenario()
    scenario.h2("Contract")
    scenario += c1
    
    # now store secret data encrypted with key using aes
    scenario.h1('Test Store Secret 1')
    encryptedData = 'abcdefgh'
    
    proof = sp.bytes("0x62436d677a706263382f2b4f4a4d67367478745233513d3d") # 12345678aabc - UTF-8
    # create next token

    nexthashedProof = sp.blake2b(sp.bytes("0x313233343536373861626263")) # 12345678aabc - UTF-8
    c2 = c1.add_secret(proof = proof, nexthashedProof = nexthashedProof, encryptedData = encryptedData).run()
    scenario += c2
    
    # now store proof data encrypted with key using aes
    scenario.h1('Test Store Secret 2')
    encryptedData = 'qwertyuiop'
    
    proof = sp.bytes("0x313233343536373861626263") # 0x12345678aabc - UTF-8
    # create next token

    nexthashedProof = sp.blake2b(sp.bytes("0x313233343536373861616264")) # 0x12345678aabd - UTF-8
    c2 = c1.add_secret(proof = proof, nexthashedProof = nexthashedProof, encryptedData = encryptedData).run()
    scenario += c2