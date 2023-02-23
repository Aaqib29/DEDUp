from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,Pairing
from charm.toolbox.secretutil import SecretUtil
from charm.schemes.abenc.abenc_gghsw13 import CPabe_gghsw13
import hashlib
from Crypto.Util.number import getPrime, inverse
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import math
import os

class PaillierABE:
    def __init__(self, keysize=2048):
        if keysize < 1024:
            raise ValueError("Keysize must be at least 1024 bits")
        if keysize % 2 != 0:
            raise ValueError("Keysize must be an even number of bits")
        self.group = PairingGroup('MNT224')
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)
        self.alpha = self.group.random(ZR)
        self.g1_alpha = self.g1 ** self.alpha
        self.keygen()

    def keygen(self):
        self.util = SecretUtil(self.group, verbose=False)
        self.cpabe = CPabe_gghsw13(self.group)
        self.attributes = ['A', 'B', 'C', 'D']
        self.access_policy = '((four or three) and (two or one))'
        self.master_key, self.public_key = self.cpabe.setup(self.g1, self.g2, self.g1_alpha, self.attributes)
        self.sk_A = self.cpabe.keygen(self.public_key, self.master_key, ['A'])
        self.sk_B = self.cpabe.keygen(self.public_key, self.master_key, ['B'])
        self.sk_C = self.cpabe.keygen(self.public_key, self.master_key, ['C'])
        self.sk_D = self.cpabe.keygen(self.public_key, self.master_key, ['D'])

        def encrypt(self, m, dedup=True, block_size=4096):
          if m < 0 or m >= self.public_key['n']:
            raise ValueError("Message must be a non-negative integer less than n")
        aes_key = os.urandom(16)
        cipher = AES.new(aes_key, AES.MODE_GCM)
        nonce = cipher.nonce
        
      if dedup:
        # Initialize a dictionary to store hash values of data blocks
        block_hashes = {}
        # Read the input file block by block and encrypt each block
        with open(m, 'rb') as f:
            while True:
                # Read the next block from the file
                block = f.read(block_size)
                if not block:
                    break
                # Compute the hash of the block
                block_hash = hashlib.sha256(block).digest()
                # If the block has already been seen, use its existing ciphertext
                if block_hash in block_hashes:
                    c = block_hashes[block_hash]
                # Otherwise, encrypt the block and store its ciphertext
                else:
                    padded_block = pad(block, AES.block_size)
                    r = self.group.random(ZR)
                    s = self.group.random(ZR)
                    msk = self.cpabe.genMSK(self.public_key, self.master_key)
                    pk_A = self.cpabe.pkgen(self.public_key, self.sk_A)
                    pk_B = self.cpabe.pkgen(self.public_key, self.sk_B)
                    pk_C = self.cpabe.pkgen(self.public_key, self.sk_C)
                    pk_D = self.cpabe.pkgen(self.public_key, self.sk_D)
                    h = self.group.hash(str(r), G1)
                    k = self.group.hash(str(s), G1)
                    C0 = self.public_key['g2'] ** s
                    C1 = (self.g1 ** r) * (self.public_key['g2'] ** (self.alpha * r))
                    C2_A = self.cpabe.encrypt(self.public_key, pk_A, h, padded_block)
                    C2_B = self.cpabe.encrypt(self.public_key, pk_B, h, padded_block)
                    C2_C = self.cpabe.encrypt(self.public_key, pk_C, k, padded_block)
                    C2_D = self.cpabe.encrypt(self.public_key, pk_D, k, padded_block)
                    C3 = self.group.hash(str(r) + str(s) + str(block_hash), G1)
                    c = {'C0': C0, 'C1': C1, 'C2_A': C2_A, 'C2_B': C2_B, 'C2_C': C2_C, 'C2_D': C2_D, 'C3': C3}
                    # Store the ciphertext in the block_hashes dictionary
                    block_hashes[block_hash] = c
                yield c, nonce, aes_key

    else:
        with open(m, 'rb') as f:
            while True:
                block = f.read(block_size)
                if not block:
                    break
                padded_block = pad(block, AES.block_size)
                r = self.group.random(ZR)
                s = self.group.random(ZR)
                msk = self.cpabe.genMSK(self.public_key, self.master_key)
                pk_A = self.cpabe.pkgen(self.public_key, self.sk_A)
                pk_B = self.cpabe.pkgen(self.public_key, self.sk_B)
                pk_C = self.cpabe.pkgen(self.public_key, self.sk_C)
                pk_D = self.cpabe.pkgen(self.public_key, self.sk_D)
                h = self.group.hash(str(r), G1)
                k = self.group.hash(str(s), G1)
                C0 = self.public_key['g2'] ** s
                C1 = (self.g1 ** r) * (self.public_key['g2'] ** (self.alpha * r))
                C2_A = self.cpabe.encrypt(self.public_key, pk_A, h, padded_block)
                            C2_B = self.cpabe.encrypt(self.public_key, pk_B, k, padded_block)
            C2_C = self.cpabe.encrypt(self.public_key, pk_C, h * k, padded_block)
            C2_D = self.cpabe.encrypt(self.public_key, pk_D, h + k, padded_block)
            # Store the ciphertexts of the block using their hash values as keys
            block_hashes[block_hash] = (C0, C1, C2_A, C2_B, C2_C, C2_D)
    # Serialize the block hashes and ciphertexts and encrypt them with Paillier
    serialized_block_hashes = str(block_hashes).encode()
    plaintext = pad(serialized_block_hashes, AES.block_size)
    Paillier = self.Paillier_encrypt(plaintext)
    # Concatenate the nonce, ciphertext of the AES key, and ciphertext of the serialized block hashes
    ciphertext = nonce + cipher.encrypt(aes_key) + Paillier
    return ciphertext

def decrypt(self, ciphertext, outfile):
    # Split the ciphertext into its components
    nonce = ciphertext[:16]
    aes_key_ciphertext = ciphertext[16:48]
    paillier_ciphertext = ciphertext[48:]
    # Decrypt the AES key using the private key
    aes_key = self.Paillier_decrypt(aes_key_ciphertext)
    # Decrypt the serialized block hashes using the AES key and the nonce
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce)
    serialized_block_hashes = unpad(cipher.decrypt(paillier_ciphertext), AES.block_size)
    # Deserialize the block hashes
    block_hashes = eval(serialized_block_hashes.decode())
    # Initialize a dictionary to store the plaintext blocks
    plaintext_blocks = {}
    # Iterate over the ciphertexts of the blocks and decrypt them
    for block_hash, (C0, C1, C2_A, C2_B, C2_C, C2_D) in block_hashes.items():
        # Decrypt the access structure associated with the block
        policy = self.cpabe.boolean_policy_to_formula(self.public_key['pairing'], self.cpabe.prune(self.cpabe.boolean_formula_to_tree(self.access_policy)))
        attrs = self.attributes
        if not self.cpabe.satisfy(self.public_key['pairing'], policy, attrs):
            continue
        # Decrypt the block if the access structure is satisfied
        plaintext_block_A = self.cpabe.decrypt(self.public_key, self.sk_A, C2_A, C1, C0)
        plaintext_block_B = self.cpabe.decrypt(self.public_key, self.sk_B, C2_B, C1, C0)
        plaintext_block_C = self.cpabe.decrypt(self.public_key, self.sk_C, C2_C, C1, C0)
        plaintext_block_D = self.cpabe.decrypt(self.public_key, self.sk_D, C2_D, C1, C0)
        # Verify the integrity of the block by checking its hash
        if hashlib.sha256(plaintext_block_A).digest() != block_hash:
            raise ValueError("Block hash mismatch")
        # Store the plaintext block using its hash value as the key
        plaintext_blocks[block_hash] = plaintext_block_A
    # Write the plaintext blocks to the output file in the order they appear in the input file
    with open(outfile, 'wb') as f:
        for block_hash in block_hashes:
            if block_hash in plaintext_blocks:
                f.write(plaintext_blocks[block_hash])
    return True

def Paillier_encrypt(self, m):
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    g = n + 1
    l = pow(self.group.hash(m, G1), -1, n)
    r = pow(g, self.group.random(ZR), n) % n
    c = (pow(g, int(m), n) * pow(l, int(m), n) * r) % n
    return c.to_bytes((c.bit_length() + 7) // 8, byteorder='big')

def Paillier_decrypt(self, c):
    p = self.private_key['p']
    q = self.private_key['q']
    n = p * q
    m = pow(c, self.private_key['d'], n)
    return m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')


