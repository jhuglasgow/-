import hashlib
import ecdsa
import codecs
import base58

def addr(private_key):
    private_key_bytes = codecs.decode(private_key, 'hex')
    # Get ECDSA public key
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
    public_key = '04' + bytes.decode(key_hex)
    # print(key_str)

    # Run SHA-256 for the public key
    public_key_bytes = codecs.decode(public_key, 'hex')
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    # Run RIPEMD-160 for the SHA-256
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    ripemd160_str = bytes.decode(ripemd160_bpk_hex)
    # print(ripemd160_str)

    # adding network byte
    ripemd160_bpk_mainnet = '00' + ripemd160_str
    # print(ripemd160_bpk_mainnet)

    # Double SHA256 to get checksum
    ripemd160_bpk_hex2 = codecs.decode(ripemd160_bpk_mainnet, 'hex')
    sha256_nbpk = hashlib.sha256(ripemd160_bpk_hex2)
    sha256_nbpk_digest = sha256_nbpk.digest()
    sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
    sha256_2_nbpk_digest = sha256_2_nbpk.digest()
    sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
    checksum = bytes.decode(sha256_2_hex[:8])
    # print(checksum)

    address = str(ripemd160_bpk_mainnet) + str(checksum)
    # print(address)

    address_base58 = base58.base58(address)
    return address_base58


def comaddr(private_key):
    private_key_bytes = codecs.decode(private_key, 'hex')
    # Get ECDSA public key
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
    key_str = bytes.decode(key_hex)
    # print(key_str)

    if int(key_str[-2:], 16) % 2 == 0:
        public_key = '02' + key_str[0:64]
    else:
        public_key = '03' + key_str[0:64]
    # print(public_key)

    # Run SHA-256 for the public key
    public_key_bytes = codecs.decode(public_key, 'hex')
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    # Run RIPEMD-160 for the SHA-256
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    ripemd160_str = bytes.decode(ripemd160_bpk_hex)
    # print(ripemd160_str)

    # adding network byte
    ripemd160_bpk_mainnet = '00' + ripemd160_str
    # print(ripemd160_bpk_mainnet)

    # Double SHA256 to get checksum
    ripemd160_bpk_hex2 = codecs.decode(ripemd160_bpk_mainnet, 'hex')
    sha256_nbpk = hashlib.sha256(ripemd160_bpk_hex2)
    sha256_nbpk_digest = sha256_nbpk.digest()
    sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
    sha256_2_nbpk_digest = sha256_2_nbpk.digest()
    sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
    checksum = bytes.decode(sha256_2_hex[:8])
    # print(checksum)

    address = str(ripemd160_bpk_mainnet) + str(checksum)
    # print(address)

    address_base58 = base58.base58(address)
    return address_base58