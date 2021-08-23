"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
from Crypto.Hash import HMAC, SHA384
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

secrets_filepath = "../bootloader/secret_build_output.txt"
HMAC_KEY_LENGTH = 48
HMAC_SIG_LENGTH = 48
AES_KEY_LENGTH = 16
AES_IV_LENGTH = 16
AES_GCM_TAG_LENGTH = 16
AES_GCM_AAD_LENGTH = 16

def random(state):
    z = state + 0x6D2B79F5
    z = (z ^ z >> 15) * (1 | z)
    z ^= z + (z ^ z >> 7) * (61 | z)
    return z ^ z >> 14

#TODO: IMPLEMENT ROLLING IV's
def roll_iv(original_iv):
    for i in range(AES_IV_LENGTH):
        original_iv[i] = random(original_iv[i]) % 256
    return original_iv

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()
        
    # Load secrets from secret_build_output.txt
    with open(secrets_filepath, 'rb') as fp:
        secrets = fp.read()
    temp = 0
    hmac_key = secrets[temp:temp + HMAC_KEY_LENGTH]
    temp += HMAC_KEY_LENGTH
    aes_key = secrets[temp:temp + AES_KEY_LENGTH]
    temp += AES_KEY_LENGTH
    aes_iv = bytearray(secrets[temp:temp + AES_IV_LENGTH])
    temp += AES_IV_LENGTH
    aes_aad = bytearray(secrets[temp:temp + AES_GCM_AAD_LENGTH])
    aes_aad[0] ^= version & 0xFF
    aes_aad[1] ^= (version >> 8) & 0xFF
    
    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b'\00'

    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Append firmware and message to metadata
    firmware_blob = metadata + firmware_and_message

    hmac = HMAC.new(hmac_key, digestmod=SHA384)
    hmac.update(firmware_blob)
    sig_and_firmware_blob = hmac.digest() + firmware_blob

    for i in range(version):
        aes_iv = roll_iv(aes_iv)
    
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_iv, mac_len=AES_GCM_TAG_LENGTH)
    cipher.update(aes_aad)
    ciphertext, authtag = cipher.encrypt_and_digest(sig_and_firmware_blob)
    ciphertext_and_tag = ciphertext + authtag
    
    plaintext_version = struct.pack('<H', version)
    version_and_ciphertext_and_tag = plaintext_version + ciphertext_and_tag

    with open(outfile, 'wb+') as outfile:
        outfile.write(version_and_ciphertext_and_tag)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
