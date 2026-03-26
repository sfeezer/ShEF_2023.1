#!/usr/bin/env python3
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Configuration matching security_kernel constants
CHUNK_SIZE = 1024
IV_SIZE = 12
TAG_SIZE = 16
KEY_HEX = "F878B838D8589818E868A828C8488808F070B030D0509010E060A020C0408000"

WORD_SIZE = 4  # PCAP is word-oriented (32-bit)

def _byteswap_words(data: bytes, word_size: int = WORD_SIZE) -> bytes:
    if len(data) % word_size != 0:
        raise ValueError(
            f"Bitstream payload length must be a multiple of {word_size} bytes "
            f"(got {len(data)})."
        )
    return b"".join(
        data[i : i + word_size][::-1] for i in range(0, len(data), word_size)
    )

def encrypt_bitstream(input_file, output_file):
    print(f"Encrypting {input_file} to {output_file}...")
    key = bytes.fromhex(KEY_HEX)
    
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        chunk_idx = 0
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break

            # Vivado .bin is little-endian; PCAP requires big-endian word order.
            # Swap bytes within each 32-bit word so the decrypted payload can be
            # streamed directly to PCAP without additional swapping.
            chunk = _byteswap_words(chunk)
                
            # Generate random IV for this chunk
            iv = get_random_bytes(IV_SIZE)
            
            # Encrypt
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            ciphertext, tag = cipher.encrypt_and_digest(chunk)
            
            # Write Format: IV | Tag | Ciphertext
            # security_kernel.c: 
            # iv_addr = addr + chunk_ptr
            # gcm_tag_addr = addr + chunk_ptr + IV_SIZE
            # chunk_addr = addr + chunk_ptr + IV_SIZE + TAG_SIZE
            
            f_out.write(iv)
            f_out.write(tag)
            f_out.write(ciphertext)
            
            chunk_idx += 1
            
    print(f"Done. Processed {chunk_idx} chunks.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 encrypt_bitstream.py <input.bit/bin> <output.bin>")
        print("Example: python3 encrypt_bitstream.py system.bin bitstr.bin")
        sys.exit(1)
        
    encrypt_bitstream(sys.argv[1], sys.argv[2])
