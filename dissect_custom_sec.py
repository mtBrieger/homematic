import sys
import logging
from Crypto.Cipher import AES

# format of messages
# <-10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010
# <-10101010101010101010101010101010111010011100101011101001110010100000101110110110101101000100000001011100111000110001111001011011101101101101000100000001000010101000000111101001
# ->10101010101010101010101010101010111010011100101011101001110010100001000110110110101000000000001001011011101101101101000101011100111000110001111000000100101100100100001111110101111000101101100001101110000000000101110011011011


# leaked default HomeMatic AES-key
key = bytes.fromhex('A4E375C6B09FD185F27C4E96FC273AE4')


def main():
    """
    read previous messages from stdin
    extract m_frame and c_frame
    compute encrypted AES payload based on https://git.zerfleddert.de/hmcfgusb/AES/
    """

    f = sys.stdin

    # skip first message
    f.readline()

    m_frame = bitstring_to_bytes(f.readline()[-113:-17])
    c_frame = bitstring_to_bytes(f.readline()[-161:-17])

    logging.info('m_frame', bytes_to_hexstring(m_frame))
    logging.info('c_frame', bytes_to_hexstring(c_frame))

    tmp = xor(key, c_frame[11:17])
    aes = AES.new(tmp, AES.MODE_ECB)

    Pd_d = bytes.fromhex('00' * 6) + m_frame[1:11]
    Pd_ = aes.encrypt(Pd_d)

    parameters = m_frame[11:15]
    Pd = xor(Pd_, parameters)
    P = aes.encrypt(Pd)

    print(bytes_to_bitstring(P), end='')


def xor(a, b):
    c = [0] * (len(a))
    for i in range(len(a)):
        if len(b) > i:
            c[i] = (a[i] ^ b[i]) & 0xff
        else:
            c[i] = a[i]
    return bytes(c)


def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])


def bytes_to_bitstring(a):
    return ''.join(format(x, '08b') for x in a)


def bytes_to_hexstring(a):
    return ''.join(format(x, '02x') for x in a)


if __name__ == "__main__":
    main()
