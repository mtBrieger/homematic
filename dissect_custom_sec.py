
import sys
from Crypto.Cipher import AES

# -> 0E 03 A0 11 68EA14 1ED017 02 01C80000 (CMD)
# <- 11 03 A0 02 1ED017 68EA14 04 D962D9FB2B03 00 (CAL)
# -> 19 03 A0 03 68EA14 1ED017 344305154D33A8766DBAE938311FA514 (RSP)
# <- 12 03 80 02 1ED017 68EA14 0101C80016 8B0C277F (ACK)

# AES-key: A4E375C6B09FD185F27C4E96FC273AE4


key = bytes.fromhex('A4E375C6B09FD185F27C4E96FC273AE4')


def xor(a, b):
    c = [0] * (len(a))
    for i in range(len(a)):
        if len(b) > i:
            c[i] = (a[i] ^ b[i]) & 0xff
        else:
            c[i] = a[i]
    return bytes(c)


def format_bytes(a):
    return ''.join(format(x, '02x') for x in a)


def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])


def main():
    f = sys.stdin
    f.readline()

    m_frame = bitstring_to_bytes(f.readline()[-113:-17])
    c_frame = bitstring_to_bytes(f.readline()[-161:-17])

    #print('m_frame: ' + format_bytes(m_frame))
    #print('c_frame: ' + format_bytes(c_frame))

    tmp = xor(key, c_frame[11:17])
    aes = AES.new(tmp, AES.MODE_ECB)

    Pd_d = bytes.fromhex('00' * 6) + m_frame[1:11]
    Pd_ = aes.encrypt(Pd_d)

    parameters = m_frame[11:15]
    Pd = xor(Pd_, parameters)
    P = aes.encrypt(Pd)

    print(''.join(format(x, '08b') for x in P), end='')


if __name__ == "__main__":
    main()
