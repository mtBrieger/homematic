
from Crypto.Cipher import AES

# -> 0E 03 A0 11 68EA14 1ED017 02 01C80000 (CMD)
# <- 11 03 A0 02 1ED017 68EA14 04 D962D9FB2B03 00 (CAL)
# -> 19 03 A0 03 68EA14 1ED017 344305154D33A8766DBAE938311FA514 (RSP)
# <- 12 03 80 02 1ED017 68EA14 0101C80016 8B0C277F (ACK)

# AES-key: A4E375C6B09FD185F27C4E96FC273AE4


key = bytes.fromhex('A4E375C6B09FD185F27C4E96FC273AE4')

m_frame = bytes.fromhex('0b13b4405ce31e5bb6d1010a')
c_frame = bytes.fromhex('1113a0025bb6d15ce31e048d2c0e74092800')
r_frame = bytes.fromhex('1913a0035ce31e5bb6d17b98b58454deef71541a04b4055408e8')

a_frame = bytes.fromhex('121380025bb6d15ce31e0101010027a8793cee')


m_frame = bytes.fromhex('0b14b4405ce31e5bb6d1020a')
c_frame = bytes.fromhex('1114a0025bb6d15ce31e0410d198cb603b00')
r_frame = bytes.fromhex('1914a0035ce31e5bb6d1b0fbed947ae026fce331def127fcf743')

a_frame = bytes.fromhex('121480025bb6d15ce31e010101202c6a6a54a8')


m_frame = bytes.fromhex('0b19b4405ce31e5bb6d1020c')
c_frame = bytes.fromhex('1119a0025bb6d15ce31e04f3985e0fe97b00')
r_frame = bytes.fromhex('1919a0035ce31e5bb6d1fd3b92b913551b3251c0c6a6cac45006')

a_frame = bytes.fromhex('121980025bb6d15ce31e010101202d15f19d00')

def xor(a, b):
    c = [0] * (len(a))
    for i in range(len(a)):
        if len(b) > i:
            c[i] = (a[i] ^ b[i]) & 0xff
        else:
            c[i] = a[i]
    return bytes(c)


tmp = xor(key, c_frame[11:17]) #[0:6]
print(''.join(format(x, '02x') for x in tmp) + "\n")
parameters = m_frame[11:15]
IV = parameters + bytes.fromhex('00' * (16 - len(parameters)))
P = r_frame[10:26]


aes = AES.new(tmp, AES.MODE_ECB) #IV
Pd = aes.decrypt(P)

Pd_ = xor(Pd, parameters)

print(''.join(format(x, '02x') for x in Pd_[0:2]))

Pd_d = aes.decrypt(Pd_)

print(''.join(format(x, '02x') for x in Pd))
print(''.join(format(x, '02x') for x in Pd_))
print(''.join(format(x, '02x') for x in Pd_d))

print(''.join(format(x, '02x') for x in Pd_d[0:6]))

#51742b9c7449
#54032c2b030a
#138b33b181a5

print('\n')

tmp = xor(key, c_frame[11:17])
aes = AES.new(tmp, AES.MODE_ECB)

Pd_d = bytes.fromhex('00' * 6) + m_frame[1:11]
Pd_ = aes.encrypt(Pd_d)

parameters = m_frame[11:15]
Pd = xor(Pd_, parameters)
P = aes.encrypt(Pd)

print(''.join(format(x, '02x') for x in P))