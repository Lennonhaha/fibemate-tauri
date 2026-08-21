#!/usr/bin/env python3
"""
Verify ML-KEM key generation against KAT vectors
"""

import hashlib

q = 3329

def shake256(data, length):
    from hashlib import shake_256
    return shake_256(data).digest(length)

def sha3_256(data):
    import hashlib
    return hashlib.sha3_256(data).digest()

def sha3_512(data):
    import hashlib
    return hashlib.sha3_512(data).digest()

def cbd2(buf):
    r = []
    for i in range(128):
        b = buf[i]
        c0 = (b & 1) + ((b >> 1) & 1) - ((b >> 2) & 1) - ((b >> 3) & 1)
        c1 = ((b >> 4) & 1) + ((b >> 5) & 1) - ((b >> 6) & 1) - ((b >> 7) & 1)
        r.extend([c0, c1])
    return r

def sample_poly(seed, nonce):
    """Sample polynomial uniformly from seed+nonce"""
    stream = shake256(bytes([*seed, nonce & 0xFF]), 504)
    a = []
    j = 0
    idx = 0
    while j < 256 and idx < 503:
        d1 = stream[idx] | ((stream[idx+1] & 0x0F) << 8)
        d2 = (stream[idx+1] >> 4) | (stream[idx+2] << 4)
        idx += 3
        if d1 < q:
            a.append(d1)
            j += 1
        if j < 256 and d2 < q:
            a.append(d2)
            j += 1
    return a

def mod_mul(a, b):
    return (a * b) % q

def mod_add(a, b):
    r = a + b
    return r - q if r >= q else r

def mod_sub(a, b):
    r = a - b
    return r + q if r < 0 else r

def poly_mul(f, g):
    """Negacyclic convolution in time domain"""
    r = [0] * 256
    for i in range(256):
        if f[i] == 0:
            continue
        for j in range(256):
            if g[j] == 0:
                continue
            k = i + j
            prod = mod_mul(f[i], g[j])
            if k < 256:
                r[k] = mod_add(r[k], prod)
            else:
                r[k - 256] = mod_sub(r[k - 256], prod)
    return r

def mat_vec_mul(A, s):
    """Matrix-vector multiply"""
    k = len(A)
    r = []
    for i in range(k):
        total = [0] * 256
        for j in range(k):
            prod = poly_mul(A[i][j], s[j])
            for l in range(256):
                total[l] = mod_add(total[l], prod[l])
        r.append(total)
    return r

def vec_add(a, b):
    """Vector add"""
    k = len(a)
    r = []
    for i in range(k):
        r.append([mod_add(a[i][j], b[i][j]) for j in range(256)])
    return r

def byte_encode(f, d):
    """Encode polynomial with d bits per coefficient"""
    out = bytearray(256 * d // 8)
    for i in range(256):
        t = ((f[i] % q) + q) % q
        for j in range(d):
            bi = i * d + j
            out[bi >> 3] |= ((t >> j) & 1) << (bi & 7)
    return bytes(out)

def generate_keypair_deterministic(d, z):
    """Deterministic key generation with given seeds"""
    seed = sha3_512(d)
    rho = seed[:32]
    sigma = seed[32:64]
    
    # A matrix
    A = []
    for i in range(3):
        row = []
        for j in range(3):
            row.append(sample_poly(rho, (i << 8) | j))
        A.append(row)
    
    # s and e vectors
    s = []
    e = []
    for i in range(3):
        s.append(cbd2(shake256(bytes([*sigma, i]), 128)))
        e.append(cbd2(shake256(bytes([*sigma, i + 3]), 128)))
    
    # t = A*s + e
    As = mat_vec_mul(A, s)
    t = vec_add(As, e)
    
    # Encode public key
    pk = bytearray(1184)
    off = 0
    for i in range(3):
        pk[off:off+384] = byte_encode(t[i], 12)
        off += 384
    pk[off:off+32] = rho
    
    # Encode secret key
    sk = bytearray(2400)
    off = 0
    for i in range(3):
        sk[off:off+384] = byte_encode(s[i], 12)
        off += 384
    sk[off:off+1184] = pk
    off += 1184
    sk[off:off+32] = sha3_256(pk)
    off += 32
    sk[off:off+32] = z
    
    return bytes(pk), bytes(sk)

# Parse KAT
def parse_kat_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    
    lines = content.split('\n')
    test_case = {}
    current_matrix = None
    matrix_buffer = []
    
    for line in lines:
        line = line.strip()
        if not line:
            if current_matrix and matrix_buffer:
                matrix_str = ''.join(matrix_buffer)
                try:
                    test_case[current_matrix] = eval(matrix_str)
                except:
                    pass
                current_matrix = None
                matrix_buffer = []
            continue
        
        if line.startswith('Key Generation'):
            test_case['type'] = line
            continue
        
        hex_fields = {'z', 'd', 'rho', 'sigma', 'ek', 'dk'}
        found = False
        for field in hex_fields:
            if line.startswith(f'{field}: '):
                test_case[field] = line[len(field)+2:].strip().replace(' ', '')
                found = True
                break
        
        if found:
            if current_matrix and matrix_buffer:
                matrix_str = ''.join(matrix_buffer)
                try:
                    test_case[current_matrix] = eval(matrix_str)
                except:
                    pass
                current_matrix = None
                matrix_buffer = []
            continue
        
        if ': [[' in line:
            if current_matrix and matrix_buffer:
                matrix_str = ''.join(matrix_buffer)
                try:
                    test_case[current_matrix] = eval(matrix_str)
                except:
                    pass
            colon_idx = line.index(': [[')
            current_matrix = line[:colon_idx].strip()
            matrix_buffer = [line[colon_idx+2:].strip()]
            continue
        
        if current_matrix:
            matrix_buffer.append(line)
    
    if current_matrix and matrix_buffer:
        matrix_str = ''.join(matrix_buffer)
        try:
            test_case[current_matrix] = eval(matrix_str)
        except:
            pass
    
    return test_case

# Test
file = r'D:\fibemate-electron\src\test-vectors\intermediate-2023\PQC Intermediate Values\Key Generation -- ML-KEM-768.txt'
tc = parse_kat_file(file)

d = bytes.fromhex(tc['d'])
z = bytes.fromhex(tc['z'])
ek_expected = bytes.fromhex(tc['ek'])
dk_expected = bytes.fromhex(tc['dk'])

print("Testing deterministic key generation...")
print(f"d: {d.hex()[:40]}...")
print(f"z: {z.hex()[:40]}...")

pk, sk = generate_keypair_deterministic(d, z)

print(f"\nComputed ek: {pk.hex()[:40]}...")
print(f"Expected ek: {ek_expected.hex()[:40]}...")
print(f"ek match: {pk == ek_expected}")

print(f"\nComputed dk: {sk.hex()[:40]}...")
print(f"Expected dk: {dk_expected.hex()[:40]}...")
print(f"dk match: {sk == dk_expected}")

if pk != ek_expected:
    # Find first mismatch
    for i in range(len(pk)):
        if pk[i] != ek_expected[i]:
            print(f"First ek mismatch at byte {i}: {pk[i]:02x} vs {ek_expected[i]:02x}")
            break

if sk != dk_expected:
    for i in range(len(sk)):
        if sk[i] != dk_expected[i]:
            print(f"First dk mismatch at byte {i}: {sk[i]:02x} vs {dk_expected[i]:02x}")
            break
