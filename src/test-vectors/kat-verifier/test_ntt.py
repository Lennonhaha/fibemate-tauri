#!/usr/bin/env python3
"""
NTT implementation for ML-KEM-768 - Fixed version
"""

q = 3329
zeta = 17

def bit_reverse_7(x):
    r = 0
    for i in range(7):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r

# ML-KEM zetas
zetas = []
for i in range(128):
    br = bit_reverse_7(i + 1)
    z = pow(zeta, br, q)
    zetas.append(z)

print("First 10 zetas:", zetas[:10])
print("zeta^128 mod q =", pow(zeta, 128, q))
print("zeta^256 mod q =", pow(zeta, 256, q))

def ntt_forward(f):
    """
    ML-KEM NTT forward transform
    
    7 layers, each combining pairs with stride doubling:
    Layer 0: stride=2, 128 butterflies, zetas[0]
    Layer 1: stride=4, 64 butterflies, zetas[1..2]
    Layer 2: stride=8, 32 butterflies, zetas[3..6]
    ...
    Layer 6: stride=128, 2 butterflies, zetas[63..126]
    
    Total zetas used: 1 + 2 + 4 + 8 + 16 + 32 + 64 = 127
    """
    n = 256
    a = [((x % q) + q) % q for x in f]
    
    zeta_idx = 0
    length = 2
    
    while length <= 128:
        half = length // 2
        for start in range(0, n, length):
            z = zetas[zeta_idx]
            zeta_idx += 1
            for j in range(half):
                t = (z * a[start + j + half]) % q
                a[start + j + half] = (a[start + j] - t) % q
                a[start + j] = (a[start + j] + t) % q
        length *= 2
    
    return a

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

file = r'D:\fibemate-electron\src\test-vectors\intermediate-2023\PQC Intermediate Values\Key Generation -- ML-KEM-768.txt'
tc = parse_kat_file(file)

s = tc['s']
sHat = tc['sHat']

print("\nTesting NTT...")
print(f"s[0] first 10 coeffs: {s[0][:10]}")
print(f"sHat[0] first 10 coeffs: {sHat[0][:10]}")

sHat_computed = ntt_forward(s[0])

mismatches = 0
for i in range(256):
    if sHat_computed[i] != sHat[0][i]:
        if mismatches < 5:
            print(f"  sHat[0][{i}]: computed={sHat_computed[i]}, expected={sHat[0][i]}")
        mismatches += 1

print(f"\nNTT: {mismatches}/256 mismatches")

if mismatches > 0:
    # Try bit-reversed comparison
    def bit_reverse_8(x):
        r = 0
        for i in range(8):
            r = (r << 1) | (x & 1)
            x >>= 1
        return r
    
    print("\nTrying bit-reversed comparison...")
    mismatches_br = 0
    for i in range(256):
        br_i = bit_reverse_8(i)
        if sHat_computed[i] != sHat[0][br_i]:
            if mismatches_br < 3:
                print(f"  sHat_computed[{i}] vs expected[{br_i}]: {sHat_computed[i]} vs {sHat[0][br_i]}")
            mismatches_br += 1
    
    print(f"Bit-reversed: {mismatches_br}/256 mismatches")
    
    # Also try reversed order within pairs
    print("\nTrying reversed pairs...")
    mismatches_rp = 0
    for i in range(0, 256, 2):
        if sHat_computed[i] != sHat[0][i+1] or sHat_computed[i+1] != sHat[0][i]:
            mismatches_rp += 1
    print(f"Reversed pairs: {mismatches_rp}/128 pair mismatches")
