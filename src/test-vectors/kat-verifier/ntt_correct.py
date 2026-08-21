#!/usr/bin/env python3
"""
Correct ML-KEM NTT implementation

Based on Kyber/ML-KEM reference implementation pattern:
- 7 layers of butterflies
- Each layer doubles the stride
- Zetas are used sequentially from the precomputed table
"""

q = 3329
zeta = 17

def bit_reverse_7(x):
    r = 0
    for i in range(7):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r

# Precompute zetas: zetas[i] = zeta^(brv(i+1)) mod q
zetas = []
for i in range(128):
    br = bit_reverse_7(i + 1)
    z = pow(zeta, br, q)
    zetas.append(z)

def ntt_forward(f):
    """
    ML-KEM NTT forward transform.
    
    Algorithm (iterative, in-place):
    for layer = 0 to 6:
        stride = 2^layer
        for each group of 2*stride elements:
            z = zetas[appropriate_index]
            for j = 0 to stride-1:
                butterfly on elements at offset j and j+stride
    """
    n = 256
    a = [((x % q) + q) % q for x in f]
    
    # Layer 0: pairs (stride=1, but we process 2 elements at a time)
    # Actually let me use the standard formulation:
    
    k = 1
    zeta_idx = 0
    
    while k < 128:  # 7 iterations: k=1,2,4,8,16,32,64
        # In layer with parameter k, we have 128/k groups
        # Each group has 2k elements
        # Within each group, k butterflies
        # All butterflies in position j across groups share zeta
        
        for j in range(k):  # k different zetas in this layer
            z = zetas[zeta_idx]
            zeta_idx += 1
            
            # Apply butterfly to all groups at position j
            for group_start in range(0, n, 2*k):
                idx1 = group_start + j
                idx2 = idx1 + k
                
                t = (z * a[idx2]) % q
                a[idx2] = (a[idx1] - t) % q
                a[idx1] = (a[idx1] + t) % q
        
        k *= 2
    
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

s = tc['s']
sHat = tc['sHat']

print("Testing corrected NTT...")
sHat_computed = ntt_forward(s[0])

mismatches = 0
for i in range(256):
    if sHat_computed[i] != sHat[0][i]:
        if mismatches < 5:
            print(f"  sHat[0][{i}]: computed={sHat_computed[i]}, expected={sHat[0][i]}")
        mismatches += 1

print(f"Result: {mismatches}/256 mismatches")

if mismatches > 0:
    # Try bit-reversed
    def bit_reverse_8(x):
        r = 0
        for i in range(8):
            r = (r << 1) | (x & 1)
            x >>= 1
        return r
    
    print("\nTrying bit-reversed...")
    mismatches_br = 0
    for i in range(256):
        br_i = bit_reverse_8(i)
        if sHat_computed[i] != sHat[0][br_i]:
            mismatches_br += 1
    print(f"Bit-reversed: {mismatches_br}/256 mismatches")
