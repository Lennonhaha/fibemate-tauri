#!/usr/bin/env python3
"""
NTT implementation based on known-correct reference

The issue is that ML-KEM uses a specific NTT variant.
Let me implement it exactly as specified in the standard.
"""

q = 3329

# Zetas for ML-KEM NTT
# From FIPS 203 / Kyber reference
zetas = [
    1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2783,
    3265, 183, 1154, 2312, 224, 1435, 3173, 1324, 178, 591, 1997, 881,
    2409, 2393, 1708, 1517, 1107, 90, 1503, 1810, 2475, 1331, 2426, 2382,
    1470, 1601, 1979, 2248, 2278, 1066, 1701, 961, 239, 2277, 2455, 1639,
    1215, 1229, 2491, 1734, 2340, 2471, 1503, 1202, 443, 2043, 2419, 1316,
    899, 1724, 1388, 2065, 2206, 246, 472, 1508, 2184, 472, 2308, 1340,
    460, 929, 2440, 2127, 2219, 146, 489, 2438, 2349, 1267, 2010, 2078,
    2372, 310, 492, 110, 1322, 728, 2173, 2255, 2063, 847, 135, 1432,
    2389, 445, 2393, 1554, 1787, 2387, 1332, 3073, 1403, 504, 2575, 881,
    2047, 11, 2331, 654, 729, 1034, 211, 1710, 2437, 146, 2194, 2103,
    1273, 2306, 219, 1295, 2109, 1904, 2964, 1363, 1259, 3171, 2804, 235,
    2862, 806, 2096, 1164, 707, 2992, 2234, 2756, 1315, 978, 1430, 2384,
    615, 1291, 1101, 2584, 2558, 1457, 1997, 1697, 1479, 427, 2896, 1493,
    1877, 2557, 1439, 955, 1139, 480, 2479, 2143, 1263, 2384, 823, 2021,
    150, 1320, 2415, 1263, 883, 2261, 1612, 2260, 99, 2388, 106, 781
]

print(f"Number of zetas: {len(zetas)}")

def ntt_layer(a, start, step, z):
    """Single butterfly layer"""
    for i in range(start, 256, step):
        t = (z * a[i + step//2]) % q
        a[i + step//2] = (a[i] - t) % q
        a[i] = (a[i] + t) % q
    return a

def ntt_forward(f):
    """
    ML-KEM NTT forward transform.
    
    This follows the exact structure from the reference implementation.
    """
    a = [((x % q) + q) % q for x in f]
    
    # Layer 0: 128 groups of 2
    # Each pair: (a[2i], a[2i+1]) with zeta=1
    for i in range(0, 256, 2):
        t = a[i+1]
        a[i+1] = (a[i] - t) % q
        a[i] = (a[i] + t) % q
    
    # Remaining layers use zetas
    zeta_idx = 0
    length = 4
    
    while length <= 128:
        half = length // 2
        for start in range(0, 256, length):
            z = zetas[zeta_idx]
            zeta_idx += 1
            for j in range(half):
                idx1 = start + j
                idx2 = idx1 + half
                t = (z * a[idx2]) % q
                a[idx2] = (a[idx1] - t) % q
                a[idx1] = (a[idx1] + t) % q
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

# Test
file = r'D:\fibemate-electron\src\test-vectors\intermediate-2023\PQC Intermediate Values\Key Generation -- ML-KEM-768.txt'
tc = parse_kat_file(file)

s = tc['s']
sHat = tc['sHat']

print("\nTesting NTT with reference zetas...")
sHat_computed = ntt_forward(s[0])

mismatches = 0
for i in range(256):
    if sHat_computed[i] != sHat[0][i]:
        if mismatches < 5:
            print(f"  sHat[0][{i}]: computed={sHat_computed[i]}, expected={sHat[0][i]}")
        mismatches += 1

print(f"Result: {mismatches}/256 mismatches")

# If still failing, try without first layer (which might be implicit)
if mismatches == 256:
    print("\nTrying without explicit first layer...")
    
    def ntt_forward_v2(f):
        a = [((x % q) + q) % q for x in f]
        
        zeta_idx = 0
        length = 2
        
        while length <= 128:
            half = length // 2
            for start in range(0, 256, length):
                z = zetas[zeta_idx]
                zeta_idx += 1
                for j in range(half):
                    idx1 = start + j
                    idx2 = idx1 + half
                    t = (z * a[idx2]) % q
                    a[idx2] = (a[idx1] - t) % q
                    a[idx1] = (a[idx1] + t) % q
            length *= 2
        
        return a
    
    sHat_v2 = ntt_forward_v2(s[0])
    mismatches_v2 = sum(1 for i in range(256) if sHat_v2[i] != sHat[0][i])
    print(f"V2: {mismatches_v2}/256 mismatches")
