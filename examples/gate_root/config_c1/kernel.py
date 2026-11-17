_T = [max(-128, min(127, (a * b + 8) >> 4)) for a in range(-128, 128) for b in range(-128, 128)]
def q(a, b):
    return _T[(a + 128) * 256 + (b + 128)]
