def q(a, b):
    return max(-128, min(127, (a * b + 8) >> 4))
