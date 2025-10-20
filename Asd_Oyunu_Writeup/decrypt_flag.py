#!/usr/bin/env python3
"""
ASD Oyunu - Static Flag Extractor
Ghidra analiziyle bulunan algoritmayı kullanarak flag'ı decrypt eder
"""

def decrypt_flag(hex_string, key):
    """
    Decrypt algoritması:
    1. Hex string'i byte array'e çevir
    2. Her byte için: (byte - index) XOR key[i % keylen] - 1
    """
    # Hex to bytes
    encrypted = bytes.fromhex(hex_string)
    
    print(f"Encrypted (hex): {hex_string}")
    print(f"Key: {key}")
    print(f"Length: {len(encrypted)}")
    print()
    
    # Decrypt
    decrypted = []
    for i in range(len(encrypted)):
        # Algoritma: (byte - index) XOR key[i % keylen] - 1
        subtracted = encrypted[i] - i
        xored = subtracted ^ ord(key[i % len(key)])
        result = xored - 1
        
        # Debug için ilk 6 karakteri göster
        if i < 6:
            print(f"[{i}] encrypted={encrypted[i]:02x} - {i} = {subtracted:02x} " +
                  f"XOR '{key[i % len(key)]}' = {xored:02x} - 1 = {result:02x} " +
                  f"= '{chr(result)}'")
        
        decrypted.append(chr(result))
    
    return ''.join(decrypted)


if __name__ == "__main__":
    # Ghidra String arama sonucu (0x140007750)
    hex_flag = "35272c671e232f3c6f19485c663a44288b401f24325993274f54592d4e5e684e484c"
    
    # Ghidra FUN_140002a20 fonksiyonunda bulundu
    key = "asd OYUNU"
    
    print("=" * 70)
    print("ASD OYUNU - STATIC FLAG EXTRACTION")
    print("=" * 70)
    print()

    flag = decrypt_flag(hex_flag, key)

    print()
    print("=" * 70)
    print(f"FLAG: {flag}")
    print("=" * 70)