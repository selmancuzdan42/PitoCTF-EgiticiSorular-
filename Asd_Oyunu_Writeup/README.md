# ASD Oyunu - CTF Writeup

Bu repository, **ASD Oyunu** adlı Reverse Engineering CTF challenge'ının çözümünü içermektedir.

## 📋 Challenge Bilgileri

- **Challenge:** ASD Oyunu
- **Kategori:** Reverse Engineering / Game
- **Seviye:** Zor
- **Flag:** `STMCTF{z1pL4yanK4ykayc1Hatir@$i_p}`

## 🎯 Özet

Bu challenge'da bir SDL2 oyunu veriliyor ve oyunu çalıştırıp kazanarak flag'ı elde etmemiz bekleniyor. Ancak program "no license." hatası vererek kapanıyor. Bu writeup'ta **tamamen statik analiz** kullanarak flag'ı nasıl elde ettiğimizi gösteriyoruz.

## 🛠️ Kullanılan Araçlar

- **Ghidra** - Binary analizi ve reverse engineering
- **Python** - Flag decrypt script'i
- **File** komutu - Binary türü tespiti

## 🔍 Çözüm Yaklaşımı

1. **Statik Analiz:** Dinamik çözüm yerine Ghidra ile binary analizi
2. **String Arama:** Hex encoded flag'ın bulunması
3. **Algoritma Analizi:** XOR decrypt mekanizmasının çözülmesi
4. **Manuel Decrypt:** Python script ile flag'ın elde edilmesi

## 📁 Dosyalar

- `asd_oyunu_writeup copy.md` - Detaylı writeup ve çözüm süreci
- `decrypt_flag.py` - Flag decrypt script'i (writeup içinde)

## 🚀 Hızlı Başlangıç

1. Repository'yi klonlayın:
```bash
git clone https://github.com/[username]/asd-oyunu-writeup.git
cd asd-oyunu-writeup
```

2. Detaylı writeup'ı okuyun:
```bash
# Markdown viewer ile açın veya GitHub'da görüntüleyin
```

3. Decrypt script'ini çalıştırın:
```python
# Writeup içindeki Python kodunu kopyalayıp çalıştırın
python decrypt_flag.py
```

## 🔑 Decrypt Algoritması

Ghidra analiziyle bulunan algoritma:

```python
def decrypt_flag(hex_string, key):
    encrypted = bytes.fromhex(hex_string)
    decrypted = []
    
    for i in range(len(encrypted)):
        # (byte - index) XOR key[i % keylen] - 1
        subtracted = encrypted[i] - i
        xored = subtracted ^ ord(key[i % len(key)])
        result = xored - 1
        decrypted.append(chr(result))
    
    return ''.join(decrypted)
```

**Key:** `"asd OYUNU"`  
**Encrypted Hex:** `35272c671e232f3c6f19485c663a44288b401f24325993274f54592d4e5e684e484c`

## 🎯 Sonuç

Bu challenge tamamen statik analizle çözüldü. Programı hiç çalıştırmadan, sadece Ghidra'daki kod okuma ve algoritma anlama becerileriyle flag elde edildi.

## 📚 Öğrenilen Konular

- PE binary analizi
- Ghidra kullanımı ve string arama
- Cross-reference takibi
- XOR şifreleme/çözme
- Hex encoding/decoding
- Statik analiz teknikleri

## 🤝 Katkıda Bulunma

Bu writeup'ı geliştirmek için:

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/improvement`)
3. Değişikliklerinizi commit edin (`git commit -am 'Add improvement'`)
4. Branch'inizi push edin (`git push origin feature/improvement`)
5. Pull Request oluşturun

## 📄 Lisans

Bu proje eğitim amaçlıdır ve MIT lisansı altında paylaşılmaktadır.

---

**Not:** Bu writeup sadece eğitim amaçlıdır. CTF challenge'larını çözmek için kullanılan teknikler, sadece yasal ve etik amaçlarla kullanılmalıdır.