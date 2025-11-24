# Adli Bilişim Uzmanı 2 - CTF Writeup

## 📋 Soru Bilgileri

**Kategori:** Forensics  
**Seviye:** Zor  
**Dosyalar:** `disk.ad1`, `mem.vmem`

**Senaryo:** Müşteri bir EXE dosyası çalıştırmış ve önemli bir dosyasını şifrelemiş. Görev: Şifreleme anahtarını bulup dosyayı geri çözmek.

---

## 🔍 Analiz

### Adım 1: Disk İmajı Analizi (FTK Imager)

`disk.ad1` dosyasını FTK Imager ile açtığımızda Desktop'ta şu dosyaları bulduk:
- `locker_sim.exe` - Şifreleme programı
- `to_encrypt.txt.enc` - Şifrelenmiş dosya

Recycle Bin içinde silinmiş dosyalar:
- `Dc1.txt` - İçeriği: `sigmadroid`
- `INFO2` - Orijinal yol bilgisi: `C:\Documents and Settings\RagdollFan2005\Desktop\secret_part.txt`

**Bulgu 1:** `secret_part = sigmadroid`

---

### Adım 2: Memory Dump Analizi (Volatility)

**Computer Name bulma:**
```bash
vol -f mem.vmem windows.envars.Envars | grep -iE "COMPUTERNAME"
```

Çıktı: `RAGDOLLF-F9AC5A`

**Bulgu 2:** `computer_name = RAGDOLLF-F9AC5A`

**Program argümanı bulma:**

Volatility 3'te consoles çalışmadığı için Volatility 2 kurduk:
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python2 vol.py -f ~/Desktop/mem.vmem --profile=WinXPSP3x86 consoles
```

Çıktıda şu satırı bulduk:
```
C:\Documents and Settings\RagdollFan2005\Desktop>locker_sim.exe hmmisitreallyts
```

**Bulgu 3:** `arg = hmmisitreallyts`

---

### Adım 3: Şifre Çözme

İpuçlarına göre key formatı: `arg|computer_name|secret_part`

**SHA-256 hash hesaplama:**
```bash
echo -n "hmmisitreallyts|RAGDOLLF-F9AC5A|sigmadroid" | sha256sum
```

Çıktı: `1117e5b8fdff9d7be375e7a88354c497b93788da64a3968621499687f10474e5`

**AES-256-CBC ile decrypt:**
```bash
openssl enc -aes-256-cbc -d -in to_encrypt.txt.enc -out decrypted.txt \
  -K "1117e5b8fdff9d7be375e7a88354c497b93788da64a3968621499687f10474e5" \
  -iv "1117e5b8fdff9d7be375e7a88354c497"
```

**Base64 decode (4 kez):**
```bash
cat decrypted.txt | base64 -d | base64 -d | base64 -d | base64 -d
```

---

## 🚩 Flag

```
Securinets{screen+registry+mft??}
```

---

## 🛠️ Kullanılan Araçlar

| Araç | Kullanım Amacı |
|------|----------------|
| FTK Imager | Disk imajı analizi |
| Volatility 2/3 | Memory dump analizi |
| OpenSSL | AES-256-CBC decryption |
| Base64 | Decode işlemleri |

---

## 📝 Öğrenilen Teknikler

1. Windows XP Recycle Bin analizi (INFO2 dosyası)
2. Volatility ile environment variables çıkarma
3. Volatility consoles ile command history bulma
4. AES-256-CBC şifre çözme (key + IV)
5. Çoklu Base64 encoding tespiti
