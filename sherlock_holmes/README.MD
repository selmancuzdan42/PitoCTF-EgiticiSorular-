# Sherlock Holmes - Memory Forensics WriteUp

## 📋 Genel Bakış

Bu depo, **Sherlock Holmes** adlı forensics challenge'ının çözümünü içermektedir. Challenge, phishing e-postası yoluyla bulaşmış bir sistemin bellek dökümünü analiz ederek kötü amaçlı yazılımı tespit etmeyi ve bayrağı bulmayı amaçlamaktadır.

**Challenge Bilgileri:**
- **Kategori:** Forensics
- **Seviye:** Orta
- **Araç:** Volatility 3

---

## 📁 Depo İçeriği

- **[sherlock-holmes-writeup.md](sherlock-holmes-writeup.md)** - Detaylı analiz süreci, bulgular ve bayrak
- **[volatility3_komutlari.md](volatility3_komutlari)** - Kullanabileceğimiz Volatility Komutları
- **README.md** - Bu dosya (genel bakış ve hızlı başlangıç)

---

## 🚀 Hızlı Başlangıç

### Gereksinimler
```bash
# Volatility 3 kurulumu (Kali Linux)
sudo apt install pipx
pipx install volatility3
```

### Temel Analiz Adımları

1. **Süreçleri Listele**
```bash
vol -f flounder-pc-memdump.elf windows.pslist
```

2. **Komut Satırlarını İncele**
```bash
vol -f flounder-pc-memdump.elf windows.cmdline
```

3. **Base64 Payloadları Decode Et**
```bash
echo 'BASE64_STRING' | base64 -d
```

4. **Bayrağı Bul**
```
HTB{$_j0G_y0uR_M3m0rY_$}
```

---

## 🔍 Önemli Bulgular

- **PID 2812** - thunderbird.exe (E-posta istemcisi)
- **PID 496** - powershell.exe (İlk aşama malware)
- **PID 2752** - powershell.exe (İkinci aşama malware - bayrak burada)

**Saldırı Zinciri:**
```
Phishing E-posta → resume.zip → resume.pdf.lnk → PowerShell Stage 1 → PowerShell Stage 2 (C2 Beacon)
```

---

## 🛠️ Kullanışlı Volatility 3 Komutları
```bash
# Süreç listeleme
vol -f memory.dump windows.pslist
vol -f memory.dump windows.pstree

# Komut satırı parametreleri
vol -f memory.dump windows.cmdline

# Ağ bağlantıları
vol -f memory.dump windows.netscan

# Dosya tarama
vol -f memory.dump windows.filescan
vol -f memory.dump windows.filescan | grep -i "resume"

# Malware tespiti
vol -f memory.dump windows.malfind
vol -f memory.dump windows.psxview
```

---

## 🏆 Flag
```
HTB{$_j0G_y0uR_M3m0rY_$}
```

---

## ⚠️ Uyarı

Bu writeup **sadece eğitim amaçlıdır**. Kötü amaçlı kullanım kesinlikle yasaktır. Bu teknikleri yalnızca kendi sistemlerinizde veya yasal izin aldığınız sistemlerde kullanın.

---
