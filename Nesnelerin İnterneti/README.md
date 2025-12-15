# ITUCTF - Nesnelerin İnterneti (IoT) Writeup

**Kategori:** Misc (IoT)  
**Zorluk:** Orta  
**Flag:** `ITUCTF{smart_washer_backdoor}`

---

## Özet

Bu soruda IoT cihazı (akıllı çamaşır makinesi) ile ilgili üç dosya verildi. MQTT trafiğinden AES şifreleme anahtarını çıkarıp, şifrelenmiş JSON dosyasındaki flag'i çözdük.

---

## Verilen Dosyalar
```
app_traffic.pcap          # Ağ trafiği yakalama dosyası
washer_config.enc.json    # Şifrelenmiş konfigürasyon
washer_firmware.bin       # Çamaşır makinesi firmware'i
```

---

## Çözüm Adımları

### Adım 1: PCAP Dosyasının İncelenmesi

MQTT protokolü kullanan IoT cihazları genellikle düz metin olarak veri gönderir. Wireshark veya tshark ile PCAP dosyasını inceledik:
```bash
tshark -r app_traffic.pcap
```

İlk pakette MQTT Publish mesajı dikkatimizi çekti:
```
1  0.000000  160.75.91.89  192.168.1.100  MQTT  88  Publish Message [washer]
```

Wireshark'ta bu pakete sağ tıklayıp **"Follow → TCP Stream"** seçeneğini kullandığımızda şifreleme anahtarını bulduk:
```
key:63feea64418d90ee2241153632766846
```

**Bulgu:** 32 karakterlik hex anahtar (16 byte = 128-bit AES anahtarı)

---

### Adım 2: Şifrelenmiş JSON Dosyasının İncelenmesi
```bash
cat washer_config.enc.json
```

Çıktı:
```json
{
    "device_name": "SmartWasher",
    "mqtt_broker": "192.168.1.100",
    "mqtt_port": 1883,
    "flag": {
        "iv": "Mu2yQqeHK04lRpdFozVYqw==",
        "data": "ZV4fQSmDoPIcNwyDLZcADa858SfmY6Sjc+3H3tSqTC0="
    }
}
```

**Analiz:**
- `iv`: Base64 encoded Initialization Vector (AES-CBC için gerekli)
- `data`: Base64 encoded şifrelenmiş flag
- Şifreleme modu: **AES-128-CBC** (IV kullanımından anlaşılıyor)

---

### Adım 3: Flag'in Şifresinin Çözülmesi

Python ve `pycryptodome` kütüphanesi kullanarak şifreyi çözdük:
```python
from Crypto.Cipher import AES
import base64
import json

# Anahtar (MQTT trafiğinden elde edildi)
key = bytes.fromhex('63feea64418d90ee2241153632766846')

# JSON dosyasını oku
with open('washer_config.enc.json', 'r') as f:
    config = json.load(f)

# IV ve şifrelenmiş veriyi decode et
iv = base64.b64decode(config['flag']['iv'])
encrypted_data = base64.b64decode(config['flag']['data'])

# AES-CBC ile şifreyi çöz
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(encrypted_data)

# PKCS7 padding'i temizle
padding_length = decrypted[-1]
flag = decrypted[:-padding_length].decode('utf-8')

print("FLAG:", flag)
```

**Tek satırda çalıştırma:**
```bash
python3 -c "from Crypto.Cipher import AES; import base64, json; key = bytes.fromhex('63feea64418d90ee2241153632766846'); config = json.load(open('washer_config.enc.json')); iv = base64.b64decode(config['flag']['iv']); data = base64.b64decode(config['flag']['data']); cipher = AES.new(key, AES.MODE_CBC, iv); dec = cipher.decrypt(data); print(dec[:-dec[-1]].decode())"
```

**Çıktı:**
```
FLAG: ITUCTF{smart_washer_backdoor}
```

---

## Flag
```
ITUCTF{smart_washer_backdoor}
```

---
