# Pikachu - Mobile CTF Challenge Writeup

**Challenge Name:** Soru72: pika pika?  
**Category:** Mobile  
**Difficulty:** Orta (Medium)  
**Description:** Pokitopum nerede?  
**Flag:** `HK{s3ni_secmed1m_pik4chuUu}`

---

## 📋 Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Analysis](#initial-analysis)
3. [Java Code Analysis](#java-code-analysis)
4. [Native Library Analysis](#native-library-analysis)
5. [Decryption Algorithm](#decryption-algorithm)
6. [Solution](#solution)
7. [Conclusion](#conclusion)

---

## 🎯 Challenge Overview

Bu challenge'da bir Android APK dosyası veriliyor. Uygulama, SMS okuma izni istiyor ve belirli bir SMS içeriğine göre flag'i gösteriyor. Pokémon temalı bu challenge'da hem Java hem de native kod analizi yapmamız gerekiyor.

---

## 🔍 Initial Analysis

### Araçlar
- **JADX** - Android APK decompiler
- **Ghidra** - Binary analysis tool
- **Python** - Decryption script

### İlk Adımlar

APK dosyasını JADX ile açıyoruz:

```bash
jadx pikachu.apk
```

Ana uygulama paketi: `com.hk.pikachu`

---

## ☕ Java Code Analysis

### MainActivity.java

JADX'te `MainActivity.java` dosyasını incelediğimizde önemli kodları görüyoruz:

```java
public class MainActivity extends AppCompatActivity {
    // Native metodlar
    public native String check();
    public native String flag(String str, String str2);
    public native String secret();
    public native String whoareyou();
    
    static {
        System.loadLibrary("pikachu");
    }
    
    public void getFlag(View view) {
        if (whoareyou().equals("admin")) {
            if (!checkPermission().booleanValue()) {
                // Permission check
                return;
            }
            collectSms();
            return;
        }
        this.text.setText("sadece adminler görebilir!");
    }
    
    void collectSms() {
        // SMS'leri oku
        for (String item : this.sms_body) {
            if (item.equals(check())) {
                this.found = true;
                this.text.setText(flag(item, secret()));
            }
        }
        if (!this.found.booleanValue()) {
            this.text.setText(pika());
        }
    }
}
```

### Önemli Noktalar

1. **Native kütüphane yükleniyor:** `libpikachu.so`
2. **Flag alma mantığı:**
   - `whoareyou()` "admin" dönmeli
   - SMS body `check()` ile eşleşmeli
   - `flag(sms_body, secret())` flag'i döndürür

3. **Native metodlar:**
   - `check()` → SMS içeriğinin ne olması gerektiği
   - `secret()` → Flag için key
   - `flag()` → Flag'i üretir
   - `whoareyou()` → Kullanıcı türü

---

## 🔧 Native Library Analysis

### libpikachu.so Dosyasını Bulma

JADX'te sol panelde `lib/` klasörünü açıyoruz:
```
lib/
├── arm64-v8a/
│   └── libpikachu.so
├── armeabi-v7a/
│   └── libpikachu.so
├── x86/
└── x86_64/
```

`arm64-v8a/libpikachu.so` dosyasını export ediyoruz.

### Strings Analizi

İlk olarak dosyada ne tür stringler var bakalım:

```bash
strings libpikachu.so
```

**İlginç stringler:**
```
fake_flag}
zayotem
bir seyler yanlis!!!
GHTB[H?XFFM
HJyq0jdXqb_h_])dOjbc+Y]iHgc
hmm... tekrar dene
user
16128
```

### Ghidra ile Decompilation

`libpikachu.so` dosyasını Ghidra'da açıp analiz ediyoruz.

#### 1. `whoareyou()` Fonksiyonu

```c
undefined8 Java_com_hk_pikachu_MainActivity_whoareyou(_JNIEnv *param_1) {
    basic_string abStack_30[24];
    
    basic_string("user");
    return NewStringUTF(param_1, "user");
}
```

**Sonuç:** `"user"` döndürüyor (ama Java kodu `"admin"` bekliyor!)

---

#### 2. `secret()` Fonksiyonu

```c
undefined8 Java_com_hk_pikachu_MainActivity_secret(_JNIEnv *param_1) {
    basic_string abStack_30[24];
    
    basic_string("16128");
    return NewStringUTF(param_1, "16128");
}
```

**Sonuç:** `"16128"` stringini döndürüyor. Bu flag decryption için key.

---

#### 3. `check()` Fonksiyonu

```c
undefined8 Java_com_hk_pikachu_MainActivity_check(_JNIEnv *param_1, ...) {
    char local_28[8] = "GHTB[H?XFFM";
    byte abStack_34[12];
    
    // Her karaktere index değerini ekle
    for (local_80 = 0; local_80 < 0xb; local_80++) {
        abStack_34[local_80] = local_28[local_80] + (char)local_80;
    }
    
    // String'i oluştur
    for (local_8c = 0; local_8c < 0xb; local_8c++) {
        append(abStack_50, abStack_34[local_8c]);
    }
    
    return NewStringUTF(param_1, result);
}
```

**Algoritma:**
```
Encrypted[i] + i = Decrypted[i]
```

**Hesaplama:**
```
G + 0 = G
H + 1 = I
T + 2 = V
B + 3 = E
[ + 4 = _
H + 5 = M
? + 6 = E
X + 7 = _
F + 8 = N
F + 9 = O
M + 10 = W
```

**Sonuç:** SMS body `"GIVE_ME_NOW"` olmalı.

---

#### 4. `flag()` Fonksiyonu

En karmaşık fonksiyon. İki parametre alıyor:
- `param_3`: SMS body (`"GIVE_ME_NOW"`)
- `param_4`: Secret key (`"16128"`)

```c
undefined8 Java_com_hk_pikachu_MainActivity_flag(...) {
    // Secret key'den değerleri çıkar
    c3 = stoi(secret[0]); // 1
    c4 = stoi(secret[1]); // 6
    c5 = stoi(secret[3]); // 2
    c6 = stoi(secret[0]); // 1
    c7 = stoi(secret[4]); // 8
    
    char encrypted[] = "HJyq0jdXqb_h_])dOjbc+Y]iHgc";
    
    // Decode algoritması
    for (i = 0; i < 0x1b; i++) {
        if (3 <= i && i <= 6) {
            decrypted[i] = encrypted[i] + i - c3;
        }
        else if (8 <= i && i <= 15) {
            decrypted[i] = encrypted[i] + i - c4;
        }
        else if (17 <= i && i <= 25) {
            decrypted[i] = encrypted[i] + i - (c5 + c6 + c7);
        }
        else {
            decrypted[i] = encrypted[i] + i;
        }
    }
    
    return decrypted;
}
```

---

## 🔓 Decryption Algorithm

### Secret Key Analizi

```
Secret: "16128"
Index:   01234

c3 = secret[0] = '1' = 1
c4 = secret[1] = '6' = 6
c5 = secret[3] = '2' = 2
c6 = secret[0] = '1' = 1
c7 = secret[4] = '8' = 8
```

### Flag Decryption

Şifrelenmiş flag: `HJyq0jdXqb_h_])dOjbc+Y]iHgc`

**Decryption kuralları:**
- Index 0-2: `encrypted[i] + i`
- Index 3-6: `encrypted[i] + i - 1`
- Index 7: `encrypted[i] + i`
- Index 8-15: `encrypted[i] + i - 6`
- Index 16: `encrypted[i] + i`
- Index 17-25: `encrypted[i] + i - (2+1+8) = encrypted[i] + i - 11`
- Index 26: `encrypted[i] + i`

### Python Decryption Script

```python
#!/usr/bin/env python3

# check() fonksiyonu - SMS body
encrypted_check = "GHTB[H?XFFM"
sms_body = ""

for i in range(len(encrypted_check)):
    sms_body += chr(ord(encrypted_check[i]) + i)

print(f"SMS body: {sms_body}")

# secret() fonksiyonu
secret_key = "16128"
print(f"Secret key: {secret_key}")

# flag() fonksiyonu
encrypted_flag = "HJyq0jdXqb_h_])dOjbc+Y]iHgc"

# Secret key'den değerleri çıkar
c3 = int(secret_key[0])  # 1
c4 = int(secret_key[1])  # 6
c5 = int(secret_key[3])  # 2
c6 = int(secret_key[0])  # 1
c7 = int(secret_key[4])  # 8

# Flag'i decode et
flag = ""
for i in range(len(encrypted_flag)):
    char = encrypted_flag[i]
    
    if 3 <= i <= 6:
        decoded = chr(ord(char) + i - c3)
    elif 8 <= i <= 15:
        decoded = chr(ord(char) + i - c4)
    elif 17 <= i <= 25:
        decoded = chr(ord(char) + i - (c5 + c6 + c7))
    else:
        decoded = chr(ord(char) + i)
    
    flag += decoded

print(f"FLAG: HK{{{flag}}}")
```

---

## 🎯 Solution

### Script Çıktısı

```bash
$ python3 solve.py
SMS body: GIVE_ME_NOW
Secret key: 16128
FLAG: HK{s3ni_secmed1m_pik4chuUu}
```

### Flag

```
HK{s3ni_secmed1m_pik4chuUu}
```


### Tools Used

| Tool | Purpose |
|------|---------|
| JADX | APK decompilation |
| Ghidra | Native binary analysis |
| Python | Decryption script |
| strings | Quick string extraction |

---
