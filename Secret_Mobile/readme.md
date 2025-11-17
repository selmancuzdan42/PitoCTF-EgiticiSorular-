![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)
![Category](https://img.shields.io/badge/Category-Mobile-red)

# Secret - Mobile CTF Challenge Writeup

## Challenge Bilgileri
- **İsim:** Secret
- **Kategori:** Mobile
- **Seviye:** Orta
- **Açıklama:** Kendi telefonunuzda açmayın. Emülatörde açın veya statik analiz yapın.
- **Flag:** `BSTF{BSidesTLV2023{RE_APK_IS_FUN}}`

---

## Çözüm

### 1. İlk Keşif

Dosya türünü kontrol edelim:
```bash
file Secret.apk
# Output: Secret.apk: Android package (APK), with gradle app-metadata.properties, with APK Signing Block
```

### 2. APK Dekompilasyonu

APK'yı `apktool` ile dekompile ediyoruz:
```bash
apktool d Secret.apk -o Secret_decompiled
cd Secret_decompiled
```

### 3. Manifest Analizi

`AndroidManifest.xml` dosyasını inceliyoruz:
```xml
<activity android:exported="true" android:name="com.example.myctf.MainActivity">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```

Ana aktivite: `com.example.myctf.MainActivity`

### 4. MainActivity.smali Analizi

`smali/com/example/myctf/MainActivity.smali` dosyasında önemli kısımlar:
```smali
.method static constructor <clinit>()V
    const-string v0, "myctf-native"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method

.method private native checkSalt(Ljava/lang/String;)Z
.end method

.method private native getFlag(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
.end method
```

**Bulgular:**
- Uygulama `libmyctf-native.so` adında native library yüklüyor
- İki native fonksiyon var:
  - `checkSalt(String)`: Salt doğrulaması
  - `getFlag(String, String)`: Salt ve PIN ile flag üretimi

### 5. Button Click Handler Analizi

`smali/com/example/myctf/MainActivity$1.smali` incelemesi:
```smali
; Salt ve PIN input'larını al
invoke-virtual {p1}, Landroid/widget/EditText;->getText()

; checkSalt çağır
invoke-static {v1, p1}, Lcom/example/myctf/MainActivity;->access$000(...)Z

; Eğer salt doğruysa getFlag çağır
invoke-static {v1, p1, v0}, Lcom/example/myctf/MainActivity;->access$100(...)Ljava/lang/String;
```

**Akış:**
1. Kullanıcı **SaltText** ve **PinText** giriyor
2. `checkSalt(salt)` ile salt doğrulanıyor
3. Doğruysa `getFlag(salt, pin)` ile flag alınıyor

### 6. Native Library'yi Bulma
```bash
ls -la lib/*/libmyctf-native.so
```

**Çıktı:**
```
-rw-rw-r-- 1 kali kali 289336 Nov 16 05:16 lib/arm64-v8a/libmyctf-native.so
-rw-rw-r-- 1 kali kali 157976 Nov 16 05:16 lib/armeabi-v7a/libmyctf-native.so
-rw-rw-r-- 1 kali kali 295008 Nov 16 05:16 lib/x86_64/libmyctf-native.so
-rw-rw-r-- 1 kali kali 267752 Nov 16 05:16 lib/x86/libmyctf-native.so
```

Analiz için x86_64 versiyonunu kullanacağız (PC mimarisi ile uyumlu, analizi kolay).

### 7. Radare2 ile Reverse Engineering

#### checkSalt Fonksiyonu Analizi
```bash
r2 lib/x86_64/libmyctf-native.so
aaa  # Analiz yap
pdf @sym.Java_com_example_myctf_MainActivity_checkSalt
```

**Kritik assembly kodu:**
```assembly
0x000201ff      4883f804       cmp rax, 4                  ; Salt uzunluğu 4 olmalı
0x00020203      744d           je 0x20252

0x00020252      488d0d1030..   lea rcx, str.l33t           ; 0x13269 ; "l33t"
0x00020259      488d7c2408     lea rdi, [var_8h]
0x0002025e      41b804000000   mov r8d, 4                  ; 4 karakter
0x00020264      31f6           xor esi, esi
0x00020266      48c7c2ffff..   mov rdx, 0xffffffffffffffff
0x0002026d      e81e380200     call fcn.00043a90           ; String karşılaştırma
0x00020272      85c0           test eax, eax
0x00020274      0f94c3         sete bl                     ; bl = 1 if salt == "l33t"
```

✅ **Salt bulundu:** `l33t`

#### getFlag Fonksiyonu Analizi
```bash
pdf @sym.Java_com_example_myctf_MainActivity_getFlag
```

**Kritik kısımlar:**
```assembly
0x00020515      48b82d7272..   movabs rax, 0x777472753572722d ; '-rr5urtw'
0x0002051f      4889442460     mov qword [var_60h], rax
0x00020524      c644246800     mov byte [var_68h], 0
```

Bu değer little-endian formatında saklanmış. Byte'ları ters çevirince: `wtur5rr-`

**XOR Encoding:**
```assembly
0x00020547      0fbe30         movsx esi, byte [rax]
0x0002054a      83f641         xor esi, 0x41               ; Her karakter 0x41 ('A') ile XOR ediliyor
0x0002054d      488d7c2440     lea rdi, [var_40h]
0x00020552      e869350200     call fcn.00043ac0           ; String'e ekleme
```

Kod, salt+pin birleşiminin her karakterini 0x41 ile XOR yapıyor ve `wtur5rr-` ile karşılaştırıyor.

### 8. PIN'i Decode Etme
```python
target = "wtur5rr-"
result = ""

for char in target:
    result += chr(ord(char) ^ 0x41)

print(f"Salt + Pin: {result}")
# Output: 6543t33l
```

- İlk 4 karakter salt: `l33t` ✅
- Son 4 karakter PIN: `t33l`

✅ **PIN bulundu:** `t33l`

### 9. Flag Data'sını Extract Etme

Assembly kodunda offset `0x00014310`'da flag için kullanılan encrypted data var:
```bash
r2 lib/x86_64/libmyctf-native.so
px 28 @ 0x00014310
```

**Çıktı:**
```
- offset -  1011 1213 1415 1617 1819 1A1B 1C1D 1E1F  0123456789ABCDEF
0x00014310  0312 2825 2432 150d 1773 7173 723a 1304  ..(%$2...sqsr:..
0x00014320  1e00 110a 1e08 121e 0714 0f3c            ...........
```

Hex formatında:
```bash
p8 28 @ 0x00014310
# Output: 031228252432150d17737173723a13041e00110a1e08121e07140f3c
```

### 10. Flag'i Decode Etme

Flag data'sı da 0x41 ile XOR edilmiş:
```python
data = bytes.fromhex("031228252432150d17737173723a13041e00110a1e08121e07140f3c")
flag = ""

for byte in data:
    flag += chr(byte ^ 0x41)

print(f"Decoded: {flag}")
# Output: BSidesTLV2023{RE_APK_IS_FUN}

print(f"Flag: BSTF{{{flag}}}")
# Output: BSTF{BSidesTLV2023{RE_APK_IS_FUN}}
```

---

## Özet Çözüm Adımları

1. ✅ **APK dekompile** edildi (`apktool d Secret.apk`)
2. ✅ **MainActivity.smali** analiz edildi → Native library tespit edildi
3. ✅ **libmyctf-native.so** radare2 ile disassemble edildi
4. ✅ **checkSalt** fonksiyonu analizi → Salt: `l33t` bulundu
5. ✅ **getFlag** fonksiyonunda XOR encoding keşfedildi (0x41 key)
6. ✅ Target string `wtur5rr-` decode edildi → PIN: `t33l`
7. ✅ Flag data offset `0x00014310`'dan extract edildi
8. ✅ XOR decoding ile flag elde edildi

---

## Kullanılan Araçlar

| Araç | Kullanım Amacı |
|------|----------------|
| `apktool` | APK dekompilasyonu |
| `radare2` | Native library disassembly ve reverse engineering |
| `Python 3` | XOR decoding scriptleri |
| `xxd/hexdump` | Binary data görüntüleme |

---

## Teknik Detaylar

### XOR Encryption Analizi

- **XOR Key:** `0x41` (ASCII 'A')
- **Algoritma:** `plaintext[i] ^ 0x41 = ciphertext[i]`
- **Reverse:** `ciphertext[i] ^ 0x41 = plaintext[i]`

### Credentials

- **Salt:** `l33t` (4 karakter)
- **PIN:** `t33l` (4 karakter)
- **Combined:** `l33tt33l` → XOR 0x41 → `wtur5rr-`

---



## Flag
```
BSTF{BSidesTLV2023{RE_APK_IS_FUN}}
```
