# ASD Oyunu - CTF Writeup

**Challenge:** ASD Oyunu  
**Kategori:** Reverse Engineering / Game  
**Seviye:** Zor  
**Flag:** `STMCTF{z1pL4yanK4ykayc1Hatir@$i_p}`

---

## 🎯 Challenge Açıklaması

Bu challenge'da bir SDL2 oyunu veriliyor. Oyunu çalıştırıp kazanarak flag'ı elde etmemiz bekleniyor. Ancak ilk çalıştırmada program hata veriyor.

---

## 🔍 İlk Deneme

Programı çalıştırdığımızda:

```bash
C:\Users\Selman\Desktop\asdOyunu (1)\asdOyunu>asd.exe
no license.
```

Program "no license." mesajı vererek kapanıyor. Dinamik yöntemle çözmek yerine statik analiz yapmaya karar verdik.

---

## 🛠️ Statik Analiz - Ghidra

### Dosya İnceleme

```bash
$ file asd.exe
asd.exe: PE32+ executable (console) x86-64, for MS Windows
```

64-bit Windows PE dosyası. Ghidra'ya yükleyip analiz başlatıyoruz.

### Entry Point ve Main Bulma

1. **Entry Point:** `0x140005830`
2. Entry'den takip ederek **Main fonksiyonu:** `0x1400032b0`

---

## 🔐 Lisans Kontrolü Analizi

Main fonksiyonda (`FUN_1400032b0`) lisans kontrolünü buluyoruz:

```c
void FUN_1400032b0(void) {
    // ... kod ...
    
    // String oluştur: "Yarin_Cumhuriyet_ilan_edecegiz" (underscore ile)
    FUN_140004430(&local_5b0, "Yarin_Cumhuriyet_ilan_edecegiz", 0x1e);
    
    // Karşılaştır: "Yarin Cumhuriyet ilan edecegiz" (boşluk ile)
    if ((local_5a0 == 0x1e) &&
       (memcmp(string, "Yarin Cumhuriyet ilan edecegiz", 0x1e) == 0)) {
        // Başarılı
        cout << " _--_--_--_--_--_--_--_--_--_--_ ";
    } else {
        // Başarısız
        cout << "no license.";
        TerminateProcess(GetCurrentProcess(), 1);
    }
    
    // ... devam eder ...
}
```

**Önemli Bulgu:** Program bir lisans kontrolü yapıyor ama "_" (underscore) ile " " (boşluk) karakterlerini karşılaştırıyor. Bu asla eşleşmez!

**Karar:** Dinamik patch yapmak yerine, programın geri kalanını analiz edip flag'ı direkt bulmaya çalışalım.

---

## 🎮 Flag Mekanizmasını Bulma

### Adım 1: String Arama

Ghidra'da **Search → For Strings** (Ctrl+Shift+E) diyoruz.

İlginç bir hex string buluyoruz:

```
Address: 0x140007750
String: "35272c671e232f3c6f19485c663a44288b401f24325993274f54592d4e5e684e484c"
```

Bu açıkça hex encoded bir veri!

### Adım 2: Cross Reference Takibi

Hex string'e sağ tık → **References → Show References to Address**

```
From 0x14000100a in FUN_140001000 [DATA]
```

Fonksiyona gidiyoruz:

```c
void FUN_140001000(void) {
    // Hex string'i global değişkene kopyalıyor
    FUN_140004430(&DAT_14000b798,
                  "35272c671e232f3c6f19485c663a44288b401f24325993274f54592d4e5e684e484c",
                  0x44);
    atexit(FUN_140006600);
    return;
}
```

**Global Değişken:** `DAT_14000b798` - Flag burada saklanıyor!

### Adım 3: Hex Decode Fonksiyonu

`DAT_14000b798` adresine sağ tık → **Show References** → Birçok fonksiyon kullanıyor.

`FUN_1400013d0` fonksiyonunu inceliyoruz:

```c
void FUN_1400013d0(longlong *param_1, undefined8 *param_2) {
    // Hex string'i byte array'e çevirme
    
    uVar4 = param_2[2];  // String uzunluğu
    
    if (uVar4 != 0) {
        do {
            // 2 karakter al
            sVar10 = 2;
            if (uVar4 - uVar9 < 2) {
                sVar10 = uVar4 - uVar9;
            }
            
            puVar5 = param_2;
            if (0xf < (ulonglong)param_2[3]) {
                puVar5 = (undefined8 *)*param_2;
            }
            
            // 2 hex karakteri kopyala
            FUN_140004430(&local_70, (void *)((longlong)puVar5 + uVar9), sVar10);
            
            // strtol ile hex'i int'e çevir
            lVar3 = strtol((char *)ppppcVar8, (char **)&local_48, 0x10);
            
            // Sonuç buffer'a ekle
            *(char *)((longlong)plVar7 + uVar4) = (char)lVar3;
            
            uVar9 = uVar9 + 2;  // 2 karakter ilerle
        } while (uVar9 < uVar4);
    }
}
```

Bu fonksiyon hex string'i byte array'e çeviriyor!

### Adım 4: XOR Decrypt Mekanizması

Render fonksiyonunda (`FUN_140002a20`) decrypt işlemini buluyoruz:

```c
void FUN_140002a20(void) {
    // ... render kodu ...
    
    // "asd OYUNU" string'ini oluştur
    FUN_140004430(&local_c0, "asd OYUNU", 9);
    
    // Hex decode et
    puVar11 = (undefined8 *)FUN_1400013d0((longlong *)&local_80, &local_100);
    
    // XOR decrypt loop
    if (puVar11[2] != 0) {
        do {
            puVar23 = puVar11;
            if (0xf < (ulonglong)puVar11[3]) {
                puVar23 = (undefined8 *)*puVar11;
            }
            
            puVar17 = &local_c0;
            if (0xf < local_a8) {
                puVar17 = local_c0;
            }
            
            // DECRYPT ALGORITHM:
            // decrypted[i] = (encrypted[i] - i) ^ key[i % key_length]
            *(byte *)((longlong)puVar12 + uVar24) =
                 *(char *)((longlong)puVar23 + uVar24) - (char)uVar24 ^
                 *(byte *)(uVar24 % local_b0 + (longlong)puVar17);
            
            uVar24 = uVar24 + 1;
        } while (uVar24 < (ulonglong)puVar11[2]);
    }
    
    // Son adım: -1
    // decrypted[i] = decrypted[i] - 1
    
    // ... devam eder ...
}
```

**Decrypt Algoritması Bulundu!**

1. Hex string'i byte'lara çevir
2. Her byte için: `(byte - index) XOR key[i % keylen]`
3. Sonuca 1 çıkar
4. Key: `"asd OYUNU"`

---

## 🔓 Flag'ı Manuel Olarak Çıkarma

Artık tüm bilgiye sahibiz. Python ile decrypt edelim.

**Decrypt Script:** Bu repository'de `decrypt_flag.py` dosyası olarak bulunmaktadır.

### Algoritma Özeti:
1. Hex string'i byte'lara çevir: `35272c671e232f3c6f19485c663a44288b401f24325993274f54592d4e5e684e484c`
2. Key: `"asd OYUNU"`
3. Her byte için: `(byte - index) XOR key[i % keylen] - 1`

### Script'i Çalıştırıyoruz:

```bash
$ python decrypt_flag.py
======================================================================
ASD OYUNU - STATIC FLAG EXTRACTION
======================================================================

Encrypted (hex): 35272c671e232f3c6f19485c663a44288b401f24325993274f54592d4e5e684e484c
Key: asd OYUNU
Length: 34

[0] encrypted=35 - 0 = 35 XOR 'a' = 54 - 1 = 53 = 'S'
[1] encrypted=27 - 1 = 26 XOR 's' = 55 - 1 = 54 = 'T'
[2] encrypted=2c - 2 = 2a XOR 'd' = 4e - 1 = 4d = 'M'
[3] encrypted=67 - 3 = 64 XOR ' ' = 44 - 1 = 43 = 'C'
[4] encrypted=1e - 4 = 1a XOR 'O' = 55 - 1 = 54 = 'T'
[5] encrypted=23 - 5 = 1e XOR 'Y' = 47 - 1 = 46 = 'F'

======================================================================
FLAG: STMCTF{z1pL4yanK4ykayc1Hatir@$i_p}
======================================================================
```

---

## 🎯 Sonuç

**FLAG:** `STMCTF{z1pL4yanK4ykayc1Hatir@$i_p}`

### Çözüm Özeti

1. ✅ Program çalıştırıldı → "no license." hatası
2. ✅ Dinamik çözüm yerine statik analiz kararı
3. ✅ Ghidra ile binary analizi
4. ✅ String arama → Hex encoded flag bulundu
5. ✅ Cross-reference takibi → Flag'ın saklandığı yer
6. ✅ Hex decode fonksiyonu analizi
7. ✅ XOR decrypt algoritması bulundu
8. ✅ Key'in "asd OYUNU" olduğu tespit edildi
9. ✅ Python ile manuel decrypt
10. ✅ Flag elde edildi!

## 📎 Repository Dosyaları

Bu repository'de şu dosyalar bulunmaktadır:

- **`asd_oyunu_writeup.md`** - Bu detaylı writeup dosyası
- **`decrypt_flag.py`** - Flag decrypt script'i (çalıştırılabilir)
- **`README.md`** - GitHub repository açıklaması

### Decrypt Script Kullanımı

```bash
# Script'i çalıştır
python decrypt_flag.py

# Çıktı:
# FLAG: STMCTF{z1pL4yanK4ykayc1Hatir@$i_p}
```

Script, Ghidra analiziyle bulunan algoritmayı kullanarak flag'ı otomatik olarak decrypt eder.

---

## 🙏 Son Notlar

Bu challenge'ı sadece statik analizle çözebildik. Programı hiç çalıştırmadan, Ghidra'daki kod okuma ve algoritma anlama becerilerimizle flag'ı elde ettik.
