# Findthekey - CTF Writeup

**Kategori:** Reverse Engineering  
**Seviye:** Orta  
**Flag:** `0x00CTF{0bfU5c473D_PtR4Z3}`

## Özet

Bu challenge'da XOR encryption ile şifrelenmiş string'ler ve obfuscated pointer'lar içeren bir Linux binary'sini reverse engineering yaparak doğru şifreyi bulmamız ve flag'i elde etmemiz gerekiyordu.

## İlk Analiz

Binary'yi çalıştırdığımızda basit bir password prompt ile karşılaşıyoruz:

```bash
$ ./Findthekey
Welcome to the Twinlight Zone!!!
Password: test
Keep Trying!
```

Program bir şifre bekliyor ve yanlış girişlerde "Keep Trying!" mesajı veriyor.

## Ghidra ile Statik Analiz

### 1. Fonksiyon Keşfi

Binary'yi Ghidra'da açtığımızda entry point'ten başlayarak ana fonksiyona ulaşıyoruz:

**Entry Point** (`0x004006f0`):
```c
void processEntry entry(undefined8 param_1, undefined8 param_2)
{
  __libc_start_main(FUN_00400b62, ...);
}
```

Main fonksiyonu `FUN_00400b62` sadece "Hello World!" yazıyor - bu bir red herring. Asıl işlem başka fonksiyonlarda gerçekleşiyor.

### 2. XOR Decrypt Fonksiyonu Bulma

`FUN_004007dd` adresinde ilginç bir fonksiyon buluyoruz:

```c
void FUN_004007dd(long param_1, int param_2)
{
  int local_c;
  
  for (local_c = 0; local_c < param_2; local_c = local_c + 1) {
    putchar((uint)(byte)PTR_DAT_00602098[local_c % DAT_00602090] ^ 
            (int)*(char *)(param_1 + local_c));
  }
  fflush(stdout);
}
```

Bu fonksiyon açıkça bir **XOR decryption** işlemi yapıyor:
- Şifrelenmiş data'yı alıyor
- Cyclic XOR key ile decrypt ediyor
- Her karakteri ekrana yazdırıyor

### 3. Ana Kontrol Fonksiyonu

`FUN_00400a03` ana program akışını kontrol ediyor:

```c
undefined8 FUN_00400a03(void)
{
  ssize_t sVar1;
  undefined1 local_98[136];
  
  // "Welcome to the Twinlight Zone!!!" yazdır
  FUN_004007dd(PTR_DAT_006020a8, DAT_006020a0);
  
  // "Password: " yazdır
  FUN_004007dd(PTR_DAT_006020b8, DAT_006020b0);
  
  // Kullanıcıdan input al (maksimum 128 byte)
  memset(local_98, 0, 0x80);
  sVar1 = read(0, local_98, 0x80);
  
  // Eğer tam 9 byte girildiyse kontrol et
  if (sVar1 == 9) {
    FUN_0040084e(local_98);
  }
  
  // "Keep Trying!" yazdır
  FUN_004007dd(PTR_DAT_006020c8, DAT_006020c0);
  
  return 0;
}
```

**Kritik Bulgu:** Program **tam 9 byte** input bekliyor!

### 4. Password Validation Fonksiyonu

`FUN_0040084e` fonksiyonu şifre doğrulama mantığını içeriyor:

```c
undefined8 FUN_0040084e(byte *param_1)
{
  byte local_d;
  int local_c;
  
  // İlk 8 byte'ı kontrol et
  if ((((((*param_1 ^ *PTR_DAT_00602088) == 0x30) && 
        ((param_1[1] ^ PTR_DAT_00602088[1]) == 0x78)) &&
       ((param_1[2] ^ PTR_DAT_00602088[2]) == 0x30)) &&
      (((param_1[3] ^ PTR_DAT_00602088[3]) == 0x30 && 
        ((param_1[4] ^ PTR_DAT_00602088[4]) == 0x43)))) && 
     (((param_1[5] ^ PTR_DAT_00602088[5]) == 0x54 &&
       ((param_1[6] ^ PTR_DAT_00602088[6]) == 0x46 &&
        ((param_1[7] ^ PTR_DAT_00602088[7]) == 0x7b)))))) {
    
    // Başarılı! Flag'i decrypt et ve yazdır
    for (local_c = 0; local_c < DAT_00602080; local_c = local_c + 1) {
      local_d = PTR_DAT_00602088[local_c] ^ param_1[local_c % 8];
      write(1, &local_d, 1);
    }
    exit(1);
  }
  return 0xffffffff;
}
```

Bu fonksiyon şunları kontrol ediyor:
- `input[0] ^ key[0] = 0x30` ('0')
- `input[1] ^ key[1] = 0x78` ('x')
- `input[2] ^ key[2] = 0x30` ('0')
- `input[3] ^ key[3] = 0x30` ('0')
- `input[4] ^ key[4] = 0x43` ('C')
- `input[5] ^ key[5] = 0x54` ('T')
- `input[6] ^ key[6] = 0x46` ('F')
- `input[7] ^ key[7] = 0x7b` ('{')

Yani XOR'dan sonra **"0x00CTF{"** elde etmemiz gerekiyor!

### 5. XOR Key'ini Bulma

Data segment'ini incelediğimizde önemli pointer'ları buluyoruz:

```
00602080: DAT_00602080 = 0x0000001B    // 27 (encrypted flag uzunluğu)
00602088: PTR_DAT_00602088 = 0x00400c18  // XOR key pointer
00602090: DAT_00602090 = 0x00000006    // 6 (key modulo değeri, ama 8 byte kullanılıyor)
```

`0x00400c18` adresindeki XOR key:

```
00400c18: 01 16 79 44 04 64 12 5A
```

Bu 8 byte'lık key, hem validation hem de flag decryption için kullanılıyor.

### 6. Şifre Hesaplama

XOR'un tersine çevrilebilir olması özelliğini kullanarak:

```
input[i] = expected[i] ⊕ key[i]
```

Python ile hesaplama:

```python
expected = [0x30, 0x78, 0x30, 0x30, 0x43, 0x54, 0x46, 0x7b]  # "0x00CTF{"
key = [0x01, 0x16, 0x79, 0x44, 0x04, 0x64, 0x12, 0x5A]

input_bytes = []
for i in range(8):
    input_bytes.append(expected[i] ^ key[i])

# Sonuç:
# input[0] = 0x30 ^ 0x01 = 0x31 = '1'
# input[1] = 0x78 ^ 0x16 = 0x6E = 'n'
# input[2] = 0x30 ^ 0x79 = 0x49 = 'I'
# input[3] = 0x30 ^ 0x44 = 0x74 = 't'
# input[4] = 0x43 ^ 0x04 = 0x47 = 'G'
# input[5] = 0x54 ^ 0x64 = 0x30 = '0'
# input[6] = 0x46 ^ 0x12 = 0x54 = 'T'
# input[7] = 0x7b ^ 0x5A = 0x21 = '!'

password = "1nItG0T!"
```

9. byte için kapanış parantezi ekliyoruz: `}`

**Tam Şifre:** `1nItG0T!}`

## Çözüm ve Flag

Binary'yi doğru şifre ile çalıştırdığımızda:

```bash
$ ./Findthekey
Welcome to the Twinlight Zone!!!
Password: 1nItG0T!}
0x00CTF{0bfU5c473D_PtR4Z3}
```

Flag decrypt edilip ekrana yazdırılıyor!

## Flag Analizi

Flag: `0x00CTF{0bfU5c473D_PtR4Z3}`



## Sonuç

Bu challenge, temel reverse engineering becerilerini test eden güzel bir soruydu. XOR encryption'ın matematiksel özelliklerini kullanarak ve Ghidra ile statik analiz yaparak çözüme ulaştık.

**Flag:** `0x00CTF{0bfU5c473D_PtR4Z3}`