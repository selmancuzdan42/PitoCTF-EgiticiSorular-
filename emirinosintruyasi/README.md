# KıMıLdama Eller Yukarı - Writeup

## Problem Tanımı

Elimizde `KıMıLdama Eller Yukarı.xml` isminde bir dosya bulunmaktadır. Dosya isminden ve içeriğinden hareketle bu bir Geo/OSINT veya Misc kategorisinde bir CTF sorusu olabilir. Amaç dosyayı inceleyip anlamlı bir veriye (muhtemelen flag) ulaşmaktır.

## Analiz

Dosya içeriğini bir metin editörü ile açtığımızda şunları görüyoruz:

- XML formatında bir yapı.
- `<Placemark>`, `<coordinates>`, `<Style>`, `<LookAt>` gibi tagler.
- Bu tagler **KML (Keyhole Markup Language)** formatına aittir ve genellikle Google Earth/Maps gibi uygulamalarda coğrafi verileri göstermek için kullanılır.
- Ancak dosyanın başında standart `<kml>` kök elementi ve gerekli XML namespace tanımlamaları eksiktir. Bu haliyle Google Earth dosyayı açamayabilir veya hatalı görüntüleyebilir.

## Çözüm Adımları

### 1. Dosya Formatını Düzeltme

Dosyanın geçerli bir KML dosyası olması için eksik olan header bilgilerini eklememiz gerekir.

Orijinal dosya başlangıcı:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Document>
    <name>bw</name>
    ...
```

Düzeltilmiş dosya başlangıcı:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2" xmlns:gx="http://www.google.com/kml/ext/2.2" xmlns:kml="http://www.opengis.net/kml/2.2" xmlns:atom="http://www.w3.org/2005/Atom">
<Document>
    <name>bw</name>
    ...
```

Ve dosyanın en sonuna `</kml>` kapanış tagi eklenir.

### 2. Dosya Uzantısını Değiştirme

XML yapısı düzeltildikten sonra dosya `KıMıLdama Eller Yukarı.kml` olarak kaydedilir.

### 3. Görselleştirme (Flag'i Elde Etme)

Hazırladığımız `.kml` dosyasını **Google Earth Pro** uygulamasında açıyoruz.

- Dosya açıldığında uygulama bizi belirli bir coğrafi konuma götürür (XML içindeki `<LookAt>` tagleri sayesinde).
- Placemark'ların koordinatları harita üzerinde çizgiler ve şekiller oluşturur.
- Bu çizgiler birleştiğinde ortaya çıkan yazı/şekil sorunun cevabını (Flag) oluşturur.

## Sonuç

BW1337TR2020

![alt text](<WhatsApp Görsel 2025-12-11 saat 16.10.36_e0e89eff.jpg>)
