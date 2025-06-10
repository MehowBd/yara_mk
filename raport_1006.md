# System przetwarzania reguł obronnych YARA szyfrowanych homomorficznie 
*Michał Badura, Hubert Kabziński, Mikołaj Pniak, Wiktoria Sadok, Adam Woźny, Izabela Wyderka* 

Celem zadania jest praktyczna weryfikacja możliwości realizacji reguł obronnych YARA.

## Wstęp teoretyczny
### Znaczenie wykrywania złośliwego oprogramowania
W dobie dynamicznie rozwijającej się technologii, zagrożenia związane ze złośliwym oprogramowaniem stają się coraz trudniejsze do wykrycia, bardziej zaawansowane i niosą za sobą poważniejsze konsekwencje. Według [danych z 2024](https://dataprot.net/statistics/malware-statistics/), codziennie wykrywane jest ponad 560 000 nowych próbek malware, a liczba istniejących programów złośliwych przekroczyła 1 mld. Co więcej, w każdej minucie aż cztery firmy padają ofiarą ataku ransomware. W takich warunkach ręczna analiza i detekcja zagrożeń staje się niemal niemożliwa, co sprawia, że coraz większą rolę odgrywają narzędzia automatyczne, takie jak YARA.

### YARA
YARA to narzędzie służące do klasyfikacji i identyfikacji złośliwego oprogramowania na podstawie dopasowania plików do wcześniej zdefiniowanych wzorców binarnych, tekstowych i logicznych. Umożliwia automatyczne wykrywanie charakterystycznych cech malware w plikach i innych zasobach systemowych. 

### Reguły YARA
Reguły YARA są plikami tekstowymi zawierającymi kod o precyzyjnej składni, który opisuje wzór pozwalający uznać dane za złośliwe oprogramowanie. Dzięki elastyczności reguły mogą być dostosowywane do różnych potrzeb, sprawdzając się zarówno w pojedynczych analizach, jak i w dużych systemach automatycznej detekcji. Reguła składa się z kilku głównych części:

1. **Nagłówek reguły** - definiuje nazwę, opcjonalnie tagi ułatwiające organizację reguł.
2. **Sekcja meta** - zawiera opisowe informacje o regule, takie jak data, autor, czy opis, pełniąc funkcję dokumentacji. 
3. **Sekcja strings** - definiuje ciągi znaków, wyrażenia regularne lub wzorce bajtowe, które będą wyszukiwane w pliku:
- {...} - wzorce bajtowe
- /.../ - wyrażenia regularne
- "..." - ciągi tekstowe
4. **Sekcja condition** - określa jaki warunek logiczny musi zostać spełniony, by reguła została dopasowana. 

### Zalety 
- Elastyczność i modularność – reguły można dostosować do różnych potrzeb tworząc zarówno proste, jak i bardziej zaawansowane analizy.
- Uniwersalność zastosowania – YARA może być stosowana lokalnie, ale może też zostać zintegrowana z systemami bezpieczeństwa takimi jak SIEM, EDR.
- Wsparcie dla różnych typów danych – potrafi skanować pliki binarne, tekstowe, pamięć operacyjną czy obrazy dysków.
- Społeczność - jako narzędzie open-source umożliwia korzystanie z gotowych reguł.
- Szybka i skuteczna detekcja zagrożeń – wykrywa malware na podstawie wcześniej zdefiniowanych wzorców.
- Prosta i przejrzysta składnia – łatwe tworzenie własnych reguł.
- Możliwość analizy retrospektywnej – pozwala na przeszukiwanie archiwalnych danych i plików pod kątem nowych zagrożeń.

### Wady
- Wysoka zależność od jakości reguł – skuteczność zależy od precyzyjnego i aktualnego definiowania reguł, dlatego też błędne reguły mogą prowadzić do pominięcia zagrożeń.
- Ograniczenia przy wykrywaniu nieznanych zagrożeń – YARA opiera się na regułach dopasowujących się do znanych wzorców, przez co może nie radzić sobie z wykrywaniem nowych. 
- Potencjalne problemy z wydajnością – dla dużych zbiorów lub skomplikowanych reguł analiza może być czasochłonna.
 
## Realizacja
Projekt służy do automatycznej analizy wiadomości e-mail i plików binarnych za pomocą reguł YARA w celu wykrycia złośliwego oprogramowania i podejrzanych treści.

### Opis notebook'a
Notebook ładuje przykładowy zbiór reguł YARA i stosuje je do pliku wykonywalnego, aby sprawdzić, czy zawiera on cechy charakterystyczne dla malware'u. Przetwarzane są wiadomości e-mail - pliki zawierające wiadomości dzielone są na pojedyncze wiadomości i zapisywane jako osobne pliki tekstowe. Operacja ta wykonywana jest zarówno dla maili phishingowych, jak i zwykłych. Wszystkie utworzone pliki są następnie skanowane przy użyciu reguł YARA w celu wykrycia podejrzanych elementów, takich jak charakterystyczne dla phishingu słowa, podejrzane linki czy załączniki. Wyniki analiz zapisywane są w katalogu *results* w postaci raportów zawierających opisy dopasowań.  

### Utworzone reguły 
#### Suspicious_Email_Content 
Wykrywa podejrzaną zawartość wiadomości e-mail, taką jak temat, brak personalizacji czy podejrzane linki. Zawiera pięć wzorców, które mogą wskazywać na podejrzaną wiadomość. 

- $html_legacy - przestarzały typ deklaracji HTML, współcześnie rzadko używany. Może być wykorzystany do próby ukrycia podejrzanych treści, ominięcia istniejących filtrów. 
- $inline_style - stylowanie inline, niewykorzystanie CSS, ustalanie całego wyglądu w jednym atrybucie. 
- $hidden_link - szuka linków pustych lub zawierających niewidoczny tekst (np. ukryty span).
- $no_name - brak personalizacji.
- $no_signature - może sugerować automatyczną, masowo wysyłaną wiadomość.

Reguła jest spełniona, gdy e-mail zawiera co najmniej jeden element związany z nietypowym HTML-em i przynajmniej jeden element sugerujący ukrywanie treści lub brak personalizacji. 

```yara
strings:
    $html_legacy = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01"
    $inline_style = "style="
    $hidden_link = /<a[^>]+>(\s*<\/a>|\s*<span.*<\/span><\/a>)/i
    $no_name = "Hello," nocase
    $no_signature = "Best regards," nocase

condition:
    ($html_legacy or $inline_style) and
    ($hidden_link or $no_name or $no_signature)
```
**Wyniki**
|                      | Przewidziano: Phishing | Przewidziano: Nie phishing |
| -------------------- | ---------------------- | -------------------------- |
| Faktycznie: Phishing | 82 (TP)                | 740 (FN)                   |
| Faktycznie: Nie      | 61 (FP)                | 826 (TN)                   |

Reguła wykrywa tylko około 10% phishingu, co świadczy o dość niskiej czułości. Jednocześnie prawie 7% zwykłych wiadomości jest fałszywie oznaczanych jako phishing. Na podstawie wyników można uznać, że reguła powinna być stosowana raczej jako uzupełnienie do systemu wykrywania phishingu, a nie jako samodzielne narzędzie.

#### Phrases\_Email\_Rule

Reguła służy do wykrywania phishingu na podstawie typowych fraz używanych w kampaniach socjotechnicznych. Takie frazy jak „Renew your subscription”, „Urgent” czy „Verification required” są często spotykane w wiadomościach próbujących wywołać presję lub zmusić odbiorcę do szybkiego działania. Detekcja opiera się na obecności dowolnej z poniższych fraz w treści wiadomości.

```yara
{
    strings:
        $phish1 = "Renew your subscription"
        $phish2 = "Update your payment details"
        $phish3 = "Your shipment is on the way"
        $phish4 = "Password Expiration Notification"
        $phish5 = "New file shared in Teams"
        $phish6 = "Urgent"
        $phish7 = "Verification required"
        $phish8 = "Invoice"
        $phish9 = "Need urgent help"
        $phish10 = "Suspicious Outlook activity"
        $phish11 = "Important! Your password is about to expire"
        $phish12 = "Action required"
        $phish13 = "Click below"

    condition:
        any of ($phish*)
}
```

|                      | Przewidziano: Phishing | Przewidziano: Nie phishing |
| -------------------- | ---------------------- | -------------------------- |
| Faktycznie: Phishing | 91 (TP)                | 731 (FN)                   |
| Faktycznie: Nie      | 0 (FP)                 | 888 (TN)                   |

Wyniki pokazują, że reguła oparta na frazach działa z bardzo wysoką precyzją – nie wygenerowano żadnych fałszywych alarmów. Wykryto 91 wiadomości phishingowych, co wskazuje na umiarkowaną czułość. Reguła dobrze sprawdzi się jako element szerszego systemu klasyfikacji, szczególnie do weryfikacji wiadomości zawierających presję psychologiczną, typową dla phishingu.


#### Domains\_Email\_Rule
Detekcja wiadomości, w których nadawca podszywa się pod znane marki (n.p @ągh.edu.pl). Odbywa się ona poprzez bezpośrednie jednej z dwóch typów fraz: 
- $domN - podejrzana domena, której nazwa wsytępuje w wiadomości, często może wskazywać na linki do fałszywych sklepów, płatności etc.
- $mailerN - podejrzana domena, z której została wysłana wiadomość.
```yara
{
    strings:
        $dom1 = "chainsmokers-feeling.org"
        $dom2 = "xfund02.ml"
        $dom3 = "smxrayon.skin"
        $dom4 = "circularhub.ch"
        $dom5 = "panonika.si"

        $mailer1 = "amazonses.com"
        $mailer2 = "sendgrid.net"
        $mailer3 = "sparkpostmail.com"

    condition:
         any of ($dom*) and any of ($mailer*)
}
```
|                     | Przewidziano: Phishing | Przewidziano: Nie phishing |
|---------------------|------------------------|-----------------------------|
| Faktycznie: Phishing| 1 (TP)                 | 821 (FN)                    |
| Faktycznie: Nie     | 0 (FP)                 | 888 (TN)                    |

Jak można zauważyć, w przypadku zbioru testowego użytego do ewaluacji, został popawnie wykryty tylko jeden przypadek wiadomości będącej phishingiem, pozostałe 821 nie. Oznacza to, że w tym przypadku podana wyżej reguła nie ma zastosowania, co nie oznacza, że w przypadku danych n.p. z innego kraju też tak będzie.


#### Suspicious\_Geo\_and\_TLD

Reguła służy do detekcji wiadomości, które zawierają domeny z końcówkami często powiązanymi z działalnością phishingową, jak np. `.ml`, `.ga`, `.ru`, `.su`, `.cn` czy `.xyz`. Te domeny mogą wskazywać na geograficzne lub rejestrowe źródła, które są bardziej podatne na nadużycia.
W detekcji uwzględniane są jedynie wystąpienia jednej z wymienionych końcówek domenowych w treści wiadomości.

```yara
{
    strings:
        $tld_ml = ".ml"
        $tld_ga = ".ga"
        $tld_ru = ".ru"
        $tld_su = ".su" 
        $tld_skin = ".skin"
        $tld_cn = ".cn"
        $tld_top = ".top"
        $tld_sbs = ".sbs"
        $tld_bond = ".bond"
        $tld_xyz = ".xyz"

    condition:
       any of ($tld*)
}
```

|                      | Przewidziano: Phishing | Przewidziano: Nie phishing |
| -------------------- | ---------------------- | -------------------------- |
| Faktycznie: Phishing | 84 (TP)                | 738 (FN)                   |
| Faktycznie: Nie      | 159 (FP)               | 728 (TN)                   |

W przypadku tej reguły widoczna jest znacznie wyższa czułość w porównaniu do poprzedniej – udało się wykryć 84 przypadki wiadomości phishingowych spośród 822, co oznacza, że system zaczyna identyfikować zagrożenia w oparciu o podejrzane końcówki domen. Niestety, dużym problemem jest liczba fałszywych alarmów – aż 159 wiadomości zostało błędnie sklasyfikowanych jako phishing, mimo że były to zwykłe e-maile. Taka reguła może być przydatna jako element większego systemu detekcji, ale sama w sobie generuje zbyt wiele błędów, by być stosowana niezależnie.

#### EncodedReplyTo

Reguła ta wykrywa wiadomości, w których nagłówek `Reply-To` zawiera podejrzanie zakodowaną wartość w formacie MIME (Base64 z kodowaniem UTF-8). Tego typu techniki są często stosowane w kampaniach phishingowych do ukrycia prawdziwego adresu odpowiedzi i zmylenia systemów filtrowania lub użytkownika końcowego.

```yara
{
    strings:
        $replyto_encoded = /Reply-To:\s+=\?UTF-8\?B\?.{20,}\?=/

    condition:
        $replyto_encoded
}
```

|                      | Przewidziano: Phishing | Przewidziano: Nie phishing |
| -------------------- | ---------------------- | -------------------------- |
| Faktycznie: Phishing | 19 (TP)                | 803 (FN)                   |
| Faktycznie: Nie      | 0 (FP)                 | 888 (TN)                   |

Jak można zauważyć, reguła ta poprawnie zidentyfikowała 19 wiadomości phishingowych, przy zerowej liczbie fałszywych alarmów. Choć skuteczność w zakresie precyzji jest bardzo wysoka, czułość pozostaje niska – większość phishingowych wiadomości (803 z 822) nie została przez tę regułę wykryta. Może to sugerować, że technika zakodowanego `Reply-To` jest charakterystyczna tylko dla wybranych kampanii, ale nie stanowi powszechnego wzorca. Reguła ta może być zatem bardzo przydatna jako uzupełnienie innych, bardziej ogólnych mechanizmów detekcji.

#### Phishing\_Suspicious\_Links

Reguła służy do detekcji wiadomości zawierających podejrzane linki, często wykorzystywane w kampaniach phishingowych. Wyszukiwane są zarówno skracacze linków typu `bit.ly` czy `tinyurl.com`, jak i adresy wskazujące na próbę podszycia się pod loginy (`login.`) lub rzekome zabezpieczenia (`secure.`). Dodatkowo wykrywane są linki zawierające znak `@` w URL, co często służy maskowaniu prawdziwego adresu docelowego.

```yara
{
    strings:
        $url1 = "bit.ly/"
        $url2 = "tinyurl.com/"
        $url3 = "http://login." nocase
        $url4 = "http://secure." nocase
        $url5 = /https?:\/\/[^ ]*@(.*)/

    condition:
        any of ($url*)
}
```

|                      | Przewidziano: Phishing | Przewidziano: Nie phishing |
| -------------------- | ---------------------- | -------------------------- |
| Faktycznie: Phishing | 421 (TP)               | 401 (FN)                   |
| Faktycznie: Nie      | 99 (FP)                | 788 (TN)                   |

Wyniki tej reguły są obiecujące — udało się wykryć ponad połowę wiadomości phishingowych (421 z 822), co czyni ją jedną z bardziej czułych spośród dotychczasowych. Nadal jednak pozostaje 401 wiadomości phishingowych, które nie zostały rozpoznane. Warto także zauważyć, że 99 zwykłych wiadomości zostało błędnie sklasyfikowanych jako phishing, co może wynikać z ich zawartości technicznej (np. legalne maile z linkami do logowania).
Reguła ta ma potencjał do użytku praktycznego, zwłaszcza jako element większego systemu oceny ryzyka wiadomości, ale wymaga dopracowania w zakresie redukcji liczby fałszywych pozytywów.

#### Wszystkie reguły połączone


Analiza łączna wyników ze wszystkich reguł wskazuje na zdecydowaną poprawę wykrywalności phishingu w porównaniu do działania pojedynczych reguł.

|                      | Przewidziano: Phishing | Przewidziano: Nie phishing |
| -------------------- | ---------------------- | -------------------------- |
| Faktycznie: Phishing | 565 (TP)               | 257 (FN)                   |
| Faktycznie: Nie      | 195 (FP)               | 693 (TN)                   |

Zastosowanie wszystkich reguł jednocześnie pozwoliło wykryć **ok. 69%** wiadomości phishingowych, co stanowi znaczący wzrost względem poszczególnych detektorów. Warto jednak zwrócić uwagę na **195 fałszywych alarmów**, które mogą prowadzić do błędnej klasyfikacji legalnych wiadomości.


### Detekcja phishingu z wykorzystaniem YARA, LLM i szyfrowania homomorficznego

Celem tej części projektu było stworzenie systemu opartego na analizie wektorowej tekstu oraz regexach z YARA rules, wspieranego przez LLM. Projekt wykorzystuje homomorficzną enkrypcję, aby umożliwić obliczenia na zaszyfrowanych danych.

### Opis podejścia z szyfrowaniem homomorficznym
Projekt realizuje kompletną analizę phishingu, łącząc YARA, sztuczną inteligencję, przetwarzanie tekstu oraz szyfrowanie homomorficzne. Początkowo wczytywane są utworzone wcześniej pliki z regułami YARA. Dla każdego z nich generowane są wyrażenia regularne, które odzwierciedlają charakterystyczne wzorce phishingu dla uwzględnionych reguł. 

Kolejno generowane są frazy phishingowe, które pasują do regexów, co pozwala na uzyskanie realistycznych przykładów możliwych ataków. Wszystkie frazy przekształacane są w wektory przy użyciu metody n-gramów oraz funkcji hashowania, co skutkuje uzyskaniem numerycznej reprezentacji tekstu, przygotowanej do analizy. 

Wszystkie wiadomości e-mail są wektoryzowane i szyfrowane homomorficznie przed rozpoczęciem głównej pętli analizy. Dzięki temu czas analizy ulega znacznemu skróceniu, ponieważ wszystkie operacje porównawcze są wykonywane na już zaszyfrowanych danych. 
Szyfrowaniu podlegają również wektory fraz phishingowych wygenerowanych na podstawie regexów.

Kluczową częścią jest homomorficzne porównywanie wektorów. Dzięki zastosowaniu szyfrowania dane są chronione, a treść maili pozostaje nieznana w toku analizy. Wykorzystując próbkę zwwykłych maili, system kalibruje próg dopasowania, by ograniczyć liczbę nieprawidłowych wskazań. Definiowany jest on jako percentyl rozkładu podobieństw, powiększony o *vocab_boost*. Podczas skanowania każdy e-mail porównywany jest z frazami phishingowymi.

Analiza przeprowadzana jest na superkomputerze Ares, ze względu na zapotrzebowanie na zasoby obliczeniowe, związane przede wszystkim z obsługą szyfrowania homomorficznego i dużą liczbą operacji porównawczych.

W efekcie analizy, program generuje szczegółowe podsumowanie statystyk skuteczności detekcji, pokazując liczbę prawidłowo wykrytych wiadomości i fałszywych alarmów. 

### Kluczowe komponenty systemu
##### 1. Generowanie regexów z YARA rules
Funkcja *generate_regexs_from_rule_text* przetwarza plik z regułami YARA i za pomocą LLM generuje do 3 regexów dopasowanych do charakterystyki reguł. Jako wynik zwraca listę słowników z regexami i przypisanymi wagami. 

##### 2. Generowanie fraz phishingowych z regexów 
Funkcja *generate_phrases_from_regex* odpowiada za generowanie fraz pasujących do konkretnego regexa i zwraca listę, wykorzystywaną w dalszej analizie.

##### 3. Ekstrakcja n-gramów
Z każdej ze zwróconych fraz generowane są n-gramy (ciągi 3-5 słów), które służą do analizy i porównań wektorowych.

##### 4. Hashowanie i wektoryzacja tekstu 
Funkcje wykorzystywane do hashowania i wektoryzacji to *hash_ngram()* i *vectorize()*. Ich celem jest zamiana tekstu na liczbowe wektory cech. 

##### 5. Wektoryzacja i szyfrowanie maili
Celem funkcji *vectorize_all_emails* jest przetworzenie maili i zapis zhashowanych wektorów do pliku .npz. 

##### 6. Szyfrowanie homomorficzne
Szyfrowane są zarówno frazy phishingowe, jak i wiadomości e-mail, dzięki czemu *wszystkie* dane są zabezpieczone w czasie analizy.

##### 7. Kalibracja progu wykrywania phishingu
Funkcja *calibrate_threshold* automatycznie dobiera próg wykrywania phishingu, bazując na rozkładzie podobieństw w regularnych mailach.

##### 8. Skany i analiza
*scan_vectorized_emails* porównuje każdy e-mail z bazą wektorów fraz phishingowych oraz sprawdza dopasowanie regexów.  

### Testy oraz wyniki

Na systemie szyfrowanym hommomorficznie zostały przeprowadzone testy odpowiadające tym, które wykonaliśmy na tradycyjnym systemie _YARA_

#### Domains\_Email\_Rule
|                      | Przewidziano: Phishing | Przewidziano: Nie phishing |
| -------------------- | ---------------------- | -------------------------- |
| Faktycznie: Phishing | 549 (TP)               | 273 (FN)                   |
| Faktycznie: Nie      | 222 (FP)               | 665 (TN)                   |

#### Suspicious_Email_Content 

|                      | Przewidziano: Phishing | Przewidziano: Nie phishing |
| -------------------- | ---------------------- | -------------------------- |
| Faktycznie: Phishing | 631 (TP)               | 191 (FN)                   |
| Faktycznie: Nie      | 221 (FP)               | 666 (TN)                   |

#### Phrases\_Email\_Rule
|                      | Przewidziano: Phishing | Przewidziano: Nie phishing |
| -------------------- | ---------------------- | -------------------------- |
| Faktycznie: Phishing | 528 (TP)               | 294 (FN)                   |
| Faktycznie: Nie      | 221 (FP)               | 666 (TN)                   |

#### Phishing\_Suspicious\_Links
|                      | Przewidziano: Phishing | Przewidziano: Nie phishing |
| -------------------- | ---------------------- | -------------------------- |
| Faktycznie: Phishing | 611 (TP)               | 211 (FN)                   |
| Faktycznie: Nie      | 221 (FP)               | 666 (TN)                   |

#### Sekurak
|                      | Przewidziano: Phishing | Przewidziano: Nie phishing |
| -------------------- | ---------------------- | -------------------------- |
| Faktycznie: Phishing | 623 (TP)               | 199 (FN)                   |
| Faktycznie: Nie      | 220 (FP)               | 667 (TN)                   |

Wyniki uzyskane za pomocą naszego systemu z wykorzystaniem szyfrowania homomorficznego prezentują się porównywalnie, a w wielu przypadkach nawet lepiej niż wcześniejsze podejścia bezpośrednie. Dla każdej reguły udało się osiągnąć bardzo zbliżone wartości prawdziwych pozytywów przy zachowaniu tego samego poziomu fałszywych alarmów, co świadczy o skuteczności zastosowanego rozwiązania przy jednoczesnym zachowaniu prywatności analizowanych danych.