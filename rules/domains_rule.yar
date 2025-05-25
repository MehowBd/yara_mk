rule Domains_Email_Rule
{
    meta:
        author = "TwójZespół"
        description = "Detekcja wiadomości phishingowych podszywających się pod znane marki"
        date = "2025-05-25"
        reference = "https://sekurak.pl/reguly-obronne-yara-do-klasyfikacji-i-identyfikacji-zlosliwego-oprogramowania/"

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