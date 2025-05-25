rule Phrases_Email_Rule
{
    meta:
        author = "TwójZespół"
        description = "Detekcja wiadomości phishingowych podszywających się pod znane marki"
        date = "2025-05-25"
        reference = "https://sekurak.pl/reguly-obronne-yara-do-klasyfikacji-i-identyfikacji-zlosliwego-oprogramowania/"

    strings:
        $phish1 = "Renew your subscription"
        $phish2 = "Update your payment details"
        $phish3 = "Your shipment is on the way"
        $phish4 = "Password Expiration Notification"
        $phish5 = "New file shared in Teams"

        $mailer1 = "amazonses.com"
        $mailer2 = "sendgrid.net"
        $mailer3 = "sparkpostmail.com"

    condition:
        any of ($phish*) and any of ($mailer*)
}
