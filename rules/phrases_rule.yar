rule Phrases_Email_Rule
{
    meta:
        author = "Iza_Hubert"
        description = "Detekcja wiadomości phishingowych na podstawie fraz"
        date = "2025-05-25"
        reference = "https://sekurak.pl/reguly-obronne-yara-do-klasyfikacji-i-identyfikacji-zlosliwego-oprogramowania/"

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