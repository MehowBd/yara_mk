rule Phishing_Suspicious_Links
{
    meta:
        description = "Wykrywa wiadomości zawierające podejrzane linki"
        author = "Iza_Hubert"
        date = "2025-05-25"

    strings:
        $url1 = "bit.ly/"
        $url2 = "tinyurl.com/"
        $url3 = "http://login." nocase
        $url4 = "http://secure." nocase
        $url5 = /https?:\/\/[^ ]*@(.*)/

    condition:
        any of ($url*)
}
