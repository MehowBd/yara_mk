rule Suspicious_Email_Content
{
    meta:
        description = "Wykrywa podejrzaną zawartość wiadomości e-mail (temat, brak personalizacji, podejrzane linki)"
        author = "Iza_Hubert"
        score = 6

    strings:
        $html_legacy = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01"
        $inline_style = "style="
        $hidden_link = /<a[^>]+>(\s*<\/a>|\s*<span.*<\/span><\/a>)/i
        $no_name = "Hello," nocase
        $no_signature = "Best regards," nocase

    condition:
        ($html_legacy or $inline_style) and
        ($hidden_link or $no_name or $no_signature)
}
