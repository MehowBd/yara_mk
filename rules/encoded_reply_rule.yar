rule EncodedReplyTo
{
    meta:
        description = "Wykrywa zakodowane nagłówki w polu Reply-To"
        author = "Iza_Hubert"

    strings:
        $replyto_encoded = /Reply-To:\s+=\?UTF-8\?B\?.{20,}\?=/

    condition:
        $replyto_encoded
        
}