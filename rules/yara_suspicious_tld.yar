rule Suspicious_Geo_and_TLD
{
    meta:
        author = "Iza_Hubert"
        description = "Podejrzane pochodzenie i końcówka domeny – potencjalny phishing"
        date = "2025-05-25"

    strings:
        $tld_ml = ".ml"
        $tld_ga = ".ga"
        $tld_ru = ".ru"
        $tld_su = ".su"
        $tld_skin = ".skin"
        $tld_cn = ".cn"

    condition:
       any of ($tld*)
}