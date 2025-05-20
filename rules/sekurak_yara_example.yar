import "pe"
rule IsPE : PE
{
    condition:
        pe.is_pe
}
rule SampleRule1 : Educational Example
{
    meta:
        author = "Sekurak"
        date = "2022-08-08"
        description = "Educational example of YARA rule"
    strings:
   $x = { 73 65 6B 75 72 61 6B 2E 70 6C } //sekurak.pl
        $y = "sekurak.pl" wide
    condition:
        IsPE and ($x or $y)
}
