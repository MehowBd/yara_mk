rule ExampleRule
{
    meta:
        description = "Prosta reguła wykrywająca ciąg 'sekret'"

    strings:
        $secret = "sekret"
        $password = "password"

    condition:
        any of them
}
