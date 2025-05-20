rule ExampleRule
{
    meta:
        description = "Prosta reguła wykrywająca ciąg 'sekret'"
        author = "ChatGPT"

    strings:
        $secret = "sekret"
        $password = "password"

    condition:
        any of them
}
