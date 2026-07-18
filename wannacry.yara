rule WannaCry_Training_Demo
{
    meta:
        description = "Training rule for WannaCry-related indicators"
        author = "Dontrell"
        date = "2026-07-04"
        purpose = "Safe YARA lab using a harmless test file"

    strings:
        $pattern1 = "WannaCry" nocase
        $pattern2 = "WanaCrypt0r" nocase
        $pattern3 = "tasksche.exe" nocase
        $pattern4 = "WNcry@2ol7" nocase

    condition:
        any of them
}
