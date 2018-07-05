rule somestring
{
    meta:
        author = "Ibonok"

    strings:
        $a1 = "private" nocase
        $a2 = "public" nocase
        $a3 = "username" nocase
        $a4 = "password" nocase
        $hash_32 = /\b[a-fA-F\d]{32,33}\b/
        $hash_64 = /\b[a-fA-F\d]{64,65}\b/
	$n1 = "kernel" nocase
	$n2 = "stack trace" nocase

	$url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/
	$url_regex1 = /http?:\/\/([\w\.-]+)([\/\w \.-]*)/

    condition:
        (1 of ($a*) or any of ($hash_*) or $url_regex or $url_regex1) and (not any of ($n*))
}
