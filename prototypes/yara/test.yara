rule TRACE_HTTP_MDN
{
    strings:
        $my_text_string = "<link rel=\"canonical\" href=\"https://developer.mozilla.org/fr/docs/Web/HTTP/Methods/TRACE\">"

    condition:
        $my_text_string
}