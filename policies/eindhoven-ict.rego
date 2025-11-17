package httpauthz

default allow := false

allow {
    input.attributes["role"] == "ICT"
    input.attributes["gemeente"] == "Eindhoven"
    input.method == "GET"
    startswith(input.path, "/data/")
}
