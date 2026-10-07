package main

import rego.v1

# Conftest passes the parsed Dockerfile's ordered instruction array as input.
# The wrapped form keeps unit-test fixtures readable without changing production input.
instructions := input[0] if is_array(input[0])
instructions := input if not is_array(input[0])

final_stage := max([instruction.Stage | instruction := instructions[_]])

final_user_values := [user |
    instruction := instructions[_]
    instruction.Stage == final_stage
    lower(instruction.Cmd) == "user"
    user := lower(instruction.Value[0])
]

effective_final_user := final_user_values[count(final_user_values) - 1]
effective_final_username := split(effective_final_user, ":")[0]

final_healthchecks := [healthcheck |
    instruction := instructions[_]
    instruction.Stage == final_stage
    lower(instruction.Cmd) == "healthcheck"
    healthcheck := instruction.Value
]

effective_final_healthcheck := final_healthchecks[count(final_healthchecks) - 1]

deny contains msg if {
    count(final_user_values) == 0
    msg := "final Dockerfile stage must declare a literal non-root USER"
}

deny contains msg if {
    contains(effective_final_user, "$")
    msg := "final Dockerfile stage USER must be a literal value; ARG resolution is not provided"
}

deny contains msg if {
    effective_final_username == ""
    msg := "final Dockerfile stage USER must name a non-root user"
}

deny contains msg if {
    effective_final_username == "root"
    msg := "final Dockerfile stage USER must not use root"
}

deny contains msg if {
    regex.match("^0+$", effective_final_username)
    msg := "final Dockerfile stage USER must not use UID 0"
}

deny contains msg if {
    count(final_healthchecks) == 0
    msg := "final Dockerfile stage must declare a HEALTHCHECK"
}

deny contains msg if {
    lower(effective_final_healthcheck[0]) == "none"
    msg := "final Dockerfile stage HEALTHCHECK must not be NONE"
}
