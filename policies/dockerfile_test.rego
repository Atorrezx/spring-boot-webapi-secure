package main

import rego.v1

final_user_fixture(user) := [[
    {"Cmd": "from", "Stage": 0, "Value": ["runtime"]},
    {"Cmd": "user", "Stage": 0, "Value": [user]},
    {"Cmd": "healthcheck", "Stage": 0, "Value": ["CMD", "true"]},
]]

compliant := [[
    {"Cmd": "from", "Stage": 0, "Value": ["builder"]},
    {"Cmd": "user", "Stage": 0, "Value": ["root"]},
    {"Cmd": "healthcheck", "Stage": 0, "Value": ["NONE"]},
    {"Cmd": "from", "Stage": 1, "Value": ["runtime"]},
    {"Cmd": "user", "Stage": 1, "Value": ["spring:spring"]},
    {"Cmd": "healthcheck", "Stage": 1, "Value": ["CMD", "wget -q http://127.0.0.1/health"]},
]]

test_compliant_final_stage_has_no_denials if {
    results := deny with input as compliant
    count(results) == 0
}

test_final_user_last_instruction_overrides_root if {
    dockerfile := [[
        {"Cmd": "from", "Stage": 0, "Value": ["runtime"]},
        {"Cmd": "user", "Stage": 0, "Value": ["root"]},
        {"Cmd": "user", "Stage": 0, "Value": ["app"]},
        {"Cmd": "healthcheck", "Stage": 0, "Value": ["CMD", "true"]},
    ]]
    results := deny with input as dockerfile
    count(results) == 0
}

test_final_root_override_is_denied if {
    dockerfile := [[
        {"Cmd": "from", "Stage": 0, "Value": ["runtime"]},
        {"Cmd": "user", "Stage": 0, "Value": ["app"]},
        {"Cmd": "user", "Stage": 0, "Value": ["root"]},
        {"Cmd": "healthcheck", "Stage": 0, "Value": ["CMD", "true"]},
    ]]
    results := deny with input as dockerfile
    "final Dockerfile stage USER must not use root" in results
}

test_root_username_with_root_group_is_denied if {
    results := deny with input as final_user_fixture("root:root")
    "final Dockerfile stage USER must not use root" in results
}

test_root_username_with_non_root_group_is_denied if {
    results := deny with input as final_user_fixture("root:1000")
    "final Dockerfile stage USER must not use root" in results
}

test_unresolved_short_variable_user_is_denied if {
    results := deny with input as final_user_fixture("$RUNTIME_USER")
    "final Dockerfile stage USER must be a literal value; ARG resolution is not provided" in results
}

test_unresolved_braced_variable_user_is_denied if {
    results := deny with input as final_user_fixture("${RUNTIME_USER}")
    "final Dockerfile stage USER must be a literal value; ARG resolution is not provided" in results
}

test_final_uid_zero_variants_are_denied if {
    results := deny with input as final_user_fixture("000:1000")
    "final Dockerfile stage USER must not use UID 0" in results
}

test_missing_final_user_is_denied if {
    dockerfile := [[
        {"Cmd": "from", "Stage": 0, "Value": ["runtime"]},
        {"Cmd": "healthcheck", "Stage": 0, "Value": ["CMD", "true"]},
    ]]
    results := deny with input as dockerfile
    "final Dockerfile stage must declare a literal non-root USER" in results
}

test_missing_final_healthcheck_is_denied if {
    dockerfile := [[
        {"Cmd": "from", "Stage": 0, "Value": ["runtime"]},
        {"Cmd": "user", "Stage": 0, "Value": ["app"]},
    ]]
    results := deny with input as dockerfile
    "final Dockerfile stage must declare a HEALTHCHECK" in results
}

test_final_healthcheck_none_override_is_denied if {
    dockerfile := [[
        {"Cmd": "from", "Stage": 0, "Value": ["runtime"]},
        {"Cmd": "user", "Stage": 0, "Value": ["app"]},
        {"Cmd": "healthcheck", "Stage": 0, "Value": ["CMD", "true"]},
        {"Cmd": "healthcheck", "Stage": 0, "Value": ["NONE"]},
    ]]
    results := deny with input as dockerfile
    "final Dockerfile stage HEALTHCHECK must not be NONE" in results
}

test_builder_only_controls_are_denied if {
    dockerfile := [[
        {"Cmd": "from", "Stage": 0, "Value": ["builder"]},
        {"Cmd": "user", "Stage": 0, "Value": ["app"]},
        {"Cmd": "healthcheck", "Stage": 0, "Value": ["CMD", "true"]},
        {"Cmd": "from", "Stage": 1, "Value": ["runtime"]},
    ]]
    results := deny with input as dockerfile
    "final Dockerfile stage must declare a literal non-root USER" in results
    "final Dockerfile stage must declare a HEALTHCHECK" in results
}
