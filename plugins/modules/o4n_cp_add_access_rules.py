# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "octupus",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: o4n_cp_add_access_rules
short_description: Manages access-rules objects on Check Point over Web Services API
description:
  - Manages access rule objects in Check Point devices, including creation and updating if the rule to be created matches another,
  - it will add missing sources or destinations
  - All operations are performed over Web Services API.
version_added: "1.0"
author: "Randy Rozo"
notes:
  - Testeado en linux
requirements:
  - ansible >= 2.10
options:
  layers:
    description:
      - Layer that the rule belongs to identified by the name or UID.
    type: list
    required: True
    elements: dict
    suboptions:
      name:
        description:
        - Object name.
        type: str
        required: True
      rules:
        description:
            - List of rules.
        type: list
        elements: dict
        required: true
        suboptions:
            name:
                description:
                - Object name.
                type: str
                required: True
            action:
                description:
                - a "Accept", "Drop", "Ask", "Inform", "Reject", "User Auth", "Client Auth", "Apply Layer".
                type: str
            destination:
                description:
                - Collection of Network objects identified by the name or UID.
                type: list
                elements: str
            enabled:
                description:
                - Enable/Disable the rule.
                type: bool
            inline_layer:
                description:
                - Inline Layer identified by the name or UID. Relevant only if "Action" was set to "Apply Layer".
                type: str
            install_on:
                description:
                - Which Gateways identified by the name or UID to install the policy on.
                type: list
                elements: str
            service:
                description:
                - Collection of Network objects identified by the name or UID.
                type: list
                elements: str
            source:
                description:
                - Collection of Network objects identified by the name or UID.
                type: list
                elements: str
            time:
                description:
                - List of time objects. For example, "Weekend", "Off-Work", "Every-Day".
                type: list
                elements: str
            track:
                description:
                - Track Settings.
                type: dict
                suboptions:
                    accounting:
                        description:
                        - Turns accounting for track on and off.
                        type: bool
                    type:
                        description:
                        - a "Log", "Extended Log", "Detailed  Log", "None".
                        type: str
            vpn:
                description:
                - Any or All_GwToGw.
                type: str
                choices: ['Any', 'All_GwToGw']
            comments:
                description:
                - Comments string.
                type: str
            state:
                description:
                - State of the access rule (present or absent). Defaults to present.
                type: str
                default: present
                choices:
                - 'present'
                - 'absent'
  provider:
    type: dic
    required: True
    elements: dict
    options:
        host:
          type: str
          required: True
        user:
          type: str
          required: True
        password:
          type: str
          required: True
        port:
          type: integer
          required: True
        validate_certs:
          type: boolean
          required: True
        domain:
          type: str
          required: True
"""

EXAMPLES = """
tasks:
  - name: add access rules
    o4n_cp_add_access_rules:
      layer:
        - name:
          rules:
            - position: 1
              name: "regla inline"
              source:
                  - Test2
              destination:
                  - Test1
              service:
                  - TEST_PORT_UDP
              action: "Apply Layer"
              inline_layer: Test_AWX
              vpn: Any
              track:
                  type: Log
                  accounting: true
              install_on: Cluster-TEST
              comments: "Nueva regla"
      provider:
        host:
        user:
        password:
        port:
        domain:
    register: output
"""
RETURN = """
output:
  description: The checkpoint add access rules output
  type: dict
  returned: allways
  sample:
    "output": {
        "changed": false,
        "content": [
            {
                "layer_name": [
                    {
                        "action": "Accept",
                        "destination": [
                            "Any"
                        ],
                        "enabled": false,
                        "install-on": [
                            "Cluster-TEST"
                        ],
                        "number": "",
                        "section": "REGLA ACCESO",
                        "service": [
                            "Any"
                        ],
                        "source": [
                            "Any",
                        ],
                        "time": [
                            "Any"
                        ],
                        "track": "Log",
                        "vpn": [
                            "Any"
                        ]
                    }
                ]
            }
        ],
        "discard": [],
        "logout": "OK",
        "failed": false,
        "msg": {
            "layer_name": "Se han agregado 1 reglas."
        },
        "publish":{
            "progress-percentage": 100,
            "status": "succeeded",
            "suppressed": false,
            "task-details": [
                {
                    "publishResponse": {
                        "mode": "async",
                        "numberOfPublishedChanges": 1
                    },
                    "revision": "4330f-0ddf-4bb4-92a6-1d73b9f"
                }
            ],
            "task-id": "04567-89ab-cdef-87f4-5730958",
            "task-name": "Publish operation"
        }
      }
"""
import traceback
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ..module_utils.o4n_checkpoint import login, publish, discard, logout, send_request, get_name_from_uid


def set_access_rule(provider, token, payload, rule_number):
    url = "set-access-rule"
    status, response = send_request(provider, token, url, payload)
    if status:
        sources = [src["name"] for src in response["source"]]
        destinations = [dest["name"] for dest in response["destination"]]
        service = [serv["name"] for serv in response["service"]]
        vpn = [vpn["name"] for vpn in response["vpn"]]
        action = response["action"]["name"]
        time = [time["name"] for time in response["time"]]
        track = response["track"]["type"]["name"]
        install_on = [install_on["name"] for install_on in response["install-on"]]
        rule_set = {
            "uid": response["uid"],
            "state": "set",
            "enabled": response["enabled"],
            "number": rule_number,
            "source": sources,
            "destination": destinations,
            "vpn": vpn,
            "service": service,
            "action": action,
            "time": time,
            "track": track,
            "install-on": install_on,
        }
        return True, rule_set

    else:
        return False, response


def add_access_rule(provider, token, desired_rule, layer):
    url = "add-access-rule"
    payload = {}
    payload["layer"] = layer
    for key, value in desired_rule.items():
        if value:
            payload[key.replace("_", "-")] = desired_rule[key]

    status, response = send_request(provider, token, url, payload)

    if status:
        sources = [src["name"] for src in response["source"]]
        destinations = [dest["name"] for dest in response["destination"]]
        service = [serv["name"] for serv in response["service"]]
        vpn = [vpn["name"] for vpn in response["vpn"]]
        action = response["action"]["name"]
        time = [time["name"] for time in response["time"]]
        track = response["track"]["type"]["name"]
        install_on = [install_on["name"] for install_on in response["install-on"]]
        rule_add = {
            "uid": response["uid"],
            "state": "add",
            "enabled": response["enabled"],
            "number": desired_rule["position"],
            "source": sources,
            "destination": destinations,
            "vpn": vpn,
            "service": service,
            "action": action,
            "time": time,
            "track": track,
            "install-on": install_on,
        }
        return True, rule_add

    else:
        return False, response


def verify_objects_in_rule_and_set(
    module, provider, token, response, desired_rules, rule, rule_list, layer
):
    for desired_rule in desired_rules:
        desired_sources = (
            [desired_rule["source"]]
            if isinstance(desired_rule["source"], str)
            else desired_rule["source"]
        )
        desired_destinations = (
            [desired_rule["destination"]]
            if isinstance(desired_rule["destination"], str)
            else desired_rule["destination"]
        )
        desired_service = (
            [desired_rule["service"]]
            if isinstance(desired_rule["service"], str)
            else desired_rule["service"]
        )
        desired_time = (
            [desired_rule["time"]]
            if isinstance(desired_rule["time"], str)
            else desired_rule["time"]
        )

        existing_destinations = [
            get_name_from_uid(response, dest)
            for dest in rule["destination"]
        ]
        existing_sources = [
            get_name_from_uid(response, src) for src in rule["source"]
        ]
        existing_service = [
            get_name_from_uid(response, serv) for serv in rule["service"]
        ]
        existing_time = [
            get_name_from_uid(response, time) for time in rule["time"]
        ]

        # Comprobar si todos los destinos deseados ya están en la regla
        if (
            all(dest in existing_destinations for dest in desired_destinations)
            and all(serv in existing_service for serv in desired_service)
            and all(time in existing_time for time in desired_time)
        ):
            # Comprobar si falta algún origen deseado en la regla
            missing_sources = [
                src for src in desired_sources if src not in existing_sources
            ]
            if missing_sources:
                # Aquí puedes actualizar la regla para añadir los orígenes que faltan
                payload_set_rule = {
                    "uid": rule["uid"],
                    "source": {"add": missing_sources},
                    "layer": layer,
                }
                validate, rule_set = set_access_rule(
                    provider, token, payload_set_rule, rule["rule-number"]
                )
                if validate is False:
                    msg_discard = discard(provider, token)
                    msg_logout = logout(provider, token)
                    module.fail_json(
                        failed=True,
                        msg=rule_set,
                        content=[],
                        publish=[],
                        discard=msg_discard,
                        logout=msg_logout,
                    )
                rule_list.append(rule_set)
                desired_rules.remove(desired_rule)

        # Comprobar si todos los origenes deseados ya están en la regla
        elif (
            all(src in existing_sources for src in desired_sources)
            and all(serv in existing_service for serv in desired_service)
            and all(time in existing_time for time in desired_time)
        ):
            # Comprobar si falta algún origen deseado en la regla
            missing_destinations = [
                dest
                for dest in desired_destinations
                if dest not in existing_destinations
            ]
            if missing_destinations:
                # Aquí puedes actualizar la regla para añadir los orígenes que faltan
                payload_set_rule = {
                    "uid": rule["uid"],
                    "destination": {
                        "add": missing_destinations,
                    },
                    "layer": layer,
                }

                validate, rule_set = set_access_rule(
                    provider, token, payload_set_rule, rule["rule-number"]
                )
                if validate is False:
                    msg_discard = discard(provider, token)
                    msg_logout = logout(provider, token)
                    module.fail_json(
                        failed=True,
                        msg=rule_set,
                        content=[],
                        publish=[],
                        discard=msg_discard,
                        logout=msg_logout,
                    )
                rule_list.append(rule_set)
                desired_rules.remove(desired_rule)

    return rule_list, desired_rules


def add_and_set_access_rule(provider, layers, module):
    token = login(provider)
    url = "show-access-rulebase"
    try:
        msg_ret_dict = {}
        output = []

        for desired_layer in layers:
            rule_list = []
            layer_dict = {}
            page_size = 200
            page_number = 0
            layer = desired_layer["name"]
            desired_rules = desired_layer["rules"]
            layer_dict[f"{layer}"] = {}

            while True:
                payload = {
                    "offset": page_number * page_size,
                    "limit": page_size,
                    "name": layer,
                    "details-level": "standard",
                    "use-object-dictionary": True,
                }

                status, response = send_request(
                    provider, token, url, payload
                )
                if status:
                    for rules in response["rulebase"]:
                        if rules["type"] == "access-section":
                            for rule in rules["rulebase"]:
                                (
                                    rule_list,
                                    desired_rules,
                                ) = verify_objects_in_rule_and_set(
                                    module,
                                    provider,
                                    token,
                                    response,
                                    desired_rules,
                                    rule,
                                    rule_list,
                                    layer,
                                )

                        elif rules["type"] == "access-rule":
                            rule_list, desired_rules = verify_objects_in_rule_and_set(
                                module,
                                provider,
                                token,
                                response,
                                desired_rules,
                                rules,
                                rule_list,
                                layer,
                            )

                    if len(desired_rules) == 0:
                        break

                    # Verificar si hay más páginas
                    if "to" in response and "total" in response:
                        if response["to"] >= response["total"]:
                            break
                    else:
                        break

                    page_number += 1
                else:
                    msg_discard = discard(provider, token)
                    msg_logout = logout(provider, token)
                    module.fail_json(
                        failed=True,
                        msg=response,
                        content=[],
                        publish=[],
                        discard=msg_discard,
                        logout=msg_logout,
                    )
                    break

            if len(desired_rules) > 0:
                for desired_rule in desired_rules:
                    validate, rule_add = add_access_rule(
                        provider, token, desired_rule, layer
                    )
                    if validate is False:
                        msg_discard = discard(provider, token)
                        msg_logout = logout(provider, token)
                        module.fail_json(
                            failed=True,
                            msg=rule_add,
                            content=[],
                            publish=[],
                            discard=msg_discard,
                            logout=msg_logout,
                        )

                    rule_list.append(rule_add)

            layer_dict[f"{layer}"] = rule_list
            output.append(layer_dict)
            msg_ret_dict[f"{layer}"] = f"Se han agregado '{len(rule_list)}' reglas."

        task_detail = publish(provider, token)
        msg_logout = logout(provider, token)
        status = True
        msg_ret = msg_ret_dict

        return status, msg_ret, output, task_detail, [], msg_logout

    except Exception as error:
        status = False
        tb = traceback.format_exc()
        msg_ret = f"Error: <{str(error)}>\n{tb}"
        msg_discard = discard(provider, token)
        msg_logout = logout(provider, token)

        return status, msg_ret, [], [], msg_discard, msg_logout


def main():
    module = AnsibleModule(
        argument_spec=dict(
            layers=dict(
                required=False,
                type="list",
                default=[],
                elements="dict",
                options=dict(
                    name=dict(required=True, type="str"),
                    rules=dict(
                        type="list",
                        elements="dict",
                        default=[],
                        options=dict(
                            position=dict(
                                required=True, type="raw", choice=[str, int, dict]
                            ),
                            name=dict(required=False, type="str"),
                            action=dict(
                                required=False,
                                type="str",
                                choice=[
                                    "Accept",
                                    "Drop",
                                    "Ask",
                                    "Inform",
                                    "Reject",
                                    "User Auth",
                                    "Client Auth",
                                    "Apply Layer",
                                ],
                            ),
                            destination=dict(
                                required=False,
                                type="raw",
                                choice=[str, list],
                                default=["Any"],
                            ),
                            enabled=dict(required=False, type="bool"),
                            inline_layer=dict(required=False, type="str"),
                            install_on=dict(
                                required=False, type="raw", choice=[str, list]
                            ),
                            service=dict(
                                required=False,
                                type="raw",
                                choice=[str, list],
                                default=["Any"],
                            ),
                            source=dict(
                                required=False,
                                type="raw",
                                choice=[str, list],
                                default=["Any"],
                            ),
                            time=dict(
                                required=False,
                                type="raw",
                                choice=[str, list],
                                default=["Any"],
                            ),
                            track=dict(
                                type="dict",
                                options=dict(
                                    type=dict(required=False, type="str"),
                                    accounting=dict(required=False, type="bool", default=False),
                                ),
                            ),
                            vpn=dict(required=False, type="raw", choice=[str, list]),
                            comments=dict(required=False, type="str"),
                        ),
                    ),
                ),
            ),
            provider=dict(
                type="dict",
                default={},
                options=dict(
                    host=dict(
                        type="str", required=True, fallback=(env_fallback, ["CP_HOST"])
                    ),
                    user=dict(
                        type="str",
                        required=True,
                        fallback=(env_fallback, ["CP_USER", "ANSIBLE_NET_USERNAME"]),
                    ),
                    password=dict(
                        type="str",
                        required=True,
                        no_log=True,
                        fallback=(
                            env_fallback,
                            ["CP_PASSWORD", "ANSIBLE_NET_USERNAME"],
                        ),
                    ),
                    port=dict(
                        type="int", default=443, fallback=(env_fallback, ["CP_PORT"])
                    ),
                    validate_certs=dict(
                        type="bool",
                        default=False,
                        fallback=(env_fallback, ["CP_VALIDATE_CERTS"]),
                    ),
                    domain=dict(
                        type="str",
                        required=True,
                        fallback=(env_fallback, ["CP_DOMAIN"]),
                    ),
                ),
            ),
        ),
    )

    layers = module.params["layers"]
    provider = module.params["provider"]

    (
        success,
        msg_ret,
        output,
        task_detail,
        msg_discard,
        msg_logout,
    ) = add_and_set_access_rule(provider, layers, module)

    if success:
        module.exit_json(
            failed=False,
            msg=msg_ret,
            content=output,
            publish=task_detail,
            discard=msg_discard,
            logout=msg_logout,
        )
    else:
        module.fail_json(
            failed=True,
            msg=msg_ret,
            content=output,
            publish=task_detail,
            discard=msg_discard,
            logout=msg_logout,
        )


if __name__ == "__main__":
    main()
