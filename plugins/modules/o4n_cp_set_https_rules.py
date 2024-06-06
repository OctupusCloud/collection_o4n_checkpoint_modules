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
module: o4n_cp_set_https_rules
short_description: Set https rules of the selected layer.
description:
  - Set https rules of the selected layer.
  - All operations are performed over Web Services API.
version_added: "1.0"
author: "Randy Rozo"
notes:
  - Testeado en linux
requirements:
  - ansible >= 2.10
options:
  layers:
    type: list
    required: True
    elements: dict
    options:
      name:
        description:
          - Layer identified by the name or UID.
        type: str
        required: True
      rules:
        description:
          - Layer identified by the name or UID.
        type: list
        required: False
        elements: dict
        options:
            rule_number:
                description:
                    - Rule number.
                type: integer
                required: True
            uid:
                description:
                    - Object unique identifier.
                type: str
                required: True
            new_position:
                description:
                    - New position in the rulebase.
                type: integer
                required: False
            name:
                description:
                    - Object name.
                type: str
                required: True
            action:
                description:
                    - a "Bypass" or "Inspect".
                type: str
                required: False
            destination:
                description:
                    - Collection of Network objects identified by the name or UID.
                type: str, list, dict
                required: False
                options:
                    add:
                      type: str, list
                      description:
                        - Adds to collection of values
                    remove:
                      type: str, list
                      description:
                        - Adds to collection of values
            enabled:
                description:
                    - Enable/Disable the rule.
                type: boolean
                required: False
            install_on:
                description:
                    - Which Gateways identified by the name or UID to install the policy on.
                type: str, list, dict
                required: False
                options:
                    add:
                      type: str, list
                      description:
                        - Adds to collection of values
                    remove:
                      type: str, list
                      description:
                        - Adds to collection of values
            service:
                description:
                    - Collection of Network objects identified by the name or UID.
                type: str, list, dict
                required: False
                options:
                    add:
                      type: str, list
                      description:
                        - Adds to collection of values
                    remove:
                      type: str, list
                      description:
                        - Adds to collection of values
            source:
                description:
                    - Collection of Network objects identified by the name or UID.
                type: str, list, dict
                required: False
                options:
                    add:
                      type: str, list
                      description:
                        - Adds to collection of values
                    remove:
                      type: str, list
                      description:
                        - Adds to collection of values
            blade:
                description:
                    - Blades for HTTPS Inspection. Identified by Name or UID to enable the inspection for.
                    - a "Anti Bot","Anti Virus","Application Control","Data Awareness","DLP","IPS","Threat Emulation","Url Filtering".
                type: str, list, dict
                required: False
                options:
                    add:
                      type: str, list
                      description:
                        - Adds to collection of values
                    remove:
                      type: str, list
                      description:
                        - Adds to collection of values
            track:
                description:
                    - Layer identified by the name or UID.
                type: dict
                required: False
                choices: ["None","Log","Alert","Mail","SNMP trap","Mail","User Alert 1", "User Alert 2", "User Alert 3"]
            site_category:
                type: str, list, dict
                description:
                  - Collection of Site Categories objects identified by the name or UID.
                options:
                    add:
                      type: str, list
                      description:
                        - Adds to collection of values
                    remove:
                      type: str, list
                      description:
                        - Adds to collection of values
            certificate:
                type: str
                description:
                  - Internal Server Certificate identified by Name or UID, otherwise, "Outbound Certificate" is a default value.
            comments:
                type: str
                description:
                  - Comments string.
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
  - name: Set https rules
    o4n_cp_set_https_rules:
      layers:
        - name: "Web_Policy_Test"
          rules:
            - uid: '8e621a59-52fc-491c-a470-8cd20a0dccaf'
              source:
                add: 'Test3'
    register: output
"""
RETURN = """
output:
  description: The checkpoint Set acces rules output
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
                        "blade": [
                            "Any"
                        ],
                        "track": "Log",
                        "blade": [
                            "All"
                        ]
                    }
                ]
            }
        ],
        "discard": [],
        "logout": "OK",
        "failed": false,
        "msg": {
            "layer_name": "Se han modificado 1 reglas."
        },
        "publish": {
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
from ..module_utils.o4n_checkpoint import login, publish, discard, logout, send_request


def set_https_rule(provider, layers, module):
    token = login(provider)
    url = "set-https-rule"
    try:
        msg_ret_dict = {}
        output = []

        for desired_layer in layers:
            layer = desired_layer["name"]
            layer_dict = {}
            layer_dict[f"{layer}"] = {}
            rule_list = []

            for rule in desired_layer["rules"]:
                payload = {}
                payload["layer"] = layer

                for key, value in rule.items():
                    if value:
                        payload[key.replace("_", "-")] = rule[key]

                status, response = send_request(provider, token, url, payload)

                if status:
                    sources = [src["name"] for src in response["source"]]
                    destinations = [dest["name"] for dest in response["destination"]]
                    service = [serv["name"] for serv in response["service"]]
                    blade = [blade["name"] for blade in response["blade"]]
                    action = response["action"]["name"]
                    site_category = [site_category["name"] for site_category in response["site-category"]]
                    track = response["track"]["name"]
                    certificate = response["certificate"]["name"]
                    install_on = [
                        install_on["name"] for install_on in response["install-on"]
                    ]
                    rule_set = {
                        "uid": response["uid"],
                        "enabled": response["enabled"],
                        "number": rule["rule_number"] or rule["new_position"],
                        "source": sources,
                        "destination": destinations,
                        "blade": blade,
                        "service": service,
                        "action": action,
                        "site-category": site_category,
                        "track": track,
                        "certificate": certificate,
                        "install-on": install_on,
                    }
                    rule_list.append(rule_set)
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

            layer_dict[f"{layer}"] = rule_list
            output.append(layer_dict)
            msg_ret_dict[f"{layer}"] = f"Se han modificado '{len(rule_list)}' reglas."

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
                            rule_number=dict(required=False, type="int"),
                            uid=dict(required=False, type="str"),
                            new_position=dict(required=False, type="int"),
                            name=dict(required=False, type="str"),
                            action=dict(
                                required=False,
                                type="str",
                                choice=[
                                    "Bypass",
                                    "Inspect"
                                ],
                            ),
                            destination=dict(
                                required=False, type="raw", choice=[str, list, dict]
                            ),
                            enabled=dict(required=False, type="bool"),
                            install_on=dict(
                                required=False, type="raw", choice=[str, list, dict]
                            ),
                            service=dict(
                                required=False, type="raw", choice=[str, list, dict]
                            ),
                            source=dict(
                                required=False, type="raw", choice=[str, list, dict]
                            ),
                            site_category=dict(
                                required=False, type="raw", choice=[str, list, dict]
                            ),
                            track=dict(
                                required=False,
                                type="str",
                                choice=[
                                    "None",
                                    "Log",
                                    "Alert",
                                    "Mail",
                                    "SNMP trap",
                                    "User Alert 1",
                                    "User Alert 2",
                                    "User Alert 3",
                                ],
                            ),
                            blade=dict(
                                required=False, type="raw", choice=[str, list, dict]
                            ),
                            comments=dict(required=False, type="str"),
                            certificate=dict(required=False, type="str"),
                        ),
                        required_one_of=[
                            ("rule_number", "name", "uid"),
                        ],
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
        )
    )
    layers = module.params["layers"]
    provider = module.params["provider"]

    success, msg_ret, output, task_detail, msg_discard, msg_logout = set_https_rule(
        provider, layers, module
    )
    if success:
        module.exit_json(
            failed=False,
            msg=msg_ret,
            content=output,
            publish=task_detail,
            discard=msg_discard,
            logout=msg_logout,
            changed=success
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
