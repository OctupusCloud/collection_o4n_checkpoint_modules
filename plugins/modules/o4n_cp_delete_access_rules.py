#!/usr/bin/env python3
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
module: o4n_cp_delete_access_rules
short_description: Delete access rules of the selected layer.
description:
  - Delete access rules of the selected layer.
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
            name:
                description:
                    - Object name.
                type: str
                required: True
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
  - name: Delete access rules
    o4n_cp_delete_access_rules:
      layers:
        - name: "Web_Policy_Test"
          rules:
            - 'uid': '8e621a59-52fc-491c-a470-8cd20a0dccaf'
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
            "layer_name": "Se han eliminado 1 reglas."
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


def delete_access_rule(provider, layers, module):
    token = login(provider)
    url_show = "show-access-rule"
    url_set = "delete-access-rule"
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

                rule_number = rule["rule_number"]

                status_show, response_show = send_request(
                    provider, token, url_show, payload
                )
                status_set, response_set = send_request(
                    provider, token, url_set, payload
                )

                if status_show:
                    sources = [src["name"] for src in response_show["source"]]
                    destinations = [
                        dest["name"] for dest in response_show["destination"]
                    ]
                    service = [serv["name"] for serv in response_show["service"]]
                    vpn = [vpn["name"] for vpn in response_show["vpn"]]
                    action = response_show["action"]["name"]
                    time = [time["name"] for time in response_show["time"]]
                    track = response_show["track"]["type"]["name"]
                    install_on = [
                        install_on["name"] for install_on in response_show["install-on"]
                    ]
                    rule_set = {
                        "uid": response_show["uid"],
                        "enabled": response_show["enabled"],
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
                    if status_set:
                        if response_set["message"] == "OK":
                            rule_list.append(rule_set)
                    else:
                        msg_discard = discard(provider, token)
                        msg_logout = logout(provider, token)
                        module.fail_json(
                            failed=True,
                            msg=response_set,
                            content=[],
                            publish=[],
                            discard=msg_discard,
                            logout=msg_logout,
                        )
                else:
                    msg_discard = discard(provider, token)
                    msg_logout = logout(provider, token)
                    module.fail_json(
                        failed=True,
                        msg=response_show,
                        content=[],
                        publish=[],
                        discard=msg_discard,
                        logout=msg_logout,
                    )

            layer_dict[f"{layer}"] = rule_list
            output.append(layer_dict)
            msg_ret_dict[f"{layer}"] = f"Se han eliminado '{len(rule_list)}' reglas."

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
                required=True,
                type="list",
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
                            name=dict(required=False, type="str"),
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

    success, msg_ret, output, task_detail, msg_discard, msg_logout = delete_access_rule(
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
