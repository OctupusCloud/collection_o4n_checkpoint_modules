#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'octupus',
                    'metadata_version': '1.1'}

DOCUMENTATION = """
---
module: o4n_cp_rule_debugging_disabled
short_description: Deletes disabled rules of the selected layer.
description:
  - Deletes disabled rules of the selected layer.
  - All operations are performed over Web Services API.
version_added: "1.0"
author: "Randy Rozo"
notes:
  - Testeado en linux
requirements:
  - ansible >= 2.10
options:
  layer:
    description:
      - Layer identified by the name or UID.
    type: list
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
  - name: debug disabled rules
    o4n_cp_rule_debugging_disabled:
      layer: "Test Security"
    register: output
"""
RETURN = """
output:
  description: The checkpoint verify-policy output
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
                        "number": 5,
                        "section": "REGLA ACCESO",
                        "service": [
                            "Any"
                        ],
                        "source": [
                            "10.0.10.223",
                            "10.0.10.224",
                            "10.0.10.225",
                            "10.0.10.236"
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
        "failed": false,
        "msg": {
            "layer_name": "Se han eliminado un total de 107 reglas que se encontraban en estado de 'Disable'."
        }
      }
"""

import traceback
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ..module_utils.o4n_checkpoint import login, publish, discard, logout, send_request, get_name_from_uid


def delete_access_role(provider, token, response, rule, section, uid, layer):
    url = "delete-access-rule"
    payload = {
        "uid": uid,
        "layer": layer
    }
    status, response_delete = send_request(provider, token, url, payload)
    if status:
        if response_delete["message"] == "OK":
            destinations = [get_name_from_uid(response, dest) for dest in rule['destination']]
            sources = [get_name_from_uid(response, src) for src in rule['source']]
            service = [get_name_from_uid(response, serv) for serv in rule['service']]
            vpn = [get_name_from_uid(response, vpn) for vpn in rule['vpn']]
            action = get_name_from_uid(response, rule['action'])
            time = [get_name_from_uid(response, time) for time in rule['time']]
            track = get_name_from_uid(response, rule['track']['type'])
            install_on = [get_name_from_uid(response, install_on) for install_on in rule['install-on']]
            rule_deleted = {
                "section": section,
                "enabled": rule['enabled'],
                "number": rule['rule-number'],
                "source": sources,
                "destination": destinations,
                "vpn": vpn,
                "service": service,
                "action": action,
                "time": time,
                "track": track,
                "install-on": install_on,
            }
        return True, rule_deleted

    else:
        return False, response_delete


def delete_rule_deactivated(provider: dict, layers: list, module: object):
    token = login(provider)
    url = "show-access-rulebase"
    try:
        msg_ret_dict = {}
        output = []
        for layer in layers:
            page_size = 200
            page_number = 0
            layer_dict = {}
            layer_dict[f"{layer}"] = {}
            rule_list_deleted = []
            while True:
                payload = {
                    "offset": page_number * page_size,
                    "limit": page_size,
                    "name": layer,
                    "details-level": "standard",
                    "use-object-dictionary": True
                }
                status, response = send_request(
                    provider, token, url, payload
                )
                if status:
                    for rules in response["rulebase"]:
                        if rules["type"] == "access-section":
                            section = rules["name"]
                            for rule in rules["rulebase"]:
                                if rule['enabled'] is False:
                                    uid = rule['uid']
                                    status_delete, response_delete = delete_access_role(provider, token, response, rule, section, uid, layer)
                                    if status_delete:
                                        rule_list_deleted.append(response_delete)
                        elif rules["type"] == "access-rule":
                            if rules['enabled'] is False:
                                uid = rules['uid']
                                status_delete, response_delete = delete_access_role(provider, token, response, rules, "N/A", uid, layer)
                                if status_delete:
                                    rule_list_deleted.append(response_delete)
                    if 'to' in response and 'total' in response:
                        if response['to'] >= response['total']:
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
            layer_dict[f"{layer}"] = rule_list_deleted
            if len(rule_list_deleted) > 0:
                status = True
                msg_ret_dict[f"{layer}"] = f"Se han eliminado un total de {len(rule_list_deleted)} reglas que se encontraban en estado de 'Disable'."
            else:
                status = True
                msg_ret_dict[f"{layer}"] = "No se encontraron reglas en estado 'Disable'."
            output.append(layer_dict)
        task_detail = publish(provider, token)
        msg_logout = logout(provider, token)
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
            layers=dict(required=True, type='list'),
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

    provider = module.params["provider"]
    layers = module.params['layers']

    (
        success,
        msg_ret,
        output,
        task_detail,
        msg_discard,
        msg_logout,
    ) = delete_rule_deactivated(provider, layers, module)

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
