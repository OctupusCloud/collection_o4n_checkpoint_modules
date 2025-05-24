#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'octupus',
                    'metadata_version': '1.1'}

DOCUMENTATION = """
---
module: o4n_cp_nat_rule_debugging_disabled
short_description: Deletes disabled nat rules of the selected package.
description:
  - Deletes disabled nat rules of the selected package.
  - All operations are performed over Web Services API.
version_added: "1.0"
author: "Randy Rozo"
notes:
  - Testeado en linux
requirements:
  - ansible >= 2.10
  - Establecer `ansible_python_interpreter` a Python 3 si es necesario.
options:
  packages:
    description:
      - Package identified by the name or UID.
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
  - name: debug disabled nat rules
    o4n_cp_nat_rule_debugging_disabled:
      packages: "Test"
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
                "package_name": [
                    {
                        "enabled": false,
                        "install-on": [
                            "Cluster-TEST"
                        ],
                        "number": 419,
                        "original-destination": "Any",
                        "original-service": "Any",
                        "original-source": "Any",
                        "section": "NAT",
                        "translated-destination": "Original",
                        "translated-service": "Original",
                        "translated-source": "NAT_Multiple_TEST"
                    }
                ]
            }
        ],
        "failed": false,
        "msg": {
            "packages_name": "Se han eliminado un total de 107 reglas que se encontraban en estado de 'Disable'."
        }
      }
"""

import traceback
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ..module_utils.o4n_checkpoint import login, publish, discard, logout, send_request, get_name_from_uid


def delete_nat_rule(provider, token, response, rule, section, uid, package):
    url = "delete-nat-rule"
    payload = {
        "uid": uid,
        "package": package
    }
    status, response_delete = send_request(provider, token, url, payload)
    if status:
        if response_delete["message"] == "OK":
            original_source = get_name_from_uid(response, rule['original-source'])
            original_destination = get_name_from_uid(response, rule['original-destination'])
            original_service = get_name_from_uid(response, rule['original-service'])
            translated_source = get_name_from_uid(response, rule['translated-source'])
            translated_destination = get_name_from_uid(response, rule['translated-destination'])
            translated_service = get_name_from_uid(response, rule['translated-service'])
            install_on = [get_name_from_uid(response, install_on) for install_on in rule['install-on']]
            rule_deleted = {
                "section": section,
                "enabled": rule['enabled'],
                "number": rule['rule-number'],
                "original-source": original_source,
                "original-destination": original_destination,
                "original-service": original_service,
                "translated-source": translated_source,
                "translated-destination": translated_destination,
                "translated-service": translated_service,
                "install-on": install_on,
            }
        return True, rule_deleted

    else:
        return False, response_delete


def delete_nat_rule_deactivated(provider: dict, packages: list, module: object):
    token = login(provider)
    url = "show-nat-rulebase"
    try:
        msg_ret_dict = {}
        output = []
        for package in packages:
            page_size = 200
            page_number = 0
            layer_dict = {}
            layer_dict[f"{package}"] = {}
            rule_list_deleted = []
            while True:
                payload = {
                        "offset": page_number * page_size,
                        "limit": page_size,
                        "package": package,
                        "details-level": "standard",
                        "use-object-dictionary": True
                    }
                status, response = send_request(
                    provider, token, url, payload
                )
                if status:
                    for rules in response["rulebase"]:
                        if rules["type"] == "nat-section":
                            section = rules["name"]
                            for rule in rules["rulebase"]:
                                if rule['enabled'] is False:
                                    uid = rule['uid']
                                    status_delete, response_delete = delete_nat_rule(provider, token, response, rule, section, uid, package)
                                    if status_delete:
                                        rule_list_deleted.append(response_delete)
                        elif rules["type"] == "nat-rule":
                            if rules['enabled'] is False:
                                uid = rules['uid']
                                status_delete, response_delete = delete_nat_rule(provider, token, response, rules, "N/A", uid, package)
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
            layer_dict[f"{package}"] = rule_list_deleted
            if len(rule_list_deleted) > 0:
                status = True
                msg_ret_dict[f"{package}"] = f"Se han eliminado un total de {len(rule_list_deleted)} reglas que se encontraban en estado de 'Disable'."
            else:
                status = True
                msg_ret_dict[f"{package}"] = "No se encontraron reglas en estado 'Disable'."
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
            packages=dict(required=True, type='list'),
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

    packages = module.params["packages"]
    provider = module.params["provider"]

    (
        success,
        msg_ret,
        output,
        task_detail,
        msg_discard,
        msg_logout,
    ) = delete_nat_rule_deactivated(provider, packages, module)

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
