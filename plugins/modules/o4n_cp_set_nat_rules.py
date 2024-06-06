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
module: o4n_cp_set_nat_rules
short_description: Set NAT rules of the selected package.
description:
  - Set NAT rules of the selected layer.
  - All operations are performed over Web Services API.
version_added: "1.0"
author: "Randy Rozo"
notes:
  - Testeado en linux
requirements:
  - ansible >= 2.10
options:
  package:
    type: list
    required: True
    elements: dict
    options:
      name:
        description:
          - package identified by the name or UID.
        type: str
        required: True
      rules:
        description:
          - package identified by the name or UID.
        type: list
        required: False
        elements: dict
        options:
            position:
                rule_number:
                    description:
                    - Rule number.
                    type: str
                enabled:
                    description:
                    - Enable/Disable the rule.
                    type: bool
                install_on:
                    description:
                    - Which Gateways identified by the name or UID to install the policy on.
                    type: list
                    elements: str
                method:
                    description:
                    - Nat method.
                    type: str
                    choices: ['static', 'hide', 'nat64', 'nat46']
                new_position:
                    description:
                    - New position in the rulebase.
                    type: str
                original_destination:
                    description:
                    - Original destination.
                    type: str
                original_service:
                    description:
                    - Original service.
                    type: str
                original_source:
                    description:
                    - Original source.
                    type: str
                translated_destination:
                    description:
                    - Translated  destination.
                    type: str
                translated_service:
                    description:
                    - Translated  service.
                    type: str
                translated_source:
                    description:
                    - Translated  source.
                    type: str
                comments:
                    description:
                    - Comments string.
                    type: str
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
  - name: Set NAT rules
    o4n_cp_set_nat_rules:
      package:
        - name: "Web_Policy_Test"
          rules:
            - uid: 9ac113a8-751e-4f28-afed-3c278067820f
              original_destination: Test1
    register: output
"""
RETURN = """
output:
  description: The checkpoint Set NAT rules output
  type: dict
  returned: allways
  sample:
    "output": {
        "changed": false,
        "content": [
            {
                "package_name": [
                    {
                        "enabled": true,
                        "install-on": [
                            "Cluster-TEST"
                        ],
                        "method": "static",
                        "number": 1,
                        "original-destination": "Test1",
                        "original-service": "Any",
                        "original-source": "Test2",
                        "package": "TestCore",
                        "translated-destination": "Original",
                        "translated-service": "Original",
                        "translated-source": "Original"
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


def set_nat_rule(provider, packages, module):
    token = login(provider)
    url = "set-nat-rule"
    try:
        msg_ret_dict = {}
        output = []
        for desired_package in packages:
            package = desired_package["name"]
            package_dict = {}
            package_dict[f"{package}"] = {}
            rule_list = []
            for rule in desired_package["rules"]:
                payload = {}
                payload["package"] = package
                for key, value in rule.items():
                    if value:
                        payload[key.replace("_", "-")] = rule[key]

                status, response = send_request(provider, token, url, payload)

                if status:
                    rule_add = {
                        "uid": response["uid"],
                        "enabled": response["enabled"],
                        "number": rule["rule_number"],
                        "method": response["method"],
                        "original-source": response["original-source"]["name"],
                        "original-destination": response["original-destination"][
                            "name"
                        ],
                        "original-service": response["original-service"]["name"],
                        "translated-source": response["translated-source"]["name"],
                        "translated-destination": response["translated-destination"][
                            "name"
                        ],
                        "translated-service": response["translated-service"]["name"],
                        "install-on": [
                            install_on["name"] for install_on in response["install-on"]
                        ],
                    }
                    rule_list.append(rule_add)
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

            package_dict[f"{package}"] = rule_list
            output.append(package_dict)
            msg_ret_dict[f"{package}"] = f"Se han modificado '{len(rule_list)}' reglas."

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
            packages=dict(
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
                            uid=dict(required=False, type="str"),
                            rule_number=dict(
                                required=False, type="raw", choice=[str, int, dict]
                            ),
                            name=dict(required=False, type="str"),
                            new_position=dict(required=False, type="int"),
                            new_name=dict(required=False, type="str"),
                            enabled=dict(required=False, type="bool"),
                            method=dict(
                                required=False,
                                type="str",
                                choice=["static", "hide", "nat64", "nat46", "cgnat"],
                            ),
                            original_destination=dict(required=False, type="str"),
                            original_service=dict(required=False, type="str"),
                            original_source=dict(required=False, type="str"),
                            translated_destination=dict(required=False, type="str"),
                            translated_service=dict(required=False, type="str"),
                            translated_source=dict(required=False, type="str"),
                            install_on=dict(
                                required=False, type="raw", choice=[str, list]
                            ),
                            comments=dict(required=False, type="str"),
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

    packages = module.params["packages"]
    provider = module.params["provider"]

    success, msg_ret, output, task_detail, msg_discard, msg_logout = set_nat_rule(
        provider, packages, module
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
