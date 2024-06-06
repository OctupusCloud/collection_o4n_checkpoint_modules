#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'octupus',
                    'metadata_version': '1.1'}

DOCUMENTATION = """
---
module: o4n_cp_verify_policy
short_description: Verifies the policy of the selected package.
description:
  - Verifies the policy of the selected package.
  - All operations are performed over Web Services API.
version_added: "1.0"
author: "Randy Rozo"
notes:
  - Testeado en linux
requirements:
  - ansible >= 2.10
options:
  policy_package:
    description:
      - Policy package identified by the name or UID.
    type: str
    required: True
"""

EXAMPLES = """
tasks:
  - name: verify policy
    o4n_cp_verify_policy:
      policy_package: standard
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
        "msg": [
            {
                "workSession": "d41ded1e-4af4-457c-bf3a-7ac53508f79e",
                "title": "Verification of policy 'Test' completed successfully",
                "notifications": [],
                "warnings": [],
                "errors": []
            }
        ],
        "failed": false,
      }
"""

import traceback
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ..module_utils.o4n_checkpoint import login, discard, logout, send_request


def verify_policy(provider, policy_package, token):
    url = "verify-policy"
    payload = {
        "policy-package": policy_package
    }
    status, response = send_request(provider, token, url, payload)
    if status:
        task_id = response["task-id"]
        return True, task_id
    else:
        return False, response


def show_task(provider, policy_package, module):
    token = login(provider)
    try:
        validate, task_id = verify_policy(provider, policy_package, token)
        if validate is False:
            msg_discard = discard(provider, token)
            msg_logout = logout(provider, token)
            module.fail_json(
                failed=True,
                msg=task_id,
                content=[],
                publish=[],
                discard=msg_discard,
                logout=msg_logout,
            )
        task_status = "in progress"
        url = "show-task"
        while task_status == "in progress":
            payload = {
                "task-id": task_id
            }

            status_response, response = send_request(provider, token, url, payload)
            if status_response:
                task_status = response["tasks"][0]["status"]
                if task_status == "failed":
                    task_details = response["tasks"][0]
                    status = False
                    msg_ret = task_details
                elif task_status == "succeeded":
                    task_details = response["tasks"][0]
                    status = True
                    msg_ret = task_details
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

        msg_logout = logout(provider, token)
        return status, msg_ret, [], [], [], msg_logout

    except Exception as error:
        status = False
        tb = traceback.format_exc()
        msg_ret = f"Error: <{str(error)}>\n{tb}"
        msg_logout = logout(provider, token)

        return status, msg_ret, [], [], [], msg_logout


def main():
    module = AnsibleModule(
        argument_spec=dict(
            policy_package=dict(required=True, type='str'),
            provider=dict(
                type='dict',
                default={},
                options=dict(
                    host=dict(type='str', required=True, fallback=(env_fallback, ['CP_HOST'])),
                    user=dict(type='str', required=True, fallback=(env_fallback, ['CP_USER', 'ANSIBLE_NET_USERNAME'])),
                    password=dict(type='str', required=True, no_log=True, fallback=(env_fallback, ['CP_PASSWORD', 'ANSIBLE_NET_USERNAME'])),
                    port=dict(type='int', default=443, fallback=(env_fallback, ['CP_PORT'])),
                    validate_certs=dict(type='bool', default=False, fallback=(env_fallback, ['CP_VALIDATE_CERTS'])),
                    domain=dict(type='str', required=True, fallback=(env_fallback, ['CP_DOMAIN'])),
                )
            )
        ),
    )
    provider = module.params['provider']
    policy_package = module.params['policy_package']

    success, msg_ret, output, task_detail, msg_discard, msg_logout = show_task(provider, policy_package, module)
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
