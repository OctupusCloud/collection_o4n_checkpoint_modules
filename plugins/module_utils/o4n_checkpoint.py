from __future__ import absolute_import, division, print_function

__metaclass__ = type

import requests
import urllib3
import json

urllib3.disable_warnings()


def login(provider):
    username = provider["user"]
    password = provider["password"]
    domain = provider["domain"]
    url = "login"

    payload = {"user": username, "password": password, "domain": domain}

    status, response = send_request(provider, None, url, payload)
    if status:
        return response["sid"]
    else:
        return response


def publish(provider, token):
    url = "publish"
    status, response = send_request(provider, token, url, None)

    if status:
        task_id = response["task-id"]
        task_status = "in progress"

        while task_status == "in progress":
            url = "show-task"
            payload = {"task-id": task_id}
            status, response = send_request(provider, token, url, payload)

            if status:
                task_status = response["tasks"][0]["status"]
                if task_status == "failed":
                    task_details = response["tasks"][0]
                elif task_status == "succeeded":
                    task_details = response["tasks"][0]
            else:
                task_details = response
                break

        return task_details

    else:
        return response


def discard(provider, token):
    url = "discard"
    status, response = send_request(provider, token, url, None)
    if status:
        return response["message"]
    else:
        return response


def logout(provider, token):
    url = "logout"
    status, response = send_request(provider, token, url, None)
    if status:
        return response["message"]
    else:
        return response


def send_request(provider, token, url, payload):
    host = provider["host"]
    port = provider["port"]
    validate_certs = provider["validate_certs"]
    url = f"https://{host}:{port}/web_api/{url}"
    headers = {"Content-Type": "application/json", "X-chkp-sid": token}

    if token is None:
        headers.pop("X-chkp-sid")

    data = json.dumps(payload) if payload else "{}"

    response_data = requests.request(
        "POST", url, headers=headers, data=data, verify=validate_certs
    )
    if response_data.ok:
        status, response_data = True, json.loads(response_data.text)
    else:
        status, response_data = False, json.loads(response_data.text)

    return status, response_data


def get_name_from_uid(response, uid):
    """Buscar en el diccionario de objetos para obtener el nombre de un objeto utilizando su UID"""
    for obje in response["objects-dictionary"]:
        if uid == obje["uid"]:
            object_name = obje["name"]
            # print(object_name)
            break
    return object_name
