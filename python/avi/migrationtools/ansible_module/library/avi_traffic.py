# prerequisite
# 1. pip install requests
#
#
# !/usr/bin/python
from ansible.module_utils.basic import *

try:
    import requests
    import shlex
    import socket
    from subprocess import call

    HAS_REQUEST = True
except ImportError:
    HAS_REQUEST = False

def main():
    """Module instantiation"""
    module = AnsibleModule(
        argument_spec=dict(
            ip_address=dict(required=False),
            request_type=dict(required=False),
            port=dict(required=False)
        )
    )

    if not HAS_REQUEST:
        module.fail_json(msg='Library not imported properly')

    # Accessing arguments
    uri = module.params.get("ip_address", None)
    request_type = module.params.get('request_type', None)
    port = module.params.get('port', None)
    # Send http get requests to generate traffic
    if request_type == 'http' or request_type == 'https':
        for i in range(0, 10):
            try:
                response = requests.get(request_type + '://' + uri + ':' + port,
                                        verify=False)
            except:
                module.fail_json(msg='Virtualservice is down')
            if response.status_code >= 200 and response.status_code <= 299:
                continue
            else:
                module.fail_json(msg='Virtualservice is down')
                break

        if response.status_code >= 200 and response.status_code <= 299:
            module.exit_json(
                stdout='Virtualservice Traffic sent successfully',
                changed=True
            )
        else:
            module.exit_json(
                stderr='Virtualservice is not reachable',
                changed=False
            )
    # Send tcp requests traffic if 0 then Success else False
    elif request_type == 'tcp':
        command = 'nc -w 2 %s %s' % (uri, port)
        cmd = shlex.split(command)
        out = call(cmd)
        if not out:
            module.exit_json(
                stderr='Tcp Traffic sent successfully',
                changed=True
            )
        else:
            module.exit_json(
                stderr='Tcp Traffic failed',
                changed=False
            )
    # type dns then do the dns lookup
    elif request_type == 'dns':
        try:
            ip = socket.gethostbyname('google.com')
        except:
            module.fail_json(msg='Not valid dns')
        if ip:
            module.exit_json(
                stderr='Dns Lookup successful %s' % ip,
                changed=True
            )
        else:
            module.exit_json(
                stderr='Dns Lookup unsuccessful',
                changed=False
            )


if __name__ == '__main__':
    main()
