#!/usr/bin/env python
'''
Created on September 15, 2016

@author: Gaurav Rastogi (grastogi@avinetworks.com)
'''

import json
from copy import deepcopy
import yaml
import argparse
import re
import requests

DEFAULT_SKIP_TYPES = [
    'SystemConfiguration', 'Network', 'debugcontroller', 'VIMgrVMRuntime',
    'VIMgrIPSubnetRuntime', 'Alert', 'VIMgrSEVMRuntime', 'VIMgrClusterRuntime',
    'VIMgrHostRuntime', 'DebugController', 'ServiceEngineGroup',
    'SeProperties', 'ControllerProperties', 'CloudProperties']


class AviAnsibleConverter(object):
    common_task_args = {'controller': "{{ controller }}",
                        'username': "{{ username }}",
                        'password': "{{ password }}"
                        }
    ansible_dict = dict({
        'connection': 'local',
        'hosts': 'localhost',
        'vars': common_task_args,
        'tasks': []})
    skip_fields = ['uuid', 'url', 'ref_key', 'se_uuids', 'key_passphrase']
    skip_types = set(DEFAULT_SKIP_TYPES)
    default_meta_order = [
        "ControllerLicense",
        "SeProperties",
        "SecureChannelToken",
        "SecureChannelMapping",
        "VIMgrIPSubnetRuntime",
        "Tenant",
        "ControllerProperties",
        "CloudProperties",
        "SecureChannelAvailableLocalIPs",
        "JobEntry",
        "Role",
        "DebugController",
        "AutoScaleLaunchConfig",
        "MicroService",
        "AuthProfile",
        "AnalyticsProfile",
        "APICLifsRuntime",
        "LogControllerMapping",
        "SnmpTrapProfile",
        "AlertSyslogConfig",
        "NetworkRuntime",
        "AlertObjectList",
        "VIPGNameInfo",
        "CertificateManagementProfile",
        "CloudRuntime",
        "CloudConnectorUser",
        "DebugServiceEngine",
        "HardwareSecurityModuleGroup",
        "HealthMonitor",
        "VIDCInfo",
        "VIMgrControllerRuntime",
        "GlobalHealthMonitor",
        "IpamDnsProviderProfile",
        "StringGroup",
        "Backup",
        "DebugVirtualService",
        "AlertScriptConfig",
        "NetworkProfile",
        "GlobalLB",
        "IpAddrGroup",
        "Cluster",
        "SSLProfile",
        "PKIProfile",
        "ApplicationPersistenceProfile",
        "MicroServiceGroup",
        "SSLKeyAndCertificate",
        "GlobalService",
        "ApplicationProfile",
        "NetworkSecurityPolicy",
        "SystemConfiguration",
        "Cloud",
        "AlertEmailConfig",
        "PriorityLabels",
        "PoolGroupDeploymentPolicy",
        "VIMgrVMRuntime",
        "VrfContext",
        "ActionGroupConfig",
        "VIMgrHostRuntime",
        "AlertConfig",
        "VIMgrNWRuntime",
        "VIMgrClusterRuntime",
        "VIMgrSEVMRuntime",
        "ServerAutoScalePolicy",
        "Network",
        "VIMgrDCRuntime",
        "ServiceEngineGroup",
        "Pool",
        "VIMgrVcenterRuntime",
        "ServiceEngine",
        "PoolGroup",
        "HTTPPolicySet",
        "VSDataScriptSet",
        "VirtualService",
        "Alert",
        "Application"
    ]

    REF_MATCH = re.compile('^/api/[\w/.#&-]*#[\s|\w/.&-:]*$')
    REL_REF_MATCH = re.compile('^/api/*$')
    HTTP_TYPE = 'http'
    SSL_TYPE = 'ssl'
    DNS_TYPE = 'dns'
    L4_TYPE = 'l4'
    APPLICATION_PROFILE_REF = 'application_profile_ref'

    def __init__(self, avi_cfg, outdir, skip_types=None, filter_types=None):
        self.outdir = outdir
        self.avi_cfg = avi_cfg
        if skip_types is None:
            skip_types = DEFAULT_SKIP_TYPES
        if skip_types:
            self.skip_types = (skip_types if type(skip_types) == list
                               else skip_types.split(','))

        if filter_types:
            self.filter_types = \
                (set(filter_types) if type(filter_types) == list
                 else set(filter_types.split(',')))
        else:
            self.filter_types = None

    def transform_ref(self, x, obj):
        """
        :param obj:
        :param x:
        :return:
        """
        # converts ref into the relative reference
        if not (isinstance(x, basestring) or isinstance(x, unicode)):
            return x
        if x == '/api/tenant/admin':
            x = '/api/tenant/admin#admin'
        if self.REF_MATCH.match(x):
            name = x.rsplit('#', 1)[1]
            obj_type = x.split('/api/')[1].split('/')[0]
            # print name, obj_type
            x = '/api/%s?name=%s' % (obj_type, name)
        elif self.REL_REF_MATCH.match(x):
            ref_parts = x.split('?')
            for p in ref_parts[1].split('&'):
                k, v = p.split('=')
                if k.strip() == 'cloud':
                    obj['cloud_ref'] = '/api/cloud?name=%s' % v.strip()
                    print 'updating cloud ', obj
                elif k.strip() == 'tenant':
                    obj['tenant_ref'] = '/api/tenant?name=%s' % v.strip()
                    print 'updating tenant_ref ', obj
                elif k.strip() == 'name':
                    x = '%s?name=%s' % ref_parts[0]
        else:
            print x, 'did not match ref'
        return x

    def transform_obj_refs(self, obj):
        if type(obj) != dict:
            return
        for k, v in obj.iteritems():
            if type(v) == dict:
                self.transform_obj_refs(v)
                continue
            if k.endswith('_ref') or k.endswith('_refs'):
                # check for whether v is string or list of strings
                if isinstance(v, basestring) or isinstance(v, unicode):
                    ref = self.transform_ref(v, obj)
                    obj[k] = ref
                elif type(v) == list:
                    new_list = []
                    for item in v:
                        if type(item) == dict:
                            self.transform_obj_refs(item)
                        elif (isinstance(item, basestring) or
                                  isinstance(item, unicode)):
                            new_list.append(self.transform_ref(item, obj))
                    if new_list:
                        obj[k] = new_list
            elif type(v) == list:
                for item in v:
                    self.transform_obj_refs(item)
        return obj

    def build_ansible_objects(self, obj_type, objs, ansible_dict):
        """
        adds per object type ansible task
        :param obj_type type of object
        :param iterable list of objects
        :param ansible_dict: output dict
        Returns
            Ansible dict
        """
        for obj in objs:
            task = deepcopy(obj)
            for skip_field in self.skip_fields:
                task.pop(skip_field, None)
            self.transform_obj_refs(task)
            task.update(self.common_task_args)
            task_name = (
                "Create or Update %s: %s" % (obj_type, obj['name'])
                if 'name' in obj else obj_type)
            task_id = 'avi_%s' % obj_type.lower()
            task.update(
                {'api_version': self.avi_cfg['META']['version']['Version']})
            ansible_dict['tasks'].append({task_id: task, 'name': task_name,
                                          'tags': [obj['name'],
                                                   "create_object"]})
        return ansible_dict

    def get_status_vs(self, vs_name, f5server, username, password):
        """
        This function is used for getting status for F5 virtualservice.
        :param vs_name: virtualservice name
        :param username: f5 username
        :param password: f5 password
        :return: if enabled tag present.
        """
        status = requests.get('https://%s/mgmt/tm/ltm/virtual/%s/'
                              % (f5server, vs_name), verify=False, auth=(username, password))
        status = json.loads(status.content)
        if status.pop('enabled', None):
            return True

    def get_f5_attributes(self, vs_dict):
        """
        This function used for generating f5 playbook configuration.
        It pop out the parameters like ip address, services, controller,
        and user name.
        It adds related parameters for f5 yaml generation.
        :param vs_dict: contains all virtualservice list.
        :return:
        """
        f5_dict = deepcopy(vs_dict)
        f5_dict.pop('ip_address')
        f5_dict.pop('services')
        f5_dict.pop('controller')
        f5_dict.pop('username')
        f5_dict['server'] = "{{server}}"
        f5_dict['validate_certs'] = False
        f5_dict['user'] = "{{f5_username}}"
        f5_dict['password'] = "{{f5_password}}"
        return f5_dict

    def create_f5_ansible_disable(self, f5_dict, ansible_dict):
        """
        This function used to disabled f5 virtualservice.
        :param f5_dict: contains f5 related attributes.
        :param ansible_dict: used for playbook generation.
        :return:
        """
        f5_values = deepcopy(f5_dict)
        f5_values['state'] = 'disabled'
        ansible_dict['tasks'].append(
            {'name': "Disable F5 virtualservice: %s" % f5_dict['name'],
             'bigip_virtual_server': f5_values, 'delegate_to': 'localhost',
             'tags': ['DisableF5', f5_dict['name']]})

    def create_avi_ansible_enable(self, vs_dict, ansible_dict):
        """
        This function is used to enable the avi virtual service.
        :param vs_dict: avi virtualservice related parameters.
        :param ansible_dict: used for playbook generation.
        :return:
        """
        avi_enable = deepcopy(vs_dict)
        avi_enable['enabled'] = True
        ansible_dict['tasks'].append(
            {'name': "Enable AVI virtualservice: %s" % avi_enable['name'],
             'avi_virtualservice': avi_enable, 'tags': ['Enableavi',
                                                        avi_enable['name']]})

    def generate_avi_vs_traffic(self, vs_dict, ansible_dict,
                                application_profile):
        """
        This function is used for generating tags for avi traffic.
        :param vs_dict: avi virtualservice attributes.
        :param ansible_dict: used for playbook generation.
        :param application_profile: dict used to for request type
        eg: request type : dns, http, https.
        :return:
        """
        avi_traffic_dict = dict()
        avi_traffic_dict['request_type'] = \
            self.get_request_type(application_profile.split('name=')[1])
        if avi_traffic_dict['request_type'] != 'dns':
            avi_traffic_dict['port'] = vs_dict['services'][0]['port']
            avi_traffic_dict['ip_address'] = vs_dict['ip_address']['addr']
        ansible_dict['tasks'].append(
            {'name': "Generate Avi virtualservice trafic: %s" % vs_dict['name'],
             'avi_traffic': avi_traffic_dict, 'tags': [vs_dict['name']]})

    def create_avi_ansible_disable(self, vs_dict, ansible_dict):
        """
        This function is used to disable the avi virtual service.
        :param vs_dict: avi virtualservice attributes.
        :param ansible_dict: used for playbook generation.
        :return:
        """
        avi_enable = deepcopy(vs_dict)
        avi_enable['enabled'] = False
        ansible_dict['tasks'].append(
            {'name': "Disable AVI virtualservice: %s" % avi_enable['name'],
             'avi_virtualservice': avi_enable, 'tags': ['Disableavi',
                                                        avi_enable['name']]})

    def create_f5_ansible_enable(self, f5_dict, ansible_dict):
        """
        This function is used to enable the f5 virtualservice.
        :param f5_dict: f5 attributes
        :param ansible_dict: used for playbook generation.
        :return:
        """
        f5_values = deepcopy(f5_dict)
        f5_values['state'] = 'enabled'
        ansible_dict['tasks'].append(
            {'name': "Enable F5 virtualservice: %s" % f5_dict['name'],
             'bigip_virtual_server': f5_values, 'delegate_to': 'localhost',
             'tags': ['EnableF5', f5_dict['name']]})

    def get_request_type(self, name):
        """
        This function is used to get the type of virtualservice.
        :param name: application profile name.
        :return: request type
        """
        type = [app_profile['type'] for app_profile in
                self.avi_cfg['ApplicationProfile'] if
                app_profile['name'] == name]
        if self.HTTP_TYPE in str(type).lower():
            return 'http'
        elif self.SSL_TYPE in str(type).lower():
            return 'https'
        elif self.DNS_TYPE in str(type).lower():
            return 'dns'
        elif self.L4_TYPE in str(type).lower():
            return 'tcp'

    def generate_traffic(self, ansible_dict, f5server, username, password):
        """
        Generate the ansible playbook for Traffic generation.
        :param ansible_dict: ansible dict for generating yaml.
        :return:
        """
        for vs in self.avi_cfg['VirtualService']:
            if self.get_status_vs(vs['name'], f5server, username, password):
                vs_dict = dict()
                vs_dict['name'] = vs['name']
                vs_dict['ip_address'] = vs['vip'][0]['ip_address']
                vs_dict['services'] = vs['services']
                vs_dict['controller'] = "{{controller}}"
                vs_dict['username'] = "{{username}}"
                vs_dict['password'] = "{{password}}"
                f5_dict = self.get_f5_attributes(vs_dict)
                self.create_f5_ansible_disable(f5_dict, ansible_dict)
                self.create_avi_ansible_enable(vs_dict, ansible_dict)
                if self.APPLICATION_PROFILE_REF in vs:
                    self.generate_avi_vs_traffic(vs_dict, ansible_dict,
                                                 vs[self.APPLICATION_PROFILE_REF])
                self.create_avi_ansible_disable(vs_dict, ansible_dict)
                self.create_f5_ansible_enable(f5_dict, ansible_dict)

    def write_ansible_playbook(self, f5server=None, f5user=None, f5password=None):
        """
        Create the ansible playbook based on output json
        """
        ad = deepcopy(self.ansible_dict)
        meta = self.avi_cfg['META']
        if 'order' not in meta:
            meta['order'] = self.default_meta_order
        for obj_type in meta['order']:
            if self.filter_types and obj_type not in self.filter_types:
                continue
            if obj_type not in self.avi_cfg or obj_type in self.skip_types:
                continue
            self.build_ansible_objects(obj_type, self.avi_cfg[obj_type], ad)
        if f5server and f5user and f5password:
            self.generate_traffic(ad, f5server, f5user, f5password)
        with open('%s/avi_config.yml' % self.outdir, "w+") as outf:
            outf.write('# Auto-generated from Avi Configuration\n')
            outf.write('---\n')
            yaml.safe_dump([ad], outf, default_flow_style=False, indent=2)


HELP_STR = '''
Converts Avi Config JSON to Ansible Playbooks.
Please ensure configuration is exported with options include_name=true&uuid_refs=true as:
Example:
    api/configuration/export?include_name=true&uuid_refs=true

Example to export a single virtualservice:
    api/configuration/export/virtualservice/<vs-uuid>?include_name=true&uuid_refs=true

Example to export a single serviceengine:
    api/configuration/export/serviceengine/>se_uuid>?include_name=true&uuid_refs=true
'''

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=(HELP_STR))
    parser.add_argument(
        '-c', '--config_file', help='location of configuration file',
        default='avi_config.json')
    parser.add_argument('-o', '--output_dir', help='Ansible dir',
                        default='.')
    parser.add_argument(
        '-s', '--skip_types',
        help='Comma separated list of Avi Object types to '
             'skip during conversion.\n  Eg. -s DebugController,'
             'ServiceEngineGroup will skip debugcontroller and '
             'serviceengine objects',
        default=DEFAULT_SKIP_TYPES)
    parser.add_argument(
        '-f', '--filter_types',
        help='Comma separated list of Avi Objects types to '
             'include during conversion.\n Eg. -f VirtualService,'
             'Pool will do ansible conversion only for '
             'Virtualservice and Pool objects',
        default=[])
    args = parser.parse_args()

    with open(args.config_file, "r+") as f:
        avi_cfg = json.loads(f.read())
        aac = AviAnsibleConverter(
            avi_cfg, args.output_dir, skip_types=args.skip_types,
            filter_types=args.filter_types)
        aac.write_ansible_playbook()
