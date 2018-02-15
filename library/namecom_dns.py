#!/usr/bin/env python

import json
import requests
from ansible.module_utils.basic import *


SESSION_TOKEN = None
DOMAIN_RECORDS = None


def _login(api_url,username,api_token):
    global SESSION_TOKEN

    r = requests.post("%s/api/login" % api_url, json={
                'username': username,
                'api_token': api_token,
            })


    if (r.json()['result']['code']==100):
        SESSION_TOKEN = r.json()['session_token']
    else:
        raise(Exception("Unable to login, error code=%s message=%s" % 
                            (r.json()['result']['code'],r.json()['result']['message'])))



def _logout(api_url):
    r = requests.get("%s/api/logout" % api_url, headers={
                'Api-Session-Token': SESSION_TOKEN,
            })


def _list_records(api_url,domain):
    global DOMAIN_RECORDS

    r = requests.get("%s/api/dns/list/%s" % (api_url,domain), headers={
                'Api-Session-Token': SESSION_TOKEN,
            })

    if (r.json()['result']['code']==100):
        DOMAIN_RECORDS = r.json()['records']
    else:
        raise(Exception("Unable to list domain, error code=%s message=%s" % 
                            (r.json()['result']['code'],r.json()['result']['message'])))


def _get_record(domain,hostname):
    for record in DOMAIN_RECORDS:
        if record['name'] == "%s.%s" % (hostname,domain):
            return(record)

    return(None)


def create_record(data):
    # Verify what currently exists
    record = _get_record(data['domain'],data['hostname'])
    if record:
        if record['content']==data['content'] and \
           int(record['ttl'])==data['ttl'] and \
           record['type']==data['type']:
            return(False, {})
        else:
            # Cannot update existing record, so must delete first
            return(True, {'record': record, 'data': data})
            remove_record(data)
    
    # Create record if needed
    r = requests.post("%s/api/dns/create/%s" % (data['api_url'],data['domain']), headers={
                'Api-Session-Token': SESSION_TOKEN,
            },json={
                'hostname': data['hostname'],
                'content': data['content'],
                'ttl': data['ttl'],
                'type': data['type'],
            })
    if (r.json()['result']['code']==100):  
        return(True, {
                'create_date': r.json()['create_date'],
                'record_id': r.json()['record_id'],
            })
    else:
        raise(Exception("Unable to create new record %s.%s, error code=%s message=%s" % 
                            (data['hostname'],data['domain'],r.json()['result']['code'],r.json()['result']['message'])))


def remove_record(data):
    # Verify what currently exists
    record = _get_record(data['domain'],data['hostname'])
    if not record:
        return(False, {})
    
    # Remove record if needed
    r = requests.post("%s/api/dns/delete/%s" % (data['api_url'],data['domain']), headers={
                'Api-Session-Token': SESSION_TOKEN,
            },json={
                'record_id': record['record_id'],
            })
    if (r.json()['result']['code']==100):  
        return(True, record)
    else:
        raise(Exception("Unable to delete record %s.%s, error code=%s message=%s" % 
                            (data['hostname'],data['domain'],r.json()['result']['code'],r.json()['result']['message'])))


def main():

    fields = {
          "api_url": {"default": "https://api.name.com", "type": "str"},
          "username": {"required": True, "type": "str" },
          "api_token": {"required": True, "type": "str" },
          "domain": {"required": True, "type": "str" },
          "hostname": {"required": True, "type": "str" },
          "content": {"required": False, "type": "str" },
          "type": {"default": "A", "type": "str" },
          "ttl": {"default": 300, "type": "int" },

          "state": {
              "default": "present", 
              "choices": ['present', 'absent'],  
              "type": 'str' 
          },
      }

    choice_map = {
      "present": create_record,
      "absent": remove_record, 
    }
  

    module = AnsibleModule(argument_spec=fields)

    _login(module.params['api_url'],module.params['username'],module.params['api_token'])
    _list_records(module.params['api_url'],module.params['domain'])
    has_changed, result = choice_map.get(module.params['state'])(module.params)
    _logout(module.params['api_url'])

    module.exit_json(changed=has_changed, meta=result)


if __name__ == '__main__':  
    main()



