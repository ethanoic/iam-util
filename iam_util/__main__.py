import boto3

role_name = 'iam-auditor'
profile_name = 'iam-auditor-406011705551'

def get_all(func, query_args = {}, list_key = 'Items', paginate_key='Marker', query_paginate_from_key='Marker'):
  data = []
  paginate_args = None
  has_more = True
  while has_more:
    if paginate_args is not None:
      response = func(**query_args, **paginate_args)
    else:
      response = func(**query_args)
    data += response[list_key]
    if paginate_key in response:
      paginate_args = {
        query_paginate_from_key: response[paginate_key]
      }
      has_more = True
    else:
      has_more = False
  return data

def get_iam_access(account):
  session = boto3.Session(profile_name=profile_name) # this uses my configured aws profile
  # credentials = session.get_credentials()
  
  """
  credential_report = iam_client.get_credential_report()
  
  with open('credential_report.csv', 'w') as f:
    f.write(credential_report['Content'].decode('utf-8'))
  """
  
  iam_client = session.client('iam')
  users = iam_client.list_users()
  
  data = [
    ['User Name', 'Policies', 'Access Keys (KeyId|Status|CreateDate)',  'CreateDate']
  ]
  
  for user in users['Users']:
    row = []
    user_name = user['UserName']
    user_arn = user['Arn']
    row.append(user_name)
    # get user policies and permissions
    policies = []
    user_policies = get_all(
      func=iam_client.list_user_policies,
      query_args={
        "UserName": user['UserName']
      },
      list_key='PolicyNames',
      paginate_key='Marker',
      query_paginate_from_key='Marker'
    )
    for policy in user_policies:
      policies.append(policy)
    row.append('|'.join(policies))
    
    user_access_keys = get_all(
      func=iam_client.list_access_keys,
      query_args={
        "UserName": user['UserName']
      },
      list_key='AccessKeyMetadata',
      paginate_key='Marker',
      query_paginate_from_key='Marker'
    )
    access_keys = []
    for access_key in user_access_keys:
      access_key_str = f"{access_key['AccessKeyId']} {access_key['Status']} {access_key['CreateDate'].strftime('%Y-%m-%d %H:%M:%S')}"
      access_keys.append(access_key_str)
    row.append('|'.join(access_keys))
    
    created_date = user['CreateDate']
    row.append(created_date.strftime('%Y-%m-%d %H:%M:%S'))

    data.append(row)
  
  with open('iam_users.csv', 'w') as f:
    for row in data:
      f.write(','.join(row) + '\n')
      
  # get sso users
  sso_client = session.client('sso-admin')
  
  data = [
    ['User Name', 'Name', 'Email', 'Role']
  ]
  instances = get_all(
    func=sso_client.list_instances,
    query_args={},
    list_key='Instances',
    query_paginate_from_key='NextToken',
    paginate_key='NextToken'
  )
  default_instance = instances[0]
  identity_store_id = default_instance['IdentityStoreId']
  
  all_permission_sets = get_all(
    func=sso_client.list_permission_sets,
    query_args={
      'InstanceArn': default_instance['InstanceArn']
    },
    list_key='PermissionSets',
    paginate_key='NextToken',
    query_paginate_from_key='NextToken',
  )
  
  for permission_set in all_permission_sets:
    users_assigned = get_all(
      func=sso_client.list_account_assignments,
      query_args={
        'AccountId': account,
        'InstanceArn': default_instance['InstanceArn'],
        'PermissionSetArn': permission_set
      },
      list_key='AccountAssignments',
      query_paginate_from_key='NextToken',
      paginate_key='NextToken'
    )
    
    id_store = session.client('identitystore')
    for user_assigned in users_assigned:
      row = []
      principal_id = user_assigned['PrincipalId']
      
      user = id_store.describe_user(
        IdentityStoreId=identity_store_id,
        UserId=principal_id
      )
      
      user_name = user['UserName']
      row.append(user_name)
      
      name = user['DisplayName']
      row.append(name)
      
      emails = []
      for email in user['Emails']:
        emails.append(email['Value'])
      user_emails = '|'.join(emails)
      row.append(user_emails)
      
      permission_set_arn = user_assigned['PermissionSetArn']
      permission_set = sso_client.describe_permission_set(
        InstanceArn=default_instance['InstanceArn'],
        PermissionSetArn=permission_set_arn
      )
      
      row.append(permission_set['PermissionSet']['Name'])
      
      data.append(row)
    
  
  with open('sso_users.csv', 'w') as f:
    for row in data:
      f.write(','.join(row) + '\n')

if __name__ == "__main__":
  account = '406011705551'
  get_iam_access(account)