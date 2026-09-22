import urllib.request
import urllib.parse
import json

# 1. Login with admin credentials
login_data = urllib.parse.urlencode({'username': 'krrish183224@gmail.com', 'password': '183@Krrish'}).encode('utf-8')
req = urllib.request.Request('http://localhost:8000/api/auth/login', data=login_data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
res = urllib.request.urlopen(req)
token = json.loads(res.read())['access_token']

def check_rep(val):
    data = json.dumps({'value': val}).encode('utf-8')
    lookup_req = urllib.request.Request(
        'http://localhost:8000/api/threat-intel/lookup',
        data=data,
        headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
    )
    res = urllib.request.urlopen(lookup_req)
    out = json.loads(res.read())
    print(f"Lookup '{val}':")
    print(f"  Status: {out['status']}")
    print(f"  Level:  {out['reputation_level']}")
    print(f"  Score:  {out['reputation_score']}%")
    print(f"  Family: {out['threat_family']}")
    print(f"  Source: {out['source']}")
    print()

print("--- Testing Threat Intel Reputation Engine ---")
check_rep('45.154.255.89') # Log4j RCE IP
check_rep('office365-verify-login.com') # EvilGinx Phishing Domain
check_rep('24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c') # WannaCry Binary Hash
check_rep('8.8.4.4') # Clean IP
