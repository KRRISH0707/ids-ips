import urllib.request
import re

def verify():
    html = urllib.request.urlopen('http://localhost:3000/demo').read().decode('utf-8')
    scripts = re.findall(r'src="(/_next/[^"]+\.js)"', html)
    print(f"Found {len(scripts)} scripts in /demo")
    
    found_scenarios = False
    for script in scripts:
        url = 'http://localhost:3000' + script
        js_content = urllib.request.urlopen(url).read().decode('utf-8', errors='ignore')
        if 'LockBit 3.0 Ransomware' in js_content and 'CVE-2021-44228' in js_content:
            found_scenarios = True
            print(f"Matched real attack scenarios in bundle: {script}")
            break
            
    print("Found Attack Scenarios in Bundle:", found_scenarios)
    assert found_scenarios, "Attack scenarios not found in bundles!"
    print("ALL BUNDLE VERIFICATIONS PASSED!")

if __name__ == '__main__':
    verify()
