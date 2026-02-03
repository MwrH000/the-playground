import requests
import time

url = ""

requests.packages.urllib3.disable_warnings()

session = requests.Session()
session.verify = False

count = 0

while True:
    try:
        session.get(url, timeout=0.1)
    except:
        pass
    
    count += 1
    print(f"Refresh #{count}")
    
    time.sleep(1)