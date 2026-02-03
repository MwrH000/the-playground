import requests
import time

url = input('Enter the URL to refresh: ').strip()

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
    if count % 5 == 0:
        print(f"Refresh #{count}")

    time.sleep(1)
