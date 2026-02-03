import requests
import time

url = "https://camo.githubusercontent.com/27dec097cb3187e8bed5dc37a2735914d51340e822bd43936001c19f5d4adb5f/68747470733a2f2f6b6f6d617265762e636f6d2f67687076632f3f757365726e616d653d4d77724830303026636f6c6f723d626c7565266c6162656c3d50726f66696c652b5669657773"

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