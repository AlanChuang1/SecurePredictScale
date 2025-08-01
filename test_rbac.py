import requests
roles = ["client", "auditor", "trainer", "admin"]
endpoints = [("POST", "/scale"), ("POST", "/train"), ("GET", "/logs")]

for role in roles:
    token = requests.get(f"http://localhost:8000/token/{role}").json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    print(f"\n🔸 Testing role: {role}")
    for method, path in endpoints:
        url = f"http://localhost:8000{path}"
        r = requests.post(url, headers=headers) if method == "POST" else requests.get(url, headers=headers)
        result = "✅ ALLOWED" if r.status_code == 200 else f"❌ DENIED ({r.status_code})"
        print(f"  {method} {path:<6} → {result}")