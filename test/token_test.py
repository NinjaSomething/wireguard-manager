import requests

# Replace with your values
token_url = "https://wireguard-manager-jschaan.auth.us-west-2.amazoncognito.com/oauth2/token"
client_id = "33dd574hk6his25m6nbrovo78u"
client_secret = "if303depurgpi5t8fkn9vtq4thhh47kiqh2iauaig68hq7i954a"

resp = requests.post(
    token_url,
    data=f"grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}&scope=default-m2m-resource-server-aspgxq/admin default-m2m-resource-server-aspgxq/user",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
)

resp.raise_for_status()
token = resp.json()["access_token"]

print("Test unauthenticated endpoint:")
for url in [
    "http://localhost:8000/unprotected",
    "http://localhost:8000/protected",
    "http://localhost:8000/admin_only",
    "http://localhost:8000/user_only",
]:
    r = requests.get(url)
    print(r.status_code, r.text)


print("Test using access token:", token)
for url in [
    "http://localhost:8000/unprotected",
    "http://localhost:8000/protected",
    "http://localhost:8000/admin_only",
    "http://localhost:8000/user_only",
]:
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    print(r.status_code, r.text)
