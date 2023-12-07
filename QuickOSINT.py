import socket
import requests
import whois
#Import the packages

def get_ip_address(hostname):
    return socket.gethostbyname(hostname)

def get_geolocation(ip_address):
    response = requests.get(f"https://ipinfo.io/{ip_address}/json")
    return response.json()


ip_address = get_ip_address(hostname)
geolocation = get_geolocation(ip_address)

print(f"Hostname: {hostname}")
print(f"IP: {ip_address}")
print(f"City: {geolocation['city']}")
print(f"Region: {geolocation['region']}")
print(f"Country: {geolocation['country']}")
print(f"Location: {geolocation['loc']}")

def get_whois(hostname):
    return whois.whois(hostname)

ip_address = get_ip_address(hostname)
geolocation = get_geolocation(ip_address)
whois_info = get_whois(hostname)

print(f"Hostname: {hostname}")
print(f"IP: {ip_address}")
print(f"City: {geolocation['city']}")
print(f"Region: {geolocation['region']}")
print(f"Country: {geolocation['country']}")
print(f"Location: {geolocation['loc']}")
print(f"WHOIS info: {whois_info}")