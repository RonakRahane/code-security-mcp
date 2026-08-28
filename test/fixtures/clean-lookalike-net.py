import requests
from lxml import etree
from defusedxml import minidom

r = requests.get("https://api.example.com/health")
p = etree.XMLParser(resolve_entities=False, no_network=True)
doc = minidom.parseString(xml_text)
