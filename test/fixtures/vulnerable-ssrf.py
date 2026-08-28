import requests
from flask import request
from lxml import etree


@app.route("/proxy")
def proxy():
    return requests.get(request.args.get("url")).text


def parse_untrusted(xml_text):
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(xml_text, parser)
