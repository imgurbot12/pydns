"""
Simple DNS Client Usage Demo
"""
from pydns import Question, RType
from pydns.client import UdpClient

client = UdpClient([('8.8.8.8', 53)])

query = Question(b'www.google.com', RType.AAAA)
res   = client.query(query)
print(res)
