import urllib.parse

script = "http://localhost:5001/search?q=<script>document.title=\"B1-REFLECTED-XSS\"</script>"
encoded = urllib.parse.quote(script, safe='')  # safe='' মানে সব ক্যারেক্টার এনকোড করো

print(encoded)