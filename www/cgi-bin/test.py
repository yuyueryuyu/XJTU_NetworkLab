import os
print("Content-Type: text/html")
print("Server: CGI Kaiyue Yu\n\n")
# 输出HTML内容
print("<html>")
print("<head><title>CGI TEST</title></head>")
print("<body>")
print("<h1>Hello from CGI!</h1>")
print("<p>Python CGI Script!</p>")
print(f"<div>We Received a {os.environ['method']} request</div>")
print(f"<div>We Received Query: {os.environ['query']}</div>")
print('''<button onclick="clickit()">You can send a POST request using this button!</button>''')
print("</body>")
print('''<script>
      async function clickit() {
        let rsp = await fetch(window.location.href, {
                    method: 'POST',
                    body: 'test=value',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    cache: 'no-store'
                });
      }
      </script>''')
print("</html>")