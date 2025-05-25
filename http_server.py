import socket
import os
import threading
import ssl
import zlib
import hashlib
import time
import logging
from logging import handlers
from datetime import datetime, timezone
import urllib.parse
import subprocess
import sys
import argparse

class NetworkError(RuntimeError):
    '''
    为服务端编写的错误类，当错误的时候抛出
    '''
    def __init__(self, code, msg):
        self.msg = msg
        self.code = code


class WebServer:
    '''
    WEB服务器类
    '''
    def __init__(self, host, port, logger, root, ssl_cert=None, ssl_key=None):
        self.host = host
        self.port = port
        self.logger = logger
        self.root = os.path.abspath(root)
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.sessions = {}
        self.running = False
        self.socket = None

    def start(self):
        '''
        运行服务器，构建socket
        '''
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        
        # 如果ssl证书和ssl密钥存在，则用ssl对socket进行包裹，构建https服务器
        if self.ssl_cert and self.ssl_key:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=self.ssl_cert, keyfile=self.ssl_key)
            self.socket = context.wrap_socket(self.socket, server_side=True)
        
        # 开始监听
        self.socket.listen(5)
        self.running = True
        self.logger.info(f"Server started on {'https' if self.ssl_cert else 'http'}://{self.host}:{self.port}")

        # 每个连接调用threading库单开一个线程进行处理
        while self.running:
            try:
                conn, addr = self.socket.accept()
                threading.Thread(target=self.handle_connection, args=(conn, addr)).start()
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error accepting connection: {e}")

    def stop(self):
        '''
        关闭服务器
        '''
        self.running = False
        if self.socket:
            self.socket.close()
        self.logger.info("Server stopped")

    def handle_connection(self, conn, addr):
        '''
        每个线程的入口，处理连接
        '''
        ip, port = addr
        
        try:
            while True:
                # 读取请求，如果错误报bad request
                try:
                    request = self.read_request(conn)
                except NetworkError as e:
                    response, code = self.error_response(e.code, e.msg)
                    self.logger.info(f"ip={ip}, port={port}, code={code}, msg={e.msg}")
                    conn.sendall(response)
                    break
                
                if not request:
                    break
                
                headers = request.get('headers', {})
                # 根据request， 处理并返回response和状态码
                response, code = self.process_request(request, addr)
                
                self.logger.info(f"ip={ip}, port={port}, method={request['method']}, path={request['path']}, version={request['version']}, UA = {headers.get('user-agent', None)}, code={code}")
                conn.sendall(response)
                if headers.get('connection', '').lower() != 'keep-alive':
                    break
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
        finally:
            conn.close()

    def read_request(self, conn):
        '''
        读取并解析请求，返回一个字典
        '''
        try:
            data = b''
            while b'\r\n\r\n' not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return None
                data += chunk

            header_end = data.find(b'\r\n\r\n')
            headers = data[:header_end].decode()
            body = data[header_end+4:]

            header_lines = headers.split('\r\n')
            method, path, version = header_lines[0].split()
            headers = {}
            for line in header_lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.lower()] = value
            
            if 'cookie' in headers:
                cookies = headers['cookie'].split('; ')
                cookies_dict = {}
                for cookie in cookies:
                    pair = cookie.split('=')
                    cookies_dict[pair[0]] = pair[1]
                headers['cookie'] = cookies_dict

            if 'content-length' in headers:
                content_length = int(headers['content-length'])
                if content_length < 0:
                    raise NetworkError(400, "Bad Request")
                headers['content-length'] = content_length
                while len(body) < content_length:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    body += chunk

            elif 'transfer-encoding' in headers and 'chunked' in headers['transfer-encoding'].lower():
                body = self.read_chunked_body(conn, body)

            return {
                'method': method,
                'path': path,
                'version': version,
                'headers': headers,
                'body': body
            }
        except:
            raise NetworkError(400, "Bad Request")

    def read_chunked_body(self, conn, initial):
        '''
        对于进行分段编码的请求，进行特殊处理
        '''
        data = initial
        result = b''
        while True:
            chunk_header = data.split(b'\r\n', 1)[0]
            try:
                chunk_size = int(chunk_header, 16)
            except:
                break
            
            if chunk_size == 0:
                break

            chunk_end = len(chunk_header) + 2 + chunk_size + 2
            while len(data) < chunk_end:
                data += conn.recv(4096)
            
            result += data[len(chunk_header) + 2:chunk_end - 2]
            data = data[chunk_end:]
        
        return result
    
    def check_ok(self, request):
        '''
        对于包含Expect=100-continue的请求头的请求，进行检查并返回100-Continue或417-Expectation Failed
        '''
        try:
            headers = request['headers']
            cookie = headers.get('cookie', {})
            whole_path = request['path'].split('?', 1)
            path = self.url_decode(whole_path[0])
            if 'session' not in cookie or cookie['session'] not in self.sessions:
                raise NetworkError(417, "Expectation Failed")
            local_path = os.path.normpath(os.path.join(self.root, path.lstrip('/')))
            if not local_path.startswith(self.root):
                raise NetworkError(417, "Expectation Failed")
            if (request['method'] == 'HEAD' or request['method'] == 'GET') and request['body'] != b'':
                raise NetworkError(417, "Expectation Failed")
            if headers.get('content-length', 0) > 1024 * 1024 * 1024:
                raise NetworkError(417, "Expectation Failed")
        except NetworkError as e:
            raise e
        except Exception as e:
            raise NetworkError(417, "Expectation Failed")

    def process_request(self, request, addr):
        '''
        处理请求，并返回合适的应答
        '''
        try:
            headers = request['headers']
            cookie = headers.get('cookie', {})
            whole_path = request['path'].split('?', 1)
            path = self.url_decode(whole_path[0])
            
            if 'expect' in headers and headers['expect'] == '100-continue':
                try:
                    self.check_ok(request)
                    return self.error_response(100, "Continue")
                except NetworkError as e:
                    return self.error_response(e.code, e.msg)
            
            if len(whole_path) > 1:
                request['query'] = { i.split('=')[0]: i.split('=')[1] for i in whole_path[1].split('&') }
            else:
                request['query'] = {}
            local_path = os.path.normpath(os.path.join(self.root, path.lstrip('/')))
            
            if not local_path.startswith(self.root):
                return self.error_response(403, "Forbidden")
            
            if request['method'] == 'GET':
                if 'session' not in cookie or cookie['session'] not in self.sessions:
                    return self.unauthorized_response(request)
                return self.handle_get(local_path, request, addr)
            elif request['method'] == 'HEAD':
                return self.handle_head(local_path, request)
            elif request['method'] == 'POST':
                return self.handle_post(local_path, request, addr)
            else:
                return self.error_response(501, "Not Implemented")
        except Exception as e:
            self.logger.error(f"Processing error: {e}")
            return self.error_response(500, "Internal Server Error")

    def handle_get(self, path, request, addr):
        '''
        处理GET请求，返回合适的应答。
        '''
        try:
            return self.serve_file(path, request, addr=addr, include_body=True)
        except NetworkError as e:
            return self.error_response(e.code, e.msg)

    def handle_head(self, path, request):
        '''
        处理HEAD请求，并返回合适的应答
        '''
        try:
            return self.serve_file(path, request, include_body=False)
        except NetworkError as e:
            return self.error_response(e.code, e.msg)

    def handle_post(self, path, request, addr):
        '''
        处理POST请求，并返回合适的应答
        '''
        content_type = request['headers'].get('content-type', '')
        if 'multipart/form-data' in content_type:
            return self.handle_upload(path, request)
        else:
            return self.handle_form(path, request, addr)
    
    def handle_cgi(self, path, request, addr):
        '''
        处理CGI文件
        '''
        env = {}
        
        env['CONTENT_TYPE'] = request['headers'].get('content-type', '')
        env['CONTENT_LENGTH'] = str(len(request['body']))
        cookies = request['headers'].get('cookie', {})
        env['HTTP_COOKIE'] = "; ".join([f"{key}={cookies[key]}" for key in cookies])
        env['HTTP_USER_AGENT'] = request['headers'].get('user-agent', None)
        env['QUERY_STRING'] = "; ".join([f"{key}={request['query'][key]}" for key in request['query']])
        env['REMOTE_ADDR'] = addr[0]
        env['REQUEST_METHOD'] = request['method']
        env['SCRIPT_FILENAME'] = path
        env['SERVER_NAME'] = socket.gethostname()
        env['SERVER_SOFTWARE'] = 'python/KAIYUEYU_TIANYIWANG'
        try:
            
            result = subprocess.run(
                [sys.executable, path],
                capture_output=True,
                text=True,
                env=env,
                input=request['body'].decode()
            )
            
            output = result.stdout
            # 解析CGI输出
            parts = output.split('\n\n', 1)
            if len(parts) == 2:
                headers_text, body = parts
                headers = {}
                for k in headers_text.split('\n'):
                    kv = k.split(': ')
                    headers[kv[0]] = kv[1]
                response = headers, body.encode()
            else:
                response = {'Content-Type': 'text/html'}, output.encode()
                
        except Exception as e:
            self.logger.error(f"Processing error: {e}")
            response = None, str(e).encode()
        
        return response

    def serve_file(self, path, request, include_body, addr=None, intended_code=200, intended_msg="OK"):
        '''
        处理文件，将文件地址转换为合适的应答
        '''
        try:
            if not os.path.exists(path):
                raise NetworkError(404, "Not Found")
            
            stats = os.stat(path)
            etag = hashlib.md5(f"{path}-{stats.st_mtime_ns}".encode()).hexdigest()
            
            if 'if-none-match' in request['headers'] and request['headers']['if-none-match'] == etag:
                raise NetworkError(304, "Not Modified")
            
            headers = {
                'Connection': request['headers']['connection'] if 'connection' in request['headers'] else 'keep-alive',
                'Content-Type': self.get_mime_type(path),
                'Last-Modified': self.http_date(stats.st_mtime),
                'ETag': etag,
                'Cache-Control': "max-age=600", 
                "Expires": self.http_date(time.time()+600.0),
                'Server': 'KaiyueYu TianyiWang'
            }

            if not include_body:
                headers['Content-Length'] = 0
                return self.build_response(200, "OK", headers)
            
            if os.path.isdir(path):
                index_path = os.path.join(path, 'index.html')
                if not os.path.exists(index_path):
                    try:
                        content = self.list_directory(path).encode()
                    except NetworkError as e:
                        return self.error_response(e.code, e.msg)
                else:
                    path = index_path
            
            if path.endswith('.py'):
                cgi_headers, content = self.handle_cgi(path, request, addr)
                if cgi_headers is None:
                    raise NetworkError(500, f"Internal Server Error: {content}")
                for header in cgi_headers:
                    headers[header] = cgi_headers[header]
            elif not os.path.isdir(path):
                with open(path, 'rb') as f:
                    content = f.read()   

            if 'gzip' in request['headers'].get('accept-encoding', ''):
                headers['Content-Encoding'] = 'gzip'
                compressor = zlib.compressobj(wbits=31)
                compressed_content = compressor.compress(content)
                compressed_content += compressor.flush()
                content = compressed_content

            if len(content) > 1024*1024:

                headers['Transfer-Encoding'] = 'chunked'
                if 'Content-Length' in headers:
                    del headers['Content-Length'] 

                response_prefix, code = self.build_response(intended_code, intended_msg, headers)

                response_chunks = [response_prefix]
                
                index = 0
                chunk_size = 8192
                while True:
                    if index + chunk_size > len(content):
                        chunk = content[index:]
                        chunk_header = f"{len(chunk):X}\r\n".encode()
                        chunk_footer = b"\r\n"
                        response_chunks.append(chunk_header + chunk + chunk_footer)
                        break
                    else:
                        chunk = content[index:index+chunk_size]
                        chunk_header = f"{len(chunk):X}\r\n".encode()
                        chunk_footer = b"\r\n"
                        response_chunks.append(chunk_header + chunk + chunk_footer)
                    index += chunk_size
            
                response_chunks.append(b"0\r\n\r\n")
                    
                return b"".join(response_chunks), code
            else:
                if content is not None:
                    headers['Content-Length'] = str(len(content))
                response = self.build_response(intended_code, intended_msg, headers, content)
                return response
        except NetworkError as e:
            raise e
        except Exception as e:
            self.logger.error(e)
            raise NetworkError(500, f"Internal Server Error: {str(e)}")
        
    def create_session(self):
        '''
        生成独特session_id，用于进行登录验证
        '''
        session_id = hashlib.sha256(os.urandom(32)).hexdigest()
        self.sessions[session_id] = {'active': True}
        return session_id

    def add_cookie_header(self, response: bytes, session_id: str):
        '''
        添加set-cookie头，设置客户端cookie
        '''
        headers_end = response.find(b'\r\n\r\n')
        headers = response[:headers_end].decode()
        return (headers + f"\r\nSet-Cookie: session={session_id}; Path=/" + "\r\n\r\n").encode() + response[headers_end+4:]

    def build_response(self, code, reason, headers, body=b''):
        '''
        构造完整的响应
        '''
        response = [
            f"HTTP/1.1 {code} {reason}",
            f"Date: {self.http_date()}",
            f"Connection: {headers.get('Connection', 'keep-alive') if code == 200 else 'close'}"
        ]
        for k, v in headers.items():
            if k == 'Connection':
                continue
            response.append(f"{k}: {v}")
        response.append("\r\n")
        return "\r\n".join(response).encode() + body, code

    def error_response(self, code, message):
        '''
        构造非200且只包含错误信息的响应的方法
        '''
        return self.build_response(code, message, {
            'Content-Type': 'text/plain',
            'Content-Length': str(len(message))
        }, message.encode())
    
    def unauthorized_response(self, request):
        '''
        给未授权用户返回登录页面+401 Unauthorized的方法
        '''
        try:
            return self.serve_file(
                os.path.normpath(os.path.join(self.root, 'login.html'.lstrip('/'))), 
                request, include_body=True, 
                intended_code=401, intended_msg="Unauthorized"
            )
        except NetworkError as e:
            return self.error_response(401, "Unauthorized")

    def get_mime_type(self, path):
        '''
        根据路径返回合适的mimetype
        '''
        if os.path.isdir(path):
            return 'text/html'
        
        types = {
            'html': 'text/html',
            'css': 'text/css',
            'js': 'application/javascript',
            'png': 'image/png',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'gif': 'image/gif',
            'txt': 'text/plain'
        }
        ext = path.split('.')[-1].lower()
        return types.get(ext, 'application/octet-stream')

    def http_date(self, timestamp=None):
        '''
        将timestamp转换为合适的时间格式
        '''
        if timestamp is None:
            timestamp = time.time()
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')

    def url_decode(self, s):
        '''
        解析URL
        '''
        return urllib.parse.unquote(s)

    def list_directory(self, path):
        '''
        对于目录类地址，将其转换为一个列出当前目录所有文件的html
        '''
        try:
            entries = ['<li><a href="../">..</a></li>']
            for name in os.listdir(path):
                fullpath = os.path.join(path, name)
                entries.append(f'<li><a href="{name}{"/" if os.path.isdir(fullpath) else ""}">{name}</a></li>')

            content = f"<html><head><title>Directory listing</title></head><body><ul>{''.join(entries)}</ul></body></html>"
            return content
        except:
            raise NetworkError(403, "Forbidden")

    def handle_upload(self, path, request):
        '''
        处理文件上传
        '''
        boundary = request['headers']['content-type'].split('boundary=')[1]
        parts = self.parse_multipart(request['body'], boundary)
        
        for part in parts:
            if 'filename' in part and part['filename']:
                with open(os.path.join(self.root, part['filename']), 'wb') as f:
                    f.write(part['data'])
        
        return self.build_response(200, "OK", {
            'Content-Type': 'text/plain',
            'Content-Length': '13'
        }, b"File uploaded")

    def parse_multipart(self, data, boundary):
        '''
        解析文件上传类型的请求的数据
        '''
        parts = []
        boundary = boundary.encode()
        for part in data.split(b'--' + boundary)[1:-1]:
            headers, body = part.split(b'\r\n\r\n', 1)
            headers_dict = {}
            for line in headers.decode().split('\r\n'):
                if ': ' in line:
                    key, val = line.split(': ', 1)
                    headers_dict[key.lower()] = val
            
            if 'content-disposition' in headers_dict:
                params = {}
                for item in headers_dict['content-disposition'].split(';'):
                    item = item.strip()
                    if '=' in item:
                        k, v = item.split('=', 1)
                        params[k] = v.strip('"')
                parts.append({
                    'name': params.get('name'),
                    'filename': params.get('filename'),
                    'data': body.split(b'\r\n', 1)[0]
                })
        return parts

    def handle_form(self, path, request, addr):
        '''
        解析表单
        '''
        body = request['body'].decode()
        kvs = body.split('&')
        query = {}
        for kv in kvs:
            kv_split = kv.split('=')
            query[kv_split[0]] = kv_split[1]
        if 'email' in query and 'password' in query:
            if query['email'] == 'admin' and query['password'] == 'secret':
                session_id = self.create_session()
                expire_time = self.http_date(timestamp=time.time() + 1200.0)
                return self.build_response(200, "OK", {
                    'Content-Type': 'text/plain',
                    'Content-Length': '13',
                    'Set-Cookie': f'session={session_id}; expires={expire_time}; Path=/'
                }, b"Login success")
            else:
                return self.error_response(401, "Unauthorized")
        else:
            if path.endswith('py'):
                cgi_headers, content = self.handle_cgi(path, request, addr)
                if cgi_headers is None:
                    return self.error_response("500", "Internal Server Error")
                return self.build_response(200, "OK", cgi_headers, content)
            
            return self.build_response(200, "OK", {
                    'Content-Type': 'text/plain',
                    'Content-Length': '18'
                }, b"Post data received")

def set_server(ip, port, logger, ssl_cert=None, ssl_key=None):
    '''
    构建服务器
    '''
    server = WebServer(ip, port, logger, './www', ssl_cert=ssl_cert, ssl_key=ssl_key)
    return server

if __name__ == '__main__':

    # 构建logger类，进行日志的记录
    logger = logging.getLogger()
    logger.setLevel(level=logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
    
    # 文件日志输出
    file_handler = handlers.TimedRotatingFileHandler(filename='./www/server_log.log', when='D')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    # 控制台日志输出
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    
    # 构建http服务器和https服务器
    http_server = set_server('0.0.0.0', 80, logger)
    https_server = set_server('0.0.0.0', 443, logger, "./.ssh/localhost+2.pem", "./.ssh/localhost+2-key.pem")

    # 给两个服务器分别开一个线程
    http_thread = threading.Thread(target=http_server.start)
    https_thread = threading.Thread(target=https_server.start)
    http_thread.daemon = True
    https_thread.daemon = True
    try:
        http_thread.start()
        https_thread.start()
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        http_server.stop()
        https_server.stop()
        