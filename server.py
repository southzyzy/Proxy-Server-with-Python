import socket, select, re
import threading
import socketserver

BUFLEN = 8192
__version__ = '0.1.0 Draft 1'
VERSION = 'Proxy/' + __version__
TIMEOUT = 20


def url_validation(url):
    url_valid = re.match("^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$", url)
    if not url_valid:
        return False

    return True


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.buffer_data = self.request.recv(BUFLEN)
        self.conn_method, self.protocol, self.host = self.data_handler(str(self.buffer_data, 'ascii'))

        if self.conn_method == 'CONNECT':
            self.connect(self.host)
            self.request.send(bytes(self.protocol + ' 200 Connection established\n' + 'Proxy-agent: %s\n\n' % VERSION, 'utf-8'))
            self.buffer_data = b''
            self.send()

        elif self.conn_method in ['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE']:
            self.connect(self.host)
            self.client_sock.send(self.buffer_data)

            self.buffer_data = b''
            self.send()

        self.request.close()

    def data_handler(self, data):
        data_split = data.split()
        conn_method = data_split[0]

        protocol = data_split[2]

        host = data_split[4]
        if url_validation(host) == False:
            self.request.close()

        return (conn_method, protocol, host)

    def connect(self, host):
        host_port = re.search("(.*):(\d+)", host)
        if host_port:
            host = host_port.group(1)
            port_no = int(host_port.group(2))
        else:
            port_no = 80

        # Get the address information
        address = (host, port_no)

        try:
            # create the socket connection
            self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_sock.connect(address)
        except:
            pass

    def send(self):
        socs = [self.request, self.client_sock]
        time_counter = 0
        while True:
            time_counter += 1
            (recv, _, error) = select.select(socs, [], socs, 3)
            if error:
                break
            if recv:
                for in_ in recv:
                    data = in_.recv(BUFLEN)
                    if in_ is self.request:
                        out = self.client_sock
                    else:
                        out = self.request
                    if data:
                        out.send(data)
                        time_counter = 0

            if time_counter == TIMEOUT:
                break


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    # Port 0 means to select an arbitrary unused port
    HOST, PORT = "localhost", 7
    print("[*] Listening on Port number %d" % PORT)
    print("[*] Initialising Server with MultiThread")

    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()

    print("[*] Server Bind and waiting for connection ...")
