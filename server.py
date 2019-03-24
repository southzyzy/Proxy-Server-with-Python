import socket
import select
import re
import sys
import threading
import socketserver

BUFLEN = 8192  # buffer length
__version__ = '0.1.0 Draft 1'  # specify version for http header
VERSION = 'Proxy/' + __version__  # specify the proxy version for the http header
TIMEOUT = 20  # set the request timeout


def url_validation(url):
    # regex to check if the url is valid or not
    url_valid = re.match("^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$", url)
    # return False if the url is not valid
    if not url_valid:
        return False
    # else return True
    return True


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # receive the client url request and add to buffer_data
        self.buffer_data = self.request.recv(BUFLEN)
        self.conn_method, self.protocol, self.host = self.data_handler(str(self.buffer_data, 'ascii'))

        if self.conn_method == 'CONNECT':
            try:
                self.connect(self.host)
                self.request.send(
                    bytes(self.protocol + ' 200 Connection established\n' + 'Proxy-agent: %s\n\n' % VERSION, 'utf-8'))
                print("[*] Request for HTTPS: %s Done" % self.host)
                self.buffer_data = b''
                self.view_page()
            except:
                pass

        elif self.conn_method in ['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE']:
            try:
                self.connect(self.host)
                self.client_sock.send(self.buffer_data)
                print("[*] Request for HTTP: %s Done" % self.host)
                self.buffer_data = b''
                self.view_page()
            except:
                pass

        self.request.close()

    def data_handler(self, data):
        data_split = data.split()
        conn_method = data_split[0]
        protocol = data_split[2]
        host = data_split[4]

        if url_validation(host) is False:
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

    def view_page(self):
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
                        try:
                            out.send(data)
                            time_counter = 0
                        except:
                            pass

            if time_counter == TIMEOUT:
                break


# To build asynchronous handlers, use the ThreadingMixIn and ForkingMixIn classes.
class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = "localhost", int(sys.argv[1])
    print("[*] Listening on Port number %d" % PORT)
    print("[*] Initialising Server with MultiThread")

    # start the tcp server
    server = TCPServer((HOST, PORT), TCPHandler)
    # start the thread module to thread the server
    server_thread = threading.Thread(target=server.serve_forever)
    # start the thread
    server_thread.start()

    print("[*] Server Bind and waiting for connection ...")
