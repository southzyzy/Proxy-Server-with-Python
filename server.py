import socket
import re
import threading
import socketserver

http_port = 80
BUFLEN = 8192


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = str(self.request.recv(BUFLEN), 'ascii')
        host = re.search("(Host:)\s(.+)", data)
        url = host.group(2)[:-1]

        if ':' in url:
            self.request.close()
        else:
            address = (url, http_port)
            # print("[*] Processing {}".format(address) + " request for client")
            self.connect(data, address)

    def connect(self, data, address):
        # create the socket connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(address)
        s.send(data.encode('utf-8'))

        response = b''
        while True:
            response += s.recv(BUFLEN)
            eol = response.endswith(bytes('\r\n\r\n', 'utf-8'))
            if eol:
                break

        s.close()
        print(response)
        self.request.sendall(response)


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
