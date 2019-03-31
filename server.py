"""
School of Infocomm Technology
Information and Communications Technology (Information Security), BEng (Hons)

ICT-1010 Computer Networks Assignment 2 - Socket Programming

Authors: Tan Zhao Yea (1802992) && Stanley Cheong (1802986)
Class: P2
Lab Group - P5
Academic Year 2018 - 2019
Lecturer: Dr. Woo Wing Keong

Submission Date: 5th April 2019
"""

import socket
import select
import re
import sys
import threading
import socketserver

BUFLEN = 8192  # buffer length
TIMEOUT = 20  # set the request timeout

"""
Function that check if the host request by the client is a valid url. 
"""


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
        try:
            # receive the client url request and add to buffer_data
            self.buffer_data = self.request.recv(BUFLEN)

            # retrieve the connection method, protocol, and the host the client is requesting
            self.conn_method, self.protocol, self.host = self.data_handler(str(self.buffer_data, 'ascii'))

            # CONNECT header is the HTTPS request
            if self.conn_method == 'CONNECT':
                self.connect(self.host)  # create the socket connection to the host
                # construct the HTTP header and send it back to the client
                self.request.send(
                    bytes(self.protocol + ' 200 Connection established\r\n\r\n', 'utf-8'))
                print("[*] Request for HTTPS: %s --- Done" % self.host)
                self.buffer_data = b''  # reset the buffer data to empty bytes
                self.view_page()  # wait for client reply and then send the next http to view the web page


            # Get the other connection method like the HTTP
            elif self.conn_method in ['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE']:
                self.connect(self.host)  # create the socket connection to the host
                self.client_sock.send(self.buffer_data)  # send the buffer data to the client
                print("[*] Request for HTTP: %s --- Done" % self.host)
                self.buffer_data = b''  # reset the buffer data to empty bytes
                self.view_page()  # wait for client reply and then send the next http to view the web page

        except:
            pass

        self.request.close()  # close the request handler

    """
    Function that split and handlers the data to return its host, protocol and connection method
    """

    def data_handler(self, data):
        data_split = data.split()  # split the buffer_data
        if data_split:
            conn_method = data_split[0]  # retrieve the connection method
            protocol = data_split[2]  # retrieve the protocol (HTTP / HTTPS)
            host = data_split[4]  # retrieve the server and port the client is requesting

            if url_validation(host) is False:  # check to see if the host is valid or not
                self.request.close()  # close the connection if the host is not valid

            # return the connection method, protocol and host in form of tuple
            return (conn_method, protocol, host)
        else:
            self.request.close()

    """
    Function that create the socket connection with the client to send data over from the proxy server to the client server
    """

    def connect(self, host):
        host_port = re.search("(.*):(\d+)", host)  # regex to search for its host and its port
        if host_port:
            host = host_port.group(1)  # retrieve the host
            port_no = int(host_port.group(2))  # retrieve the port no
        else:
            port_no = 80  # default HTTP port. Assign it as the default port number if request is HTTP

        address = (host, port_no)  # Construct the address in form of tuple

        try:
            # create the socket connection
            self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_sock.connect(address)  # connect to the host server
        except:
            pass

    """
    Function that handles the server reply and sending the buffer_data to the client to view the requested webpage
    Using of the select function to filter out:
    1. Recv -- buffer data from the server reply
    2. _ -- empty set
    3. error -- error msg if socket have an error
    
    * Select *
    Read More: https://pymotw.com/2/select/
    """

    def view_page(self):
        socks = [self.request, self.client_sock]  # create the sockets list, client and server
        request_timeout = 0  # initialise the timer counter
        while True:
            request_timeout += 1  # start the timeout counter
            (recv, _, error) = select.select(socks, [], socks)  # retrieve the server reply, and error if any

            if error:  # break if an error occur during the trasmission
                break
            if recv:  # if the server reply back
                for buffer in recv:  # loop through every reply by the server
                    data = buffer.recv(BUFLEN)  # handle the server reply and initialise to the variable data
                    # set the target to send to based on the buffer stated
                    if buffer is self.request:
                        target = self.client_sock
                    else:
                        target = self.request
                    if data:
                        try:
                            target.send(data)  # send the buffer data to the target
                            request_timeout = 0  # reset the counter
                        except:
                            pass
            else:
                break

            if request_timeout == TIMEOUT:  # request timeout if the request is too long, break the connection
                break


# To build asynchronous handlers, use the ThreadingMixIn and ForkingMixIn classes.
class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = "localhost", int(sys.argv[1])  # get the user input
    print("[*] Listening on Port number %d" % PORT)
    print("[*] Initialising Server with MultiThread")

    # start the tcp server
    server = TCPServer((HOST, PORT), TCPHandler)
    # start the thread module to thread the server
    server_thread = threading.Thread(target=server.serve_forever)
    # start the thread
    server_thread.start()

    print("[*] Server Bind and waiting for connection ...")