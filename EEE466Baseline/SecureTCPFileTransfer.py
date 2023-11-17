
import math
import os
import socket
from EEE466Baseline.CommunicationInterface import CommunicationInterface

from constants_file import DeviceTypes

# To use utils
import nacl.utils as utils

# For asym encryption
import nacl.public as asym

# For syn encryption
import nacl.secret as sym

"""

    NOTES:
    
        1. 
        
    Status:
    
        1. Integrate the encryption in the send and receive functions. 
"""


class SecureTCPFileTransfer(CommunicationInterface):
    """
    This class inherits and implements the CommunicationInterface. It enables
    file transfers between client and server using an encrypted TCP channel.
    """

    def __init__(self):
        """
        This method is used to initialize your Communication Interface object. Class variables are defined here.

        NOTE: class objects default to Device Type SECTCPCLIENT upon initialization.

        Class Attributes:
            <device_type> : Tracks what device the instantiated communication object is acting as (ie. client, server).
                DEFAULTED TO DeviceTypes.SECTCPCLIENT UPON INSTANTIATION.
            <initial_socket : socket> : Attribute used by both server and client.
                A client uses it to connect to the server and for all its data transmission purposes.
                A server uses it only once when first creating the socket object. Once a connection is received,
                server objects then uses the socket object (returned by socket.accept()) stored in self.server_socket.
            <server_socket : socket> : Attribute only used by server - stores the returned socket object
                by socket.accept() which the server uses for data transmission.
            <client_addr : tuple> : Attribute only used by server - stores the TCP address of the client
                device connected to the server.
            <server_addr : tuple> : Attribute used by both server and client - stores the TCP address of the server
            todo: add the key attributes
        """

        self.device_type = DeviceTypes.SECTCPCLIENT;  # Setting the device type - default to Sec TCP client
        self.initial_socket = None;
        self.server_socket = None;
        self.client_addr = None;
        self.server_addr = None;

        #todo note:
        #   We are supposed to use the assymetric box first to send over the shit needed to establish a secret box

        # Attributes needed to establish the asymmetric box between client and server
        self.private_key = None;
        self.public_key = None;
        self.asym_box = None;

        # Attributes needed to establish the symmetric box between client and server (using asym_box)
        self.sym_key = None;
        self.sym_box = None;


    # Some example methods for key exchange.
    def send_public_key(self, msg):
        pass


    def receive_public_key(self):
        pass

    def initialize_server(self, source_port):
        """
        Performs any necessary communication setup for the server. Creates a socket and binds it to a port. The server
        listens for all IP addresses (e.g., "0.0.0.0").

        NOTE: Switches the object's device type to DeviceTypes.SECTCPSERVER.

        :param source_port: port that provides a service.
        """

        # Change the device type to TCP server
        self.device_type = DeviceTypes.SECTCPSERVER;

        # Set self.server_addr as a tuple
        self.server_addr = ('localhost', source_port);

        # Generate the server's public and private key
        self.private_key = asym.PrivateKey.generate();
        self.public_key = self.private_key.public_key;

        # Generate the symmetric key on the server side and the symmetric box
        # for any tcp conversations (since assume server has valid cert)
        self.sym_key = utils.random(sym.SecretBox.KEY_SIZE);
        self.sym_box = sym.SecretBox(self.sym_key);

        # Call socket(), bind(), and listen() methods for server TCP connections
        self.initial_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
        self.initial_socket.bind(self.server_addr);
        self.initial_socket.listen(0);  # <-- Unlimited retries for connection

        # Print statement for status
        print(f"{self.device_type} COMM STATUS: Server bounded and listening on port {self.server_addr[1]}...")

    def establish_server_connection(self):
        """
        Accepts incoming connections for the server socket. Not implemented for connectionless protocols.

        The active connection is used to perform send and receive function calls. There should never be more than one
        active connection. If the CommunicationInterface does not have an established connection this method should
        establish one. If there is an existing, established connection this call should close it and create a new one.
        """

        # If calling device is not a server, stop function.
        if self.device_type != DeviceTypes.SECTCPSERVER:
            self.error(f"Current device is not a server - can't establish a server connection.")
            return;

        # Call accept() method, wait for a client to connect, and save new connection socket in self.server_socket
        self.server_socket, self.client_addr = self.initial_socket.accept();

        # Print status
        print(f"{self.device_type} COMM STATUS: Server received BROWN connection from client at {self.client_addr}.");

        # Get secret box for server to conduct encrypted communications
        self.get_sym_box();

    def initialize_client(self, address, destination_port):
        """
        Performs any necessary communication setup for the server. Creates a socket and attempts to connect to the
        server.

        :param address: the address you wish to connect to. (e.g., "localhost","127.0.0.1")
        :param destination_port: the port you want the client to connect to.
        """

        # Stop calling of function if detected not a client
        if self.device_type != DeviceTypes.SECTCPCLIENT:
            print(f"ERROR: Can't establish a client connection with device type {self.device_type}.");
            return;

        # Set server address attribute
        self.server_addr = (address, destination_port);

        # Generate the client's public and private key
        self.private_key = asym.PrivateKey.generate();
        self.public_key = self.private_key.public_key;

        # Create TCP client socket, connect the client to the address and port passed through params
        self.initial_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
        self.initial_socket.connect(self.server_addr);

        # Print status
        print(f"{self.device_type} COMM STATUS: successfully connected to server at {self.server_addr}.")

        # Get the secret box for client to conduct encrypted message sending and receiving
        self.get_sym_box();


    def get_sym_box(self):
        """ Method conducts all asymmetric transactions for the calling device to establish a symmetric box
        with the other device in the TCP connection.

        Args:
            <device_type : DevicesTypes> : The type of the device calling this function.
        Returns:
            The symmetric box object.
        """

        # Encode public key
        pub_encoded = self.public_key.encode();

        # Actions if current device is the client
        if self.device_type == DeviceTypes.SECTCPCLIENT:

            # Send the public key to client
            self.slice_and_send(self.initial_socket, pub_encoded);
            print(f"{self.device_type} COMM STATUS: Sent public key to server.");

            # Receive key from client
            server_pub_key = asym.PublicKey(self.recv_and_parse(self.initial_socket));
            print(f"{self.device_type} COMM STATUS: Received public key from server.");

            # Create asym box
            self.asym_box = asym.Box(self.private_key, server_pub_key);
            print(f"{self.device_type} COMM STATUS: Asymmetric box created.");

            # Receive the symmetric key (already in bytes) from server and create symmetric box
            self.sym_key = self.asym_box.decrypt(self.recv_and_parse(self.initial_socket));
            self.sym_box = sym.SecretBox(self.sym_key);
            print(f"{self.device_type} COMM STATUS: Created symmetric box on client side.");


        # Actions if current device is server
        elif self.device_type == DeviceTypes.SECTCPSERVER:

            # Receive key from server
            client_pub_key = asym.PublicKey(self.recv_and_parse(self.server_socket));
            print(f"{self.device_type} COMM STATUS: Received public key from client.");

            # Send public key to server
            self.slice_and_send(self.server_socket, pub_encoded);
            print(f"{self.device_type} COMM STATUS: Sent public key to client.");

            # Create asym box
            self.asym_box = asym.Box(self.private_key, client_pub_key);

            # Send generated symmetric key (already in bytes) to client through asym box
            send_sym_key = self.asym_box.encrypt(self.sym_key);
            self.slice_and_send(self.server_socket, send_sym_key);
            print(f"{self.device_type} COMM STATUS: Sent symmetric key to client.");


    def send_file(self, file_path):
        """
        Transfers a file from the local directory to the "remote" directory. Can be used by either client (i.e., in a
        put request), or by the server when receiving a get request.

        This method will need to read the file from the sender's folder and transmit it over the connection. If the
        file is larger than 1028 bytes, it will need to be broken into multiple buffer reads.

        :param file_path: the location of the file to send. E.g., ".\Client\Send\\ploadMe.txt".
        """

        # Print statement for status
        path_separated = file_path.split('\\');
        file_name = path_separated[-1];
        print(
            f"\n{self.device_type} COMM STATUS: Sending file <{file_name}> in directory [{file_path[:-len(file_name)]}] "
            f"to other device...")

        # Determine the socket to use to send, depending on the type of sending device (Default to client)
        sending_socket = self.initial_socket;
        if self.device_type == DeviceTypes.SECTCPSERVER:
            sending_socket = self.server_socket;

        # Check if the TCP connection still exists, and that the sender and receiver
        # agree in terms of the format of the transmitted data. If not, stop function
        if self.verify_sender(sending_socket, b'FILE ACK'):
            return;

        # Open 'utf-8' file to read with with(), specifying the encoding [ref Notes 3]...
        with open(file_path, encoding='utf-8') as open_file:

            # Read the file contents into bytes (.read() returns a string, we convert to bytes)
            file_data = bytes(open_file.read(), 'utf-8');

            # Send the data
            self.slice_and_send(sending_socket, file_data);

        # Print status
        print(f"{self.device_type} COMM STATUS: File <{file_name}> finished sending.")

    def receive_file(self, file_path):
        """
        Receives a filename and data over the communication channel to be saved in the local directory. Can be used by
        the client or the server.

        This method has a maximum buffer size of 1028 bytes. Multiple reads from the channel are required for larger
        files. This method writes the data it receives to the client or server "Receive" directory. Note: the filename
        must be sent over the wire and cannot be hard-coded.

        :param file_path: this is the destination where you wish to save the file. E.g.,
        ".\Server\Receive\\ploadMe.txt".
        """

        # Printing the status
        path_separated = file_path.split('\\');
        file_name = path_separated[-1];
        print(f"\n{self.device_type} COMM STATUS: Receiving file and placing it in directory "
              f"[{file_path[:-len(file_name)]}] under name <{file_name}>.")

        # Determine the socket to receive data from, depending on device type (default to client)
        receiving_socket = self.initial_socket;
        if self.device_type == DeviceTypes.SECTCPSERVER:
            receiving_socket = self.server_socket;

        # Check if the TCP connection still exists, and that the sender and receiver
        # agree in terms of the format of the transmitted data. If not, stop function
        if self.verify_receiver(receiving_socket, b'FILE ACK'):
            return;

        # Open the file to write the received file info. If none exists, create one at path file_path
        with open(file_path, 'w', encoding='utf-8') as open_file:

            # Receiving the data from the sender
            recv_data = self.recv_and_parse(receiving_socket).decode();

            # Write received data to the file (wow python makes this easy)
            open_file.write(recv_data);

        print(f"{self.device_type} COMM STATUS: File <{file_name}> fully received.")

    def send_command(self, command):
        """
        Sends a command from the client to the server. At a minimum this includes GET, PUT, QUIT and their parameters.

        This method may also be used to have the server return information, i.e., ACK, ERROR. This method can be used to
        inform the client or server of the filename ahead of sending the data.

        :param command: The command you wish to send to the server.
        """

        # Determine the socket to use to send, depending on the type of sending device (default to client)
        sending_socket = self.initial_socket;
        if self.device_type == DeviceTypes.SECTCPSERVER:
            sending_socket = self.server_socket;

        # Check if the TCP connection still exists, and that the sender and receiver
        # agree in terms of the format of the transmitted data. If not, stop function
        if self.verify_sender(sending_socket, b'COMM ACK'):
            return;

        # Convert msg into utf-8 bytes
        send_data = bytes(command, 'utf-8');

        # Send message to the client (slice up into 1028 byte msgs if needed)
        self.slice_and_send(sending_socket, send_data);

    def receive_command(self):
        """
        This method should be called by the server to await a command from the client. It can also be used by the
        client to receive information such as an ACK or ERROR message.

        :return: the command received and any parameters.
        """

        # Determine the socket to receive from, depending on the type of current receiving device (default to client)
        receiving_socket = self.initial_socket;
        if self.device_type == DeviceTypes.SECTCPSERVER:
            receiving_socket = self.server_socket;

        # Check if the TCP connection still exists, and that the sender and receiver
        # agree in terms of the format of the transmitted data. If not, stop function
        if self.verify_receiver(receiving_socket, b'COMM ACK'):
            return;

        # Receive the data bytes from the server
        recv_msg = self.recv_and_parse(receiving_socket);

        # Decode and return received command
        return recv_msg.decode();

    def close_connection(self):
        """
        If an unrecoverable error occurs or a QUIT command is called the server and client and tear down the
        connection.
        """

        print(f"\n{self.device_type} COMM STATUS: Shutting down connection... ", end='');
        if self.device_type == DeviceTypes.SECTCPSERVER:
            self.server_socket.close();
        elif self.device_type == DeviceTypes.SECTCPCLIENT:
            self.initial_socket.close();
        print("Successfully shutdown.");

        # Resetting the socket attributes (covers both cases of client and server)
        self.initial_socket = None;
        self.server_socket = None;

    def error(self, error_msg):
        """
        OPTIONAL error method can be used to display an error to the client or server, or can be used to send
        an error message across an open connection if something fails.

        :param error_msg: The error message you would like to display.
        """

        print(f">>> {self.device_type} COMMS ERROR: {error_msg} <<<")  # , file = stderr

    # --------- Making my own Non-API functions --------

    def slice_and_send(self, in_socket, in_data):
        """ Refer to Notes 1.
        Function slices up message in 1028 byte groupings as needed. The sending device then sends
        the separate messages in order to the device on the other side of the TCP connection.

        Args:
             <in_socket : socket > : A TCP socket object through which the message is to be sent.
             <in_data : bytes> : The data which is to be sent to the other device in the TCP connection.
             Returns: nothing
        """

        # Find how many slices of 1028 bytes we are sending
        bytes_len = len(in_data);
        slice_num = math.ceil(bytes_len / 1028)

        # Send the slice number (made possible by converting to string, then bytes)
        in_socket.send(bytes(str(slice_num), 'utf-8'));

        # Wait for acknowledgement first before proceeding (refer Notes 2)
        if in_socket.recv(3) == b'ACK': pass;

        # Send the slices of the bytes next
        for i in range(slice_num):

            # Check if sending last slice
            if i == slice_num - 1:

                # possibility of exceeding in_data's indices, so sending
                # last slice like this for good practice
                start_ind = i * 1028;
                slice_bytes = in_data[start_ind:];

            # Otherwise, compute start and end indices for data slices
            else:

                start_ind = i * 1028;
                end_ind = (i + 1) * 1028;
                slice_bytes = in_data[start_ind: end_ind]

            # Send the slice of bytes (sounds like a delicious dish lol)
            in_socket.send(slice_bytes);

    def recv_and_parse(self, in_socket):
        """ Refer to Notes 1.
        Function receives data slices of max size 1028 bytes from sender, and reconstructs
        the original message accordingly.

        Args:
            <in_socket : socket> : A TCP socket object to receive the data through
            Returns: The reconstructed stream of bytes received in slices from the sender.
        """

        # Creating dummy var to contain total received data
        recv_data = b'';

        # Receive the number of slices from sender (receive as bytes, convert to str, then int).
        # Shouldn't be more than 5 bytes lol
        slice_num = int(in_socket.recv(5).decode())

        # Send acknowledgement that number received (refer to Notes 2)
        in_socket.send(b'ACK');

        # Next, call recv() slice_num number of times and receive the
        # slices and reconstruct bytes through concatenation
        for i in range(slice_num):
            recv_data += in_socket.recv(1028);

        return recv_data;

    def verify_sender(self, sending_socket, ack_format):
        """ Refer to Notes 4.
        Function verifies if the sending machine has a valid connection working. Next,
        verifies if the receiving machine is expecting the same data format that is to be sent.

        If any condition violated, error is thrown and function returns true.

        Args:
            <sending_socket : socket> : The socket to send data through
            <ack_msg : bytes> : The ack message that is to be expected from the receiver to check format agreement.
            returns: returns 1 if an error is detected. Otherwise, returns 0.
        """

        # First check if connection exists
        if sending_socket is None:
            self.error("Unable to send data since no connection exists.");
            return 1;

        # Second, send the <ack_format> to the receiving device and wait for an
        # acknowledgement that the data format that will be sent is what they expect to receive
        sending_socket.send(ack_format);
        if sending_socket.recv(10) != b'ACK':
            self.error(f"No data sent - receiving device expecting to receive different data format. "
                       f"Check data format being sent. This ack_format = {ack_format}");
            return 1;

    def verify_receiver(self, receiving_socket, ack_format):
        """ Refer to Notes 4.
        Function verifies if the receiving machine has a valid connection working. Next,
        verifies if the sending machine is sending the same data that this machine is receiving.

        If any condition violated, error is thrown and function returns true.

        Args:
            <receiving_socket : socket> : The socket to receive data through
            <ack_msg : bytes> : The ack message the receiver will send to the sender to check format agreement.
            returns: returns 1 if an error is detected. Otherwise, returns 0.
            """

        # First check if connection exists
        if receiving_socket is None:
            self.error("Unable to send data since no connection exists.");
            return 1;

        # Second, ensure we are receiving the expected ack_format msg from the sender.
        # Send ACK back if correct. If anything else received, throw error and close connection.
        if receiving_socket.recv(10) == ack_format:
            receiving_socket.send(b'ACK');
        else:
            receiving_socket.send(b'ERROR');
            self.error(f"No data received - sender is detected sending data in an unexpected format. "
                       f"Verify data format expect to receive. This ack_format = {ack_format}")
            return 1;


