import os
import socket
from EEE466Baseline.CommunicationInterface import CommunicationInterface
from nacl.public import PrivateKey, PublicKey, Box


class SecureTCPFileTransfer(CommunicationInterface):
    """
    This class inherits and implements the CommunicationInterface. It enables
    file transfers between client and server using an encrypted TCP channel.
    """
    def __init__(self):
        """
        This method is used to initialize your Communication Interface object.
        """
        pass

    # Some example methods for key exchange.
    def send_public_key(self, msg):
        pass
    def receive_public_key(self):
        pass
