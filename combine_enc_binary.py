#-----------------------------------------------------------------------------------
# MIT License

# Copyright (c) 2024 Takumi Asada

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#-----------------------------------------------------------------------------------

#-----------------------------------------------------------------------------------#
# ----------------------------------- Import  --------------------------------------#
#-----------------------------------------------------------------------------------#
import os
import zlib
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


#-----------------------------------------------------------------------------------#
# ----------------------------------- Class  ---------------------------------------#
#-----------------------------------------------------------------------------------#
class BinaryProcessor:
    def __init__(self, binary_paths, output_path, output_folder='output', max_bin_size_kb=900):
        self.binary_paths = binary_paths
        self.output_path = output_path
        self.max_bin_size_kb = max_bin_size_kb
        self.private_key = None
        self.public_key = None
        self.signature_file = os.path.join(output_folder, "signature.bin")
        self.public_key_file = os.path.join(output_folder, "public_key.pem")
        self.private_key_file = os.path.join(output_folder, "private_key.pem")
        self.encrypted_file = os.path.join(output_folder, "enc_binary.binx")
        self.output_folder = output_folder

        # Ensure the output folder exists
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)

#-- Function Name: format_size -- #
    def format_size(self, size):
        """
        Formats the file size in bytes to kilobytes (KB) with two decimal places.

        Parameters:
        size (int): The size of the file in bytes.

        Returns:
        str: The formatted size as a string in KB.
        """
        kb_size = size / 1024
        return f"{kb_size:.2f} KB"

#-- Function Name: get_binary_sizes -- #
    def get_binary_sizes(self):
        """
        Retrieves and prints the size of each binary file.

        Returns:
        dict: A dictionary with binary file paths as keys and their sizes (in bytes) as values.
        """
        sizes = {}
        for binary_path in self.binary_paths:
            binary_size = os.path.getsize(binary_path)
            sizes[binary_path] = binary_size
            print(f"Binary size of {binary_path}:", self.format_size(binary_size))
        return sizes

#-- Function Name: combine_binaries -- #
    def combine_binaries(self, padding_byte=b'\x00'):
        """
        Combines multiple binary files, adds padding if necessary, and writes the result to a single output file.

        Parameters:
        padding_byte (bytes): The byte value used for padding if the binary data is smaller than the specified size. Default is b'\x00'.

        Returns:
        str: The path to the output file where the combined binary data is saved.
        """
        combined_data = b''
        total_size = 0

        for binary_path in self.binary_paths:
            with open(binary_path, 'rb') as binary_file:
                binary_data = binary_file.read()

                if len(binary_data) < self.max_bin_size_kb * 1024:
                    padding_size = (self.max_bin_size_kb * 1024) - len(binary_data)
                    binary_data += padding_byte * padding_size

                combined_data += binary_data
                total_size += len(binary_data)

        with open(self.output_path, 'wb') as output_file:
            output_file.write(combined_data)

        print("Total Binary size:", self.format_size(total_size))
        return self.output_path

#-- Function Name: generate_key_pair -- #
    def generate_key_pair(self):
        """
        Generates an RSA key pair and saves the private and public keys if they do not already exist.

        If the keys already exist, they are loaded from the files.

        Returns:
        None
        """
        if os.path.exists(self.private_key_file) and os.path.exists(self.public_key_file):
            with open(self.private_key_file, 'rb') as private_file:
                self.private_key = private_file.read()
            with open(self.public_key_file, 'rb') as public_file:
                self.public_key = public_file.read()
            print("Existing keys found and loaded.")
        else:
            key = RSA.generate(2048)
            self.private_key = key.export_key()
            self.public_key = key.publickey().export_key()
            self.write_file(self.public_key_file, self.public_key)
            self.write_file(self.private_key_file, self.private_key)
            print("New key pair generated.")

#-- Function Name: sign_data -- #
    def sign_data(self, data):
        """
        Signs the data using the private RSA key and saves the signature to a file.

        Parameters:
        data (bytes): The data to be signed.

        Returns:
        bytes: The signature generated by signing the data.
        """
        if os.path.exists(self.signature_file):
            print("Signature file already exists. Skipping signature generation.")
            with open(self.signature_file, 'rb') as sig_file:
                return sig_file.read()
        else:
            if self.private_key is None:
                raise ValueError("Private key is not set.")
            key = RSA.import_key(self.private_key)
            h = SHA256.new(data)
            signer = PKCS1_v1_5.new(key)
            signature = signer.sign(h)
            self.write_file(self.signature_file, signature)
            return signature

#-- Function Name: encrypt_data -- #
    def encrypt_data(self, data):
        """
        Encrypts the data using the public RSA key with OAEP padding.

        Parameters:
        data (bytes): The data to be encrypted.

        Returns:
        bytes: The encrypted data.
        """
        if self.public_key is None:
            raise ValueError("Public key is not set.")
        key = RSA.import_key(self.public_key)
        cipher = PKCS1_OAEP.new(key)

        max_chunk_size = (key.size_in_bytes() - 42)  # 42 bytes for padding
        encrypted_data = b''

        for i in range(0, len(data), max_chunk_size):
            chunk = data[i:i + max_chunk_size]
            encrypted_data += cipher.encrypt(chunk)

        return encrypted_data

#-- Function Name: write_file -- #
    def write_file(self, file_path, data):
        """
        Writes data to a specified file path.

        Parameters:
        file_path (str): The path to the file where data will be written.
        data (bytes): The data to be written.

        Returns:
        None
        """
        with open(file_path, 'wb') as file:
            file.write(data)

#-- Function Name: process -- #
    def process(self):
        """
        Processes the binary files by getting their sizes, combining them, generating an RSA key pair, 
        signing the combined binary, and encrypting the signed data.

        Returns:
        None
        """
        # Get sizes and combine binaries
        self.get_binary_sizes()
        self.combine_binaries()

        # Generate RSA key pair
        self.generate_key_pair()

        # Read combined binary file
        with open(self.output_path, 'rb') as file:
            data = file.read()

        # Sign the data
        signature = self.sign_data(data)

        # Encrypt the compressed data
        encrypted_data = self.encrypt_data(data)
        self.write_file(self.encrypted_file, encrypted_data)

#-- Function Name: find_binary_files -- #
def find_binary_files(directory, filenames):
    """
    Finds the binary files in a specified directory.

    Parameters:
    directory (str): The directory to search for binary files.
    filenames (list): A list of filenames to look for in the directory.

    Returns:
    list: A list of paths to the found binary files.
    """
    binary_paths = []
    for filename in filenames:
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
            binary_paths.append(file_path)
    return binary_paths


#-----------------------------------------------------------------------------------#
# ----------------------------------- main  --------------------------------------- #
#-----------------------------------------------------------------------------------#
if __name__ == "__main__":
    current_dir = os.getcwd()
    binary_folder = os.path.join(current_dir, 'binary')

    filenames = ['float32_pub', 'twiststamped_pub', 'string_pub', 'range_pub', 'rviz2']

    binary_paths = find_binary_files(binary_folder, filenames)

    if not binary_paths:
        print("No valid files found in the binary folder.")
    else:
        output_path = os.path.join('output', 'output_binary.bin')
        processor = BinaryProcessor(binary_paths, output_path)
        processor.process()
