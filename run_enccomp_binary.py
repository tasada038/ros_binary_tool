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
import subprocess
from concurrent.futures import ThreadPoolExecutor
import zlib
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from tempfile import NamedTemporaryFile

from logger_component import ColoredLogger


#-----------------------------------------------------------------------------------#
# ----------------------------------- Class  -------------------------------------- #
#-----------------------------------------------------------------------------------#
class BinaryProcessor:
    def __init__(self, output_folder='output', chunk_size_kb=900):
        self.output_folder = output_folder
        self.chunk_size_kb = chunk_size_kb

        # Define file paths
        self.encrypted_file = os.path.join(output_folder, "enccomp_binary.binx")
        self.signature_file = os.path.join(output_folder, "signature.bin")
        self.public_key_file = os.path.join(output_folder, "public_key.pem")
        self.private_key_file = os.path.join(output_folder, "private_key.pem")

        self.public_key = None
        self.private_key = None

        colored_logger = ColoredLogger(__name__)
        self.logger = colored_logger.get_logger()

    def read_file(self, file_path):
        with open(file_path, 'rb') as file:
            return file.read()

    def decompress_data(self, compressed_data):
        try:
            decompressed_data = zlib.decompress(compressed_data)
            self.logger.info("Decompression successful")
            return decompressed_data
        except zlib.error as e:
            self.logger.error(f"Decompression error: {e}")
            return b''

    def decrypt_data(self, encrypted_data, private_key):
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        max_chunk_size = key.size_in_bytes()
        decrypted_data = b''

        try:
            for i in range(0, len(encrypted_data), max_chunk_size):
                chunk = encrypted_data[i:i + max_chunk_size]
                decrypted_data += cipher.decrypt(chunk)

            self.logger.info("Decryption successful")
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise  # Re-raise the exception to handle it in the calling method

        return decrypted_data

    def verify_signature(self, data):
        if self.public_key is None:
            raise ValueError("Public key is not set.")
        key = RSA.import_key(self.public_key)
        h = SHA256.new(data)
        with open(self.signature_file, 'rb') as sig_file:
            signature = sig_file.read()
        verifier = PKCS1_v1_5.new(key)
        try:
            # Perform the verification
            if verifier.verify(h, signature):
                self.logger.info("Signature verified successfully.")
            else:
                self.logger.error("Signature verification failed: Signature does not match.")
                raise ValueError("Signature verification failed: Signature does not match.")

        except (ValueError, TypeError) as e:
            self.logger.error(f"Signature verification failed: {e}")
            raise

    def split_binary_data(self, data, chunk_size_kb):
        chunk_size_bytes = chunk_size_kb * 1024
        chunks = [data[i:i + chunk_size_bytes] for i in range(0, len(data), chunk_size_bytes)]
        return chunks

    def execute_chunk(self, chunk_data):
        with NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(chunk_data)
            temp_file.flush()
            temp_file_name = temp_file.name

        os.chmod(temp_file_name, 0o755)  # Set execute permission
        try:
            subprocess.run([temp_file_name], check=True)
        finally:
            os.remove(temp_file_name)  # Ensure the file is deleted after execution

    def format_size(self, size):
        kb_size = size / 1024
        return f"{kb_size:.2f} KB"

    def process(self):
        # Read encrypted data, signature, and keys
        self.encrypted_data = self.read_file(self.encrypted_file)
        self.signature = self.read_file(self.signature_file)
        self.public_key = self.read_file(self.public_key_file)
        self.private_key = self.read_file(self.private_key_file)

        # Read and decrypt data
        decrypted_data = self.decrypt_data(self.encrypted_data, self.private_key)
        decompressed_data = self.decompress_data(decrypted_data)

        # Verify the signature
        self.verify_signature(decompressed_data)

        # Split the decrypted data into chunks and execute each chunk
        with ThreadPoolExecutor() as executor:
            futures = []
            for chunk_data in self.split_binary_data(decompressed_data, self.chunk_size_kb):
                futures.append(executor.submit(self.execute_chunk, chunk_data))
            for future in futures:
                future.result()  # Wait for all chunks to complete execution


#-----------------------------------------------------------------------------------#
# ----------------------------------- main  --------------------------------------- #
#-----------------------------------------------------------------------------------#
if __name__ == "__main__":
    processor = BinaryProcessor(output_folder='output', chunk_size_kb=900)
    processor.process()
