import argparse
import os
import pickle
import sys
from getpass import getpass
from typing import Set
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from dataclasses import dataclass, astuple
from shutil import make_archive, unpack_archive, rmtree


class Template:
    @dataclass
    class CipherConfig:
        """A data class for storing ciphertext, salt, tag, and nonce."""
        ciphertext: bytes
        salt: bytes
        tag: bytes
        nonce: bytes
        filename: str = ""


class Utils:
    """A class that provides utility functions."""

    @staticmethod
    def attrs(cc):
        """Returns a tuple of the attributes of a CipherConfig object.

        :param cc: A CipherConfig object
        :type cc: CipherConfig
        :returns: A tuple of the attributes of the CipherConfig object
        :rtype: tuple
        """
        return astuple(cc)

    @staticmethod
    def _rename(file):
        """Renames a file by removing the '.enc' extension if parameter 'file' endswith '.enc'
        or by appending the '.cryptfile' extension if parameter 'file' does not endswith '.enc'.

        :param file: The file to be renamed
        :type file: str
        :returns: The renamed file
        :rtype: str
        """

        if file.endswith(".enc"):
            return file[:-4]
        else:
            print("[*] It seems you have changed filename after encryption.")
            print(f"[*] Decrypted file will be saved as `{file + '.cryptfile'}`.")
            return file + ".cryptfile"

    @staticmethod
    def save_cc(data, file):
        """Saves CipherConfig in pickled format to a file.

        :param data: The data to be saved
        :type data: CipherConfig
        :param file: The file to save the data to
        :type: file: str
        """

        with open(file + ".enc", "wb") as f:
            pickle.dump(data.__dict__, f, -1)

    @staticmethod
    def save_file(data, filename):
        """Saves data to a file.

        :param data: The data to be saved
        :type data: bytes
        :param filename: The file to save the data to
        :type: filename: str
        """

        with open(filename, "wb") as f:
            f.write(data)

    @staticmethod
    def open_file(file, pickled: bool = False):
        """Opens a file and returns its content in either bytes or pickled format.

        :param file: The file to be opened
        :type file: str
        :param pickled: Specifies whether file content is pickled or not. Defaults to False
        :type pickled: bool, optional

        :returns: The content of the file in either bytes or pickled format, depending on the value
            of the 'pickled' argument.
        :rtype: bytes or object
        """

        with open(file, "rb") as f:
            if pickled:
                data_dict = pickle.load(f)
                data = Template.CipherConfig(**data_dict)
            else:
                data = f.read()
        return data

    @staticmethod
    def archive_dir(directory, compress=False):
        if compress:
            archive_filename = os.path.basename(directory)
            output_path = make_archive(archive_filename, "zip", directory)
        else:
            archive_filename = os.path.basename(directory)
            output_path = make_archive(archive_filename, "tar", directory)
        return output_path

    @staticmethod
    def unarchive_dir(archive_file):
        if "tar" in archive_file:
            archive_filename = archive_file.split(".tar")[0]
        else:
            archive_filename = archive_file.split(".zip")[0]

        unpack_archive(archive_file, extract_dir=archive_filename)


class Security:
    """Class for handling all cryptographical functions."""

    def __init__(self, master_password_hash: bytes):
        self.mp = master_password_hash
        self.cost_factor = 2**20
        self.rounds = 8
        self.parallel_factor = 1
        self.key_length = 32


    def get_password(no_check: bool = False):
        """
        Hash the passwords entered by the user and return a hashed password 
        if `no_check` is True, else compare the two passwords to confirm 
        while encryption and return a hashed password if they match.

        :param no_check: If True, do not check for password matching. 
         Defaults to False.
        :type no_check: bool
        :return: The hashed password
        :rtype: bytes
        """
        p1 = SHA256.new(getpass("Enter Password: ").encode("utf-8")).hexdigest()
        if no_check:
            return p1.encode("utf-8")
        p2 = SHA256.new(getpass("Re-enter Password: ").encode("utf-8")).hexdigest()

        if p1 == p2:
            return p1.encode("utf-8")
        else:
            print(">>> Incorrect Password ! <<<")
            sys.exit(1)

    def _kdf_scrypt(self, _salt: bytes) -> bytes:
        """
        Use scrypt to derive a key from the master password hash and the given salt.

        :param _salt: The salt to use for key derivation
        :type _salt: bytes
        :returns: The derived key
        :rtype: bytes
        """

        return scrypt(
            str(self.mp),
            str(_salt),
            self.key_length,
            self.cost_factor,
            self.rounds,
            self.parallel_factor,
        )
    def encrypt(self, data: bytes):
        """
        Takes data to encrypt and use the key to encrypt the data. Return a 
        CipherConfig object containing the encrypted data, salt, tag, and nonce.

        :param data: The data to encrypt
        :type data: bytes
        :returns: CipherConfig: The CipherConfig object containing the encrypted 
         data, salt, tag, and nonce
        :rtype: CipherConfig
        """

        _salt = get_random_bytes(32)
        # Derive a key from the master password hash and the salt
        key = self._kdf_scrypt(_salt)
        # Initialize a cipher object with the key and the GCM mode
        cipher = AES.new(key, AES.MODE_GCM)
        # Encrypt the data
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return Template.CipherConfig(ciphertext, _salt, tag, cipher.nonce)

    def decrypt(self, cc):
        """
        Take CipherConfig object and derive a key from the master password 
        hash and CipherConfig object, and use the key to decrypt and verify 
        the data. Return the decrypted data as a string.

        :param cc: The CipherConfig object containing the encrypted data, 
         salt, tag, and nonce
        :type cc: CipherConfig
        :returns: The decrypted data
        :rtype: bytes
        """

        # Extract the ciphertext, salt, tag, and nonce from the CipherConfig object
        ciphertext, _salt, tag, nonce, _ = Utils.attrs(cc)
        # Derive a key from the master password hash and the salt
        key = self._kdf_scrypt(_salt)
        # Initialize a cipher object with the key, the GCM mode, and the nonce
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        # Decrypt and verify the data
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data


class Cryptfile:
    """Cryptfile class provides user interaction functionality and 
    prepares files for encryption and decryption."""

    def __init__(self, files: Set = None, directories: Set = None):
        """Initializes the Cryptfile object
        :param files: The file to be encrypted or decrypted
        :type files: set
        :param directories: The directory to be encrypted or decrypted
        :type directories: set
        """

        self.files = files
        self.directories = directories

    def encrypt_file(self):
        """
        Firstly, retrieve the file content in bytes format and then sent 
        to the Security class for encryption. The encrypted content is 
        then saved with the original filename + '.enc' extension.

        Example
        -------
        original file: example.txt
        after encryption: example.txt.enc
        """

        # Get password hash
        password_hash = Security.get_password()

        for file in self.files:
            # Get file content in bytes format to encrypt
            data = Utils.open_file(file)
            print(f"\nEncrypting [ {file} ]", end="\r")

            cc = Security(password_hash).encrypt(data)
            cc.filename = file

            # Save encrypted content with original file and '.enc' extension
            encrypted_file = f"{file}.enc"
            Utils.save_cc(cc, file)
            os.remove(file)
            
            print(f"Encrypting [ {file} ] \t [+] Completed", end="\n", flush=True)

    def decrypt_file(self):
        """
        The file content is first retrieved in picked bytes format and 
        then decrypted using the Security class.The decrypted content is 
        then saved with the original file name, either without the 
        '.enc' extension or with the '.cryptfile' extension if any file 
        is supplied for decryption without `.enc` extension.
        """

        # Get password hash
        password_hash = Security.get_password(no_check=True)

        for file in self.files:
            # Get file content in pickled bytes format to decrypt
            cc = Utils.open_file(file, pickled=True)
            print(f"\nDecrypting [ {file} ]", end="\r")
            data = Security(password_hash).decrypt(cc)

            # Save decrypted content with original file name or '.cryptfile' extension
            Utils.save_file(data, Utils._rename(file))
            os.remove(file)
            print(f"Decrypting [ {file} ] \t [+] Completed", end="\n", flush=True)

    def encrypt_dir(self, compress=False):
        """Encrypts the contents of the specified directory, optionally 
        compressing it before encryption."""

        # get password hash
        password_hash = Security.get_password()

        for directory in self.directories:
            archive = Utils.archive_dir(directory, compress)
            with open(archive, "rb") as f:
                data = f.read()
            cc = Security(password_hash).encrypt(data)
            cc.filename = archive
            Utils.save_cc(cc, archive)
            print(f"Encrypting [ {directory} ] \t [+] Completed", end="\n", flush=True)
            rmtree(directory)
            os.remove(archive)

    def decrypt_dir(self):
        """Decrypts the contents of the specified directory."""

        # get password hash
        password_hash = Security.get_password(no_check=True)

        for directory in self.directories:
            cc = Utils.open_file(directory, pickled=True)
            data = Security(password_hash).decrypt(cc)
            with open(cc.filename, "wb") as f:
                f.write(data)
            Utils.unarchive_dir(cc.filename)
            os.remove(directory)
            os.remove(cc.filename)


def main():
    # Create a parser object
    parser = argparse.ArgumentParser(
        prog="cryptfile",
        description="Encrypt/Decrypt file(s) or directories securely.",
    )
    # add an optional argument `-e` and a required argument `-f`
    parser.add_argument(
        "-f",
        "--file",
        help="The file(s) to encrypt/decrypt",
        nargs="+",
    )
    parser.add_argument(
        "-d",
        "--dir",
        help="The directory(s) to encrypt/decrypt",
        nargs="+",
    )
    parser.add_argument(
        "-c", "--compress", help="Compress directory before encrypting", action="store_true"
    )
    parser.add_argument(
        "-e", "--encrypt", help="Encrypt file(s) or directory(s)", action="store_true"
    )
    parser.add_argument(
        "-D", "--decrypt", help="Decrypt file(s) or directory(s)", action="store_true"
    )

    args = parser.parse_args()

    # Create an instance of the Cryptfile class
    files = set(args.file) if args.file else None
    dirs = set(args.dir) if args.dir else None
    cryptfile = Cryptfile(files=files, directories=dirs)

    # Encrypt files or directory
    if args.encrypt:
        if cryptfile.files:
            cryptfile.encrypt_file()
        if cryptfile.directories:
            cryptfile.encrypt_dir(compress=args.compress)

    # Decrypt files or directory
    elif args.decrypt:
        if cryptfile.files:
            cryptfile.decrypt_file()
        if cryptfile.directories:
            cryptfile.decrypt_dir()
    else:
        print("[!] Please specify whether to encrypt (-e) or decrypt (-D).")


if __name__ == "__main__":
    main()
