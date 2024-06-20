import os
import json
from mnemonic import Mnemonic
from pathlib import Path
from loguru import logger
from substrateinterface import Keypair as SubstrateKeypair
from eth_account import Account
from solders.keypair import Keypair as SolanaKeypair
from bitcoinlib.wallets import Wallet, wallet_delete
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from base64 import urlsafe_b64encode, urlsafe_b64decode

NEMO = Mnemonic("english")


class KeyDataError(Exception):
    """Exception raised for errors retrieving key data."""


def derive_from_password(password, salt, length=32):
    """
    Derives a key from a given password and salt using PBKDF2 with SHA256 algorithm.

    Args:
        password (str): The password to derive the key from.
        salt (bytes): The salt to use in the key derivation.
        length (int, optional): The desired length of the derived key in bytes. Defaults to 32.

    Returns:
        bytes: The derived key.

    Raises:
        None

    Note:
        The PBKDF2HMAC algorithm is used to derive the key. The SHA256 hash function is used as the underlying hash function.
        The key derivation process is repeated for the specified number of iterations to make it more secure.
        The backend used for the key derivation is the default backend provided by the cryptography library.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


# Generate 12-word mnemonic
def generate_mnemonic():
    """
    Generate a 12-word mnemonic phrase using the NEMO library.

    Returns:
        str: The generated mnemonic phrase.
    """
    return NEMO.generate(strength=128)


# Derive Substrate Keypair
def derive_substrate_key(seed):
    """
    Derive a Substrate keypair from the given seed.

    Args:
        seed (str): The seed used to derive the keypair.

    Returns:
        SubstrateKeypair: The derived Substrate keypair.
    """
    return SubstrateKeypair.create_from_seed(seed)


# Derive Ethereum Keypair
def derive_ethereum_key(seed):
    """
    Derive an Ethereum keypair from a seed.

    Args:
        seed (str): The seed used to generate the Ethereum keypair.

    Returns:
        dict: A dictionary containing the Ethereum private key and address.
            - eth_private_key (str): The hexadecimal representation of the Ethereum private key.
            - eth_address (str): The Ethereum address corresponding to the private key.
    """
    acct = Account.from_mnemonic(mnemonic=seed)
    return {"eth_private_key": acct.key.hex(), "eth_address": acct.address}


# Derive Solana Keypair
def derive_solana_key(seed):
    """
    Derives a Solana Keypair based on the provided seed.

    Parameters:
        seed (str): The seed used for keypair derivation.

    Returns:
        dict: A dictionary containing the Solana private and public keys.
    """
    sol = SolanaKeypair.from_seed(seed)
    return {"sol_private_key": sol.secret(), "sol_public_key": sol.pubkey()}


def derive_btc_key(seed):
    """
    Derives a Bitcoin Keypair based on the provided seed.

    Parameters:
        seed (str): The seed used for keypair derivation.

    Returns:
        dict: A dictionary containing the Bitcoin private key.
    """
    # Derive Bitcoin Keypair
    btcwallet = Wallet.create(name="test3", keys=seed, network="bitcoin")
    return {"btc_private_key": btcwallet.get_key()}


# Encrypt and decrypt private key
def encrypt_with_password(data: bytes, password: str) -> bytes:
    """
    Encrypts the given data using the provided password.

    Args:
        data (bytes): The data to be encrypted.
        password (str): The password used to derive the encryption key.

    Returns:
        bytes: The encrypted data, including the salt, initialization vector (IV), and encrypted data.

    This function generates a random salt, derives a key from the password using the `derive_from_password` function,
    generates a random Initialization Vector (IV), pads the data using the PKCS7 padding scheme, encrypts the data
    using the AES algorithm in CFB mode, and returns the salt, IV, and encrypted data concatenated together.
    """
    # Generate a random salt
    salt = os.urandom(16)
    # Derive a key from the password
    key = derive_from_password(password, salt)

    # Generate a random Initialization Vector (IV)
    iv = os.urandom(16)

    # Pad the data
    padder = padding.PKCS7(algorithms.AES(key).block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Return the salt + iv + encrypted_data
    return salt + iv + encrypted_data


def decrypt_with_password(encrypted_data: bytes, password: str) -> bytes:
    """
    Decrypts the given encrypted data using the provided password.

    Args:
        encrypted_data (bytes): The encrypted data to be decrypted.
        password (str): The password used to derive the decryption key.

    Returns:
        bytes: The decrypted data.

    Raises:
        None

    This function extracts the salt, initialization vector (IV), and actual encrypted data from the given encrypted data.
    It then derives the decryption key from the password and salt using the `derive_from_password` function.
    The decryption is performed using the AES algorithm in CFB mode.
    The decrypted data is unpadded using the PKCS7 padding scheme.
    The decrypted data is returned as bytes.
    """
    # Extract the salt, IV, and actual encrypted data
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    actual_encrypted_data = encrypted_data[32:]

    # Derive the key from the password and salt
    key = derive_from_password(password, salt)

    # Decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = (
        decryptor.update(actual_encrypted_data) + decryptor.finalize()
    )

    # Unpad the data
    unpadder = padding.PKCS7(algorithms.AES(key).block_size).unpadder()
    return unpadder.update(decrypted_pinned_data) + unpadder.finalize()


def create_rsa_keypair(private_key_path=None, public_key_path=None, password=None):
    """
    Creates an RSA key pair and saves the private and public keys to the specified file paths.

    Args:
        private_key_path (Path, optional): The path to save the private key. If not provided, the default path is "instance_data/private_key.enc".
        public_key_path (Path, optional): The path to save the public key. If not provided, the default path is "instance_data/public_key.pub".
        password (str, optional): The password used to encrypt the private key. If not provided, an error will be raised.

    Returns:
        Tuple[Path, Path]: A tuple containing the file paths of the private and public keys.

    Raises:
        KeyDataError: If no password is provided.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_key_path = private_key_path or Path("instance_data/private_key.enc")
    public_key_path = public_key_path or Path("instance_data/public_key.pub")
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    if password is None:
        raise KeyDataError("No password provided")
    encrypted_private_key = encrypt_with_password(private_key_pem, password)

    private_key_path.write_bytes(encrypted_private_key)
    public_key_path.write_bytes(public_key_pem)

    return private_key_path, public_key_path


def encrypt_with_file(
    data,
    password,
    private_path=None,
    public_path=None,
    public_encryption=True,
    private_encryption=True,
):
    """
    Encrypts the provided data using the specified encryption keys and password.

    Args:
        data: The data to be encrypted.
        password: The password used for encryption.
        private_path: The path to the private key file. If not provided, a new RSA key pair is generated.
        public_path: The path to the public key file. If not provided, it is derived from the private key path.
        public_encryption: Flag indicating whether public key encryption is enabled. Defaults to True.
        private_encryption: Flag indicating whether private key encryption is enabled. Defaults to True.

    Returns:
        Tuple containing the encrypted data and the paths to the private and public key files.
    """
    if private_path is None:
        private_path, public_path = create_rsa_keypair(password=password)

    private_key_path = private_path
    public_path = public_path or private_path.with_suffix(".pub")

    public_key = serialization.load_pem_public_key(public_path.read_bytes())
    private_key = private_key_path.read_bytes()

    if password is None:
        raise KeyDataError("No password provided")

    decrypted_private_key = serialization.load_pem_private_key(
        decrypt_with_password(private_key, password), password=None
    )

    encrypted_data = {}
    if public_encryption:
        public_encrypt_data = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        encrypted_data["public"] = public_encrypt_data
    if private_encryption:
        if public_encryption:
            encrypted_data["private"] = decrypted_private_key.encrypt(
                encrypted_data["public"],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        else:
            encrypted_data["private"] = decrypted_private_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

    return encrypted_data, private_path, public_path


def decrypt_with_file(
    encrypted_data,
    password,
    private_path=None,
    public_path=None,
    public_encryption=True,
    private_encryption=True,
):
    """
    Decrypts the given encrypted data using the specified password and key files.

    Args:
        encrypted_data (dict): A dictionary containing the encrypted data with keys "public" and "private".
        password (str): The password used to decrypt the data.
        private_path (Path, optional): The path to the private key file. Defaults to None.
        public_path (Path, optional): The path to the public key file. Defaults to None.
        public_encryption (bool, optional): Whether the data was encrypted using a public key. Defaults to True.
        private_encryption (bool, optional): Whether the data was encrypted using a private key. Defaults to True.

    Raises:
        KeyDataError: If no private key is provided or no password is provided.

    Returns:
        dict: A dictionary containing the decrypted data with keys "public" and "private".
    """
    if private_path is None:
        raise KeyDataError("No private key provided")

    if password is None:
        raise KeyDataError("No password provided")

    private_key_path = private_path
    public_path = public_path or private_path.with_suffix(".pub")

    decrypted_data = {}
    if public_encryption:
        public_key = serialization.load_pem_public_key(public_path.read_bytes())
        decrypted_data["public"] = public_key.decrypt(
            encrypted_data["public"],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    if private_encryption:
        private_key = serialization.load_pem_private_key(
            decrypt_with_password(private_key_path.read_bytes(), password),
            password=None,
        )
        if public_encryption:
            decrypted_data["private"] = private_key.decrypt(
                encrypted_data["private"],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        else:
            decrypted_data["private"] = private_key.decrypt(
                encrypted_data["private"],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

    return decrypted_data


def create_wallet_key(account, password):  # sourcery skip: merge-dict-assign
    """
    Creates a wallet key for the given account and password.

    Args:
        account (str): The account name.
        password (str): The password used to encrypt the key.

    Returns:
        dict: A dictionary containing the account name and the encrypted keys.
              The encrypted keys are stored in the "account_private_key" and
              "substrate_private_key" fields.

    Raises:
        KeyDataError: If there is an error deriving the key data.

    This function generates a key data using the provided password and a random
    initialization vector. It then encrypts the key data using the password and
    stores the encrypted key in the "account_private_key" field of the
    account_data_dict dictionary.

    Next, it generates a keypair using the generate_mnemonic() function and
    encrypts the private key using the password. The encrypted private key is
    stored in the "substrate_private_key" field of the account_data_dict
    dictionary.

    Finally, the account_data_dict dictionary is written to a JSON file located
    at "instance_data/{account}.json".

    Note: The function uses the `derive_from_password`, `encrypt_with_password`,
    `derive_substrate_key`, `generate_mnemonic`, `urlsafe_b64encode`, and
    `json.dumps` functions.
    """

    key_data_path = Path(f"instance_data/{account}.json")
    account_data_dict = {"account": account}

    try:
        key_data = derive_from_password(password, os.urandom(16))
        encrypted_key = encrypt_with_password(key_data, password)
        account_data_dict["account_private_key"] = urlsafe_b64encode(
            encrypted_key
        ).decode("utf-8")
    except KeyDataError as e:
        logger.error(e)
        return

    keypair = derive_substrate_key(generate_mnemonic())
    encrypted_private_key = encrypt_with_password(
        keypair.private_key.encode(), password
    )
    account_data_dict["substrate_private_key"] = urlsafe_b64encode(
        encrypted_private_key
    ).decode("utf-8")

    key_data_path.parent.mkdir(parents=True, exist_ok=True)
    key_data_path.write_text(json.dumps(account_data_dict))

    return account_data_dict


if __name__ == "__main__":
    account = "test_account"
    password = "strongpassword"

    # Create wallet key
    account_data = create_wallet_key(account, password)
    print("Account data:", account_data)
