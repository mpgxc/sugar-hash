import os
import argparse
from bit import Key
from multiprocessing import Pool, cpu_count, Manager
from Crypto.Hash import RIPEMD160, SHA256
from base58 import b58encode
from hashlib import sha256


def generate_key_from_int(i):
    hex_key = hex(i)[2:].zfill(64)
    return hex_key


def ripemd160_sha256(bytestr):
    sha256_hash = SHA256.new(bytestr).digest()
    ripemd160_hash = RIPEMD160.new(sha256_hash).digest()
    return ripemd160_hash


def public_key_to_address(public_key, version):
    version_byte = bytes.fromhex(version)
    pubkey_hash = ripemd160_sha256(public_key)
    return b58encode_check(version_byte + pubkey_hash)


def b58encode_check(data):
    digest = sha256(sha256(data).digest()).digest()
    return b58encode(data + digest[:4])


def check_range(start_range, end_range, target_address, result, reverse=False):
    if reverse:
        range_iter = range(end_range, start_range - 1, -1)
    else:
        range_iter = range(start_range, end_range + 1)

    for i in range_iter:
        if result["found"]:
            return

        hex_key = generate_key_from_int(i)
        key = Key.from_hex(hex_key)
        public_key = key.public_key
        address = public_key_to_address(public_key, '00')


        address_decoded = address.decode('utf-8')

        # print(f"Target: {target_address} => Predict: {address_decoded}")

        if address_decoded == target_address:
            result["found"] = (key.to_wif(), target_address)
            break


def main():

    parser = argparse.ArgumentParser(
        description="BrainWallet Lucky Mining")
    parser.add_argument("--reverse", action="store_true", help="Search from end to start")
    args = parser.parse_args()

    start_range = int(
        "0000000000000000000000000000000000000000000000040000000000000000", 16)
    end_range = int(
        "000000000000000000000000000000000000000000000007ffffffffffffffff", 16)
    target_address = "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9"

    num_processes = cpu_count() * 2
    chunk_size = (end_range - start_range) // num_processes

    ranges = [(start_range + i * chunk_size, start_range + (i + 1)
               * chunk_size - 1) for i in range(num_processes)]
    # Adjust the last chunk to the end of the range
    ranges[-1] = (ranges[-1][0], end_range)

    manager = Manager()
    result = manager.dict()
    result["found"] = None

    with Pool(processes=num_processes) as pool:
        futures = [pool.apply_async(
            check_range, (start, end, target_address, result, args.reverse)) for start, end in ranges]

        for future in futures:
            future.get()
            if result["found"]:
                break

    if result["found"]:
        key_wif, address = result["found"]
        print(f"Found matching key for address {target_address}\nPrivate Key (WIF): {key_wif}\nAddress: {address}")

        output_dir = "/app/output"

        os.makedirs(output_dir, exist_ok=True)

        with open(os.path.join(output_dir, "found_keys.txt"), "w", encoding="utf-8") as f:
            f.write(f"Private Key (WIF): {key_wif}\n")
            f.write(f"Address: {address}\n")
    else:
        print(f"No matching key found for address {target_address} in the given range.")


if __name__ == "__main__":
    main()
