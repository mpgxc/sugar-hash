import os
import argparse
from bit import Key
from multiprocessing import Pool, cpu_count, Manager
from Crypto.Hash import RIPEMD160, SHA256
from base58 import b58encode
from hashlib import sha256

wallet_address = [
    "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9",
    "1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ",
    "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG",
    "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
    "1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR",
    "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4",
    "1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv",
    "1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv",
    "1DJh2eHFYQfACPmrvpyWc8MSTYKh7w9eRF",
    "1Bxk4CQdqL9p22JEtDfdXMsng1XacifUtE",
    "15qF6X51huDjqTmF9BJgxXdt1xcj46Jmhb",
    "1ARk8HWJMn8js8tQmGUJeQHjSE7KRkn2t8",
    "15qsCm78whspNQFydGJQk5rexzxTQopnHZ",
    "13zYrYhhJxp6Ui1VV7pqa5WDhNWM45ARAC",
    "14MdEb4eFcT3MVG5sPFG4jGLuHJSnt1Dk2",
    "1CMq3SvFcVEcpLMuuH8PUcNiqsK1oicG2D",
    "1K3x5L6G57Y494fDqBfrojD28UJv4s5JcK",
    "1PxH3K1Shdjb7gSEoTX7UPDZ6SH4qGPrvq",
    "16AbnZjZZipwHMkYKBSfswGWKDmXHjEpSf",
    "19QciEHbGVNY4hrhfKXmcBBCrJSBZ6TaVt",
    "1EzVHtmbN4fs4MiNk3ppEnKKhsmXYJ4s74",
    "1AE8NzzgKE7Yhz7BWtAcAAxiFMbPo82NB5",
    "1AE8NzzgKE7Yhz7BWtAcAAxiFMbPo82NB5",
    "1K6xGMUbs6ZTXBnhw1pippqwK6wjBWtNpL",
    "15ANYzzCp5BFHcCnVFzXqyibpzgPLWaD8b",
    "18ywPwj39nGjqBrQJSzZVq2izR12MDpDr8",
    "1CaBVPrwUxbQYYswu32w7Mj4HR4maNoJSX",
    "1JWnE6p6UN7ZJBN7TtcbNDoRcjFtuDWoNL",
    "1CKCVdbDJasYmhswB6HKZHEAnNaDpK7W4n",
    "1PXv28YxmYMaB8zxrKeZBW8dt2HK7RkRPX",
    "1AcAmB6jmtU6AiEcXkmiNE9TNVPsj9DULf",
    "1EQJvpsmhazYCcKX5Au6AZmZKRnzarMVZu",
    "18KsfuHuzQaBTNLASyj15hy4LuqPUo1FNB",
    "15EJFC5ZTs9nhsdvSUeBXjLAuYq3SWaxTc",
    "1HB1iKUqeffnVsvQsbpC6dNi1XKbyNuqao",
    "1GvgAXVCbA8FBjXfWiAms4ytFeJcKsoyhL",
    "1824ZJQ7nKJ9QFTRBqn7z7dHV5EGpzUpH3",
    "18A7NA9FTsnJxWgkoFfPAFbQzuQxpRtCos",
    "1NeGn21dUDDeqFQ63xb2SpgUuXuBLA4WT4",
    "174SNxfqpdMGYy5YQcfLbSTK3MRNZEePoy",
    "1MnJ6hdhvK37VLmqcdEwqC3iFxyWH2PHUV",
    "1KNRfGWw7Q9Rmwsc6NT5zsdvEb9M2Wkj5Z",
    "1PJZPzvGX19a7twf5HyD2VvNiPdHLzm9F6",
    "1GuBBhf61rnvRe4K8zu8vdQB3kHzwFqSy7",
    "1GDSuiThEV64c166LUFC9uDcVdGjqkxKyh",
    "1Me3ASYt5JCTAK2XaC32RMeH34PdprrfDx",
    "1CdufMQL892A69KXgv6UNBD17ywWqYpKut",
    "1BkkGsX9ZM6iwL3zbqs7HWBV7SvosR6m8N",
    "1AWCLZAjKbV1P7AHvaPNCKiB7ZWVDMxFiz",
    "1G6EFyBRU86sThN3SSt3GrHu1sA7w7nzi4",
    "1MZ2L1gFrCtkkn6DnTT2e4PFUTHw9gNwaj",
    "1Hz3uv3nNZzBVMXLGadCucgjiCs5W9vaGz",
    "1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua",
    "16zRPnT8znwq42q7XeMkZUhb1bKqgRogyy",
    "1KrU4dHE5WrW8rhWDsTRjR21r8t3dsrS3R",
    "17uDfp5r4n441xkgLFmhNoSW1KWp6xVLD",
    "13A3JrvXmvg5w9XGvyyR4JEJqiLz8ZySY3",
    "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v",
    "1UDHPdovvR985NrWSkdWQDEQ1xuRiTALq",
    "15nf31J46iLuK1ZkTnqHo7WgN5cARFK3RA",
    "1Ab4vzG6wEQBDNQM1B2bvUz4fqXXdFk2WT",
    "1Fz63c775VV9fNyj25d9Xfw3YHE6sKCxbt",
    "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo",
    "1CD91Vm97mLQvXhrnoMChhJx4TP9MaQkJo",
    "15MnK2jXPqTMURX4xC3h4mAZxyCcaWWEDD",
    "13Q84TNNvgcL3HJiqQPvyBb9m4hxjS3jkV",
    "1LuUHyrQr8PKSvbcY1v1PiuGuqFjWpDumN",
    "18192XpzzdDi2K11QVHR7td2HcPS6Qs5vg",
    "1AoeP37TmHdFh8uN72fu9AqgtLrUwcv2wJ",
    "1FTpAbQa4h8trvhQXjXnmNhqdiGBd1oraE",
    "14JHoRAdmJg3XR4RjMDh6Wed6ft6hzbQe9",
    "19z6waranEf8CcP8FqNgdwUe1QRxvUNKBG",
    "14u4nA5sugaswb6SZgn5av2vuChdMnD9E5",
    "1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv"
]


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

        print(f"Target: {target_address} => Predict: {address}")

        if address == target_address or address in wallet_address:
            result["found"] = (key.to_wif(), address)
            return


def main():

    parser = argparse.ArgumentParser(
        description="BrainWallet Lucky Mining")
    parser.add_argument("--reverse", action="store_true", help="Search from end to start")
    args = parser.parse_args()

    start_range = int(
        "0000000000000000000000000000000000000000000000020000000000000000", 16)
    end_range = int(
        "000000000000000000000000000000000000000000000003ffffffffffffffff", 16)
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"

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
        print(f"Found matching key for address {
              target_address}\nPrivate Key (WIF): {key_wif}\nAddress: {address}")

        output_dir = "/app/output"

        os.makedirs(output_dir, exist_ok=True)

        with open(os.path.join(output_dir, "found_keys.txt"), "w") as f:
            f.write(f"Private Key (WIF): {key_wif}\n")
            f.write(f"Address: {address}\n")
    else:
        print("No matching key found for address {} in the given range.".format(
            target_address))


if __name__ == "__main__":
    main()
