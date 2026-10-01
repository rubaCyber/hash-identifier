import re


def identify_hash(hash_value):
    hash_value = hash_value.strip()

    result = {
        "length": len(hash_value),
        "format": "Unknown",
        "type": "Unknown",
        "confidence": "Low",
        "description": "The hash type could not be identified."
    }

    # bcrypt
    if hash_value.startswith(("$2a$", "$2b$", "$2y$")):
        result["format"] = "bcrypt format"
        result["type"] = "bcrypt"
        result["confidence"] = "High"
        result["description"] = (
            "bcrypt is a password hashing algorithm designed to be slow "
            "and resistant to brute-force attacks."
        )
        return result

    # Argon2
    if hash_value.startswith("$argon2"):
        result["format"] = "Argon2 format"
        result["type"] = "Argon2"
        result["confidence"] = "High"
        result["description"] = (
            "Argon2 is a modern password hashing algorithm designed to resist "
            "GPU and memory-based attacks."
        )
        return result

    # Hexadecimal validation
    if not re.fullmatch(r"[a-fA-F0-9]+", hash_value):
        result["format"] = "Invalid / Unknown"
        result["description"] = (
            "The value is not a valid hexadecimal hash and does not match "
            "bcrypt or Argon2 format."
        )
        return result

    result["format"] = "Hexadecimal"

    hash_length = len(hash_value)

    if hash_length == 32:
        result["type"] = "Possible MD5"
        result["confidence"] = "Medium"
        result["description"] = (
            "MD5 produces a 128-bit hash represented by 32 hexadecimal characters."
        )

    elif hash_length == 40:
        result["type"] = "Possible SHA-1"
        result["confidence"] = "Medium"
        result["description"] = (
            "SHA-1 produces a 160-bit hash represented by 40 hexadecimal characters."
        )

    elif hash_length == 56:
        result["type"] = "Possible SHA-224"
        result["confidence"] = "Medium"
        result["description"] = (
            "SHA-224 is part of the SHA-2 family and produces a 224-bit hash."
        )

    elif hash_length == 64:
        result["type"] = "Possible SHA-256"
        result["confidence"] = "Medium"
        result["description"] = (
            "SHA-256 is part of the SHA-2 family and produces a 256-bit hash."
        )

    elif hash_length == 96:
        result["type"] = "Possible SHA-384"
        result["confidence"] = "Medium"
        result["description"] = (
            "SHA-384 is part of the SHA-2 family and produces a 384-bit hash."
        )

    elif hash_length == 128:
        result["type"] = "Possible SHA-512"
        result["confidence"] = "Medium"
        result["description"] = (
            "SHA-512 is part of the SHA-2 family and produces a 512-bit hash."
        )

    else:
        result["description"] = (
            "The value is hexadecimal, but its length does not match "
            "the common hash types supported by this tool."
        )

    return result


print("=== Hash Identifier ===")

while True:
    hash_value = input("\nEnter the hash: ")

    result = identify_hash(hash_value)

    print("\n=== Hash Analysis ===")
    print("Length:", result["length"])
    print("Format:", result["format"])
    print("Possible Type:", result["type"])
    print("Confidence:", result["confidence"])
    print("Description:", result["description"])

    again = input("\nAnalyze another hash? (y/n): ").lower()

    if again != "y":
        print("\nGoodbye!")
        break