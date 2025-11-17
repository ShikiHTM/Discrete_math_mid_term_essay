from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )
    return ciphertext

def decrypt(private_key, ciphertext):
    plainText = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None,
        )
    )
    return plainText.decode()

private_key, public_key = generate_keys()

test_case_msg = [
    "Hello world!",
    "Hi, I'm Pham Nguyen Khanh Dang",
    "-.- .- . .-.. .- / -.- --- ...- .- .-.. ... -.- .. .- / .. ... / -- -.-- / --- ... .... .."
    "Fatty Oguri cap",
    "Special week",
    "Silence Suzuka"
]

test_success_percent = int()
test_failed_percent = int()

for testCase in test_case_msg:
    cipherText = encrypt(public_key, testCase)
    plainText = decrypt(private_key, cipherText)
    if plainText == testCase:
        test_success_percent += 1
    else:
        test_failed_percent += 1

print("Success rate: %d" % (test_success_percent))
print("Failed rate: %d" % (test_failed_percent))
print("Failed percent: %.2f" % ((test_failed_percent / float(test_success_percent))))

import matplotlib.pyplot as plt
import time

sample_text = [
    "Hello",
    "Hello RSA!",
    "Encrypt this msg",
    "Message length: twenty",
    "This is a sample message length thirty.",
    "This message contains exactly forty characters!!",
    "Fifty characters long message used for RSA timing test!!!",
    "Sixty char message for evaluating RSA performance accurately here.",
    "This is an eighty-character long message used to analyze how RSA encryption time scales.",
    "This one is a one-hundred-character test message to help you benchmark RSA encryption and decryption timings accurately."
]

encrypt_excuse_time = {}
decrypt_excuse_time = {}

for text in sample_text:
    text_length = len(text)

    start_enc = time.perf_counter()
    ct = encrypt(public_key, text)
    end_enc = time.perf_counter()

    start_dec = time.perf_counter()
    pt = decrypt(private_key, ct)
    end_dec = time.perf_counter()

    assert pt == text, "Decryption failed!"

    encrypt_excuse_time[text_length] = round((end_enc - start_enc)*1000, 5)
    decrypt_excuse_time[text_length] = round((end_dec - start_dec)*1000, 5)

lengths = sorted(encrypt_excuse_time.keys())
encrypt_times = [encrypt_excuse_time[l] for l in lengths]
decrypt_times = [decrypt_excuse_time[l] for l in lengths]

plt.figure(figsize=(10,6))

plt.plot(lengths, encrypt_times, marker='o', label="Encrypt Time (ms)")
plt.plot(lengths, decrypt_times, marker='s', label="Decrypt Time (ms)")

plt.title("RSA Encryption/Decryption Time vs Message Length")
plt.xlabel("Message lengths (characters)")
plt.ylabel("time consumptions (ms)")
plt.grid()
plt.legend()
plt.show()