#include <iostream>
#include <string>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

using namespace std;

// Function to compute SHA256 hash of a message
string computeSHA256(const string& message) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, message.c_str(), message.length());
    SHA256_Final(hash, &sha256_ctx);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << (int)hash[i];
    }
    return ss.str();
}

// Function to sign using RSA private key
string signMessage(const string& message, RSA* privateKey) {
    unsigned char* signature = new unsigned char[RSA_size(privateKey)];
    unsigned int signatureLength;
    string messageHash = computeSHA256(message);
    if (RSA_sign(NID_sha256, (unsigned char*)messageHash.c_str(), messageHash.length(), signature, &signatureLength, privateKey) != 1) {
        cerr << "Error signing message." << endl;
        delete[] signature;
        return "";
    }

    stringstream ss;
    for (unsigned int i = 0; i < signatureLength; i++) {
        ss << hex << (int)signature[i];
    }
    delete[] signature;
    return ss.str();
}

// Function to encrypt the hash of the response message
string encryptHash(const string& hash, RSA* publicKey) {
    unsigned char* encryptedHash = new unsigned char[RSA_size(publicKey)];
    int encryptedLength = RSA_public_encrypt(hash.length(), (unsigned char*)hash.c_str(), encryptedHash, publicKey, RSA_PKCS1_OAEP_PADDING);

    if (encryptedLength == -1) {
        cerr << "Error encrypting hash." << endl;
        delete[] encryptedHash;
        return "";
    }

    stringstream ss;
    for (int i = 0; i < encryptedLength; i++) {
        ss << hex << (int)encryptedHash[i];
    }
    delete[] encryptedHash;
    return ss.str();
}

// Function to create the response message
string createResponseMessage(RSA* privateKey, RSA* publicKey, const string& receivedMessage, const string& receivedSignature) {
    string messageHash = computeSHA256(receivedMessage);
    string responseMessage = "Message received and validated.";
    string responseMessageHash = computeSHA256(responseMessage);
    string encryptedHash = encryptHash(responseMessageHash, publicKey);

    string responseSignature = signMessage(responseMessage, privateKey);

    string response = "Original Signature: " + receivedSignature + "\n"
                                                                   "Original Hash: " + messageHash + "\n"
                                                                                                     "Encrypted Hash of the Response Message: " + encryptedHash + "\n"
                                                                                                                                                                  "Response Signature: " + responseSignature;

    return response;
}

int main() {
    FILE* privateKeyFile = fopen("private.pem", "r");
    RSA* privateKey = PEM_read_RSAPrivateKey(privateKeyFile, NULL, NULL, NULL);
    fclose(privateKeyFile);

    FILE* publicKeyFile = fopen("public.pem", "r");
    RSA* publicKey = PEM_read_RSA_PUBKEY(publicKeyFile, NULL, NULL, NULL);
    fclose(publicKeyFile);

    string originalMessage = "This is a message to be signed.";
    string originalSignature = signMessage(originalMessage, privateKey);

    cout << "Original Message: " << originalMessage << endl;
    cout << "Original Signature: " << originalSignature << endl;

    string responseMessage = createResponseMessage(privateKey, publicKey, originalMessage, originalSignature);
    cout << "\nResponse Message: " << endl;
    cout << responseMessage << endl;

    RSA_free(privateKey);
    RSA_free(publicKey);

    return 0;
}
