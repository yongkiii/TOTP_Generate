
//https://stackoverflow.com/questions/77315747/how-to-fetch-totp-code-using-the-secret-key-in-c
//https://www.nongnu.org/oath-toolkit/liboath-api/liboath-oath.h.html
#include <iostream>
#include <cstring>
#include <string>
#include <ctime>
#include <cmath>
#include <openssl/hmac.h>
#include <openssl/evp.h> 
//#include <endian.h>
using namespace std;

string generateTOTP(const std::string& secret, unsigned long timeStep, int digits) {
    const unsigned char* key = reinterpret_cast<const unsigned char*>(secret.c_str());
    int keyLen = secret.length();

    // Get the current Unix time
    unsigned long current_time = time(nullptr) / timeStep;

    // Convert the time to big-endian
    //current_time = htobe64(current_time);

    // Create the data to be hashed (current time)
    unsigned char data[8];
    memcpy(data, &current_time, sizeof(current_time));

    // Calculate the HMAC-SHA1 hash
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    HMAC(EVP_sha1(), key, keyLen, data, sizeof(data), hash, &hashLen);

    // Calculate the offset
    int offset = hash[hashLen - 1] & 0xf;

    // Calculate the 4 bytes OTP
    int binary = ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);

    int otp = binary % static_cast<int>(std::pow(10, digits));

    // Convert the OTP to a string with leading zeros if needed
    return std::to_string(otp);
}
int main() {
    //SECERET키는 client랑 server 둘이서 공유하는 private key
    const std::string secret_key = "###################";
    const int digits = 6; // Number of OTP digits
    //30초 간격으로 OTP 생성
    std::string totp = generateTOTP(secret_key, 30, digits);
    while (totp.length() < digits) {
        totp = "0" + totp;
    }
    std::cout << "Generated TOTP: " << totp << std::endl;
    return 0;
}