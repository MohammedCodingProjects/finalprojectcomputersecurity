#include <string>
#include <iostream>

#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>  

using namespace std;

string sha256(const string& data) {
    string digest;
    CryptoPP::SHA256 hash;
    CryptoPP::StringSource(data, true,
        new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(digest)));
    return digest;
}

string HMAC (string K, string M) { //H((K' XOR opad) || H((K' XOR ipad) || M))
    if (K.size() > 64) {K = sha256(K);}
    K.resize(64, '\0');

    string okey = K;
    string ikey = K;

    for (int i = 0; i < 64; i++) {
        okey[i] = okey[i] ^ 0x5c;
        ikey[i] = ikey[i] ^ 0x36;
    }

    string ikeySha = sha256(ikey + M);
    string okeySha = sha256(okey + ikeySha);

    return okeySha;
}

void print_hex(const string& s) {
    string out;
    CryptoPP::StringSource(s, true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(out), false));  // false = lowercase
    cout << out << endl;
}


bool verify_leak(const string& K, const string& M, const string& tag) {
    
    
    
    return false;  
}

int main() {
    print_hex(sha256("abc"));
    // should print ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

    print_hex(HMAC("Jefe", "what do ya want for nothing?"));
    // should print 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843

    return 0;
}