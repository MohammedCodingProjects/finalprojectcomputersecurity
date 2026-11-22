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
    string expected = HMAC(K,M);

    if (tag.size() != 32) return false;
        
    for (int i = 0; i < 32; i++) {
        if (expected[i] != tag[i])
        return false;
    }
    return true;  
    }

int main() {
    string K = "Testing";
    string M = "also testing";

    string control = HMAC(K,M);
    
    string test0 = control; test0[0] ^= 0x01;
    string test31 = control; test31[31] ^= 0x01;
    string tag31 = control.substr(0, 31);
    cout << boolalpha;

    cout << "control : " << verify_leak(K,M,control) << endl; //test against the control, if control is good then is correct baseline
    cout << "test0 : " << verify_leak(K,M, test0) << endl;
    cout << "test31 : " << verify_leak(K,M,test31) << endl;
    cout << "Tag in size 31 : " << verify_leak(K, M, tag31 ) << endl;

    return 0;
}