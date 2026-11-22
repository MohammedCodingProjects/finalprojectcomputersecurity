#include <string>
#include <iostream>

#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>  

#include <x86intrin.h>     // for __rdtsc() testing timing on amd/intel machines
                           // will include mac equivalent in case we have a mac user

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

volatile uint64_t g_sink = 0;   // volatile so the compiler can't delete the busy-loop
int g_work = 0;                 // busy-work per MATCHING byte; 0 = plain loop

void spin(int units) {
    for (int i = 0; i < units; i++) g_sink = g_sink + i;
}

bool verify_leak(const string& K, const string& M, const string& tag) {
    string expected = HMAC(K,M);

    if (tag.size() != 32) return false;
    
    for (int i = 0; i < 32; i++) {
    if (expected[i] != tag[i]) return false;
    spin(g_work);          // runs once per correct leading byte
    }

    for (int i = 0; i < 32; i++) {
        if (expected[i] != tag[i])
        return false;
    }

    return true;  
}

uint64_t time_verify(const string& K, const string& M, const string& tag) { //timings for single calls
    uint64_t start = __rdtsc();
    verify_leak(K, M, tag);
    uint64_t end = __rdtsc();
    return end - start;
}

uint64_t median(vector<uint64_t> v) { // returns median for better reading / higher accuracy, average is NOT good trust me
    sort(v.begin(), v.end());
    return v[v.size() / 2]; //2100 2200 2150 20000, average would make this inflated like dog
}

double mean(const vector<uint64_t>& v) {
    double s = 0;
    for (uint64_t x : v) s += x;
    return s / v.size();
}

int main() {
    string K = "Testing";
    string M = "also testing";
    string control = HMAC(K, M);

    string test0  = control;  test0[0]   ^= 0x01;
    string test31 = control;  test31[31] ^= 0x01;

    const int N = 10000;   // samples per run
    const int R = 100;     // number of runs

    cout << "run  med0   med31  medDiff   mean0    mean31   meanDiff\n";
    double sum_med_diff = 0;
    for (int r = 0; r < R; r++) {
        vector<uint64_t> t0, t31;
        for (int i = 0; i < N; i++) {
            t0.push_back(time_verify(K, M, test0));
            t31.push_back(time_verify(K, M, test31));
        }
        uint64_t m0 = median(t0),  m31 = median(t31);
        double   a0 = mean(t0),    a31 = mean(t31);
        sum_med_diff += (double)m31 - (double)m0;

        cout << r << "    " << m0 << "   " << m31
             << "   " << (long long)m31 - (long long)m0
             << "     " << (long long)a0 << "    " << (long long)a31
             << "    " << (long long)(a31 - a0) << "\n";
    }
    cout << "\navg median diff over " << R << " runs: " << sum_med_diff / R << " cycles\n";
    return 0;
}

