Rsa · CPP
#include <string>
#include <iostream>
#include <vector>
#include <algorithm>
 
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/osrng.h>
 
#include <x86intrin.h>     // for __rdtsc(), same as verifier.cpp
 
using namespace std;
using CryptoPP::Integer;
 
struct RSAKey {
    Integer n, e, d;       // public = (n, e), private = d
};
 
// random prime of exactly "bits" bits
Integer random_prime(CryptoPP::AutoSeededRandomPool& rng, int bits) {
    Integer p;
    do {
        p.Randomize(rng, bits);
        p.SetBit(bits - 1);   // force top bit so p is really "bits" long
        p.SetBit(bits - 2);   // top two bits set so p*q has the full 2*bits length
        p.SetBit(0);          // odd
    } while (!CryptoPP::VerifyPrime(rng, p, 20));
    return p;
}
 
RSAKey keygen(int bits) {
    CryptoPP::AutoSeededRandomPool rng;
    Integer e = 65537;
    Integer p, q, phi;
 
    do {
        p = random_prime(rng, bits / 2);
        do { q = random_prime(rng, bits / 2); } while (q == p);
        phi = (p - 1) * (q - 1);
    } while (Integer::Gcd(e, phi) != 1);   // e must be invertible mod phi
 
    RSAKey k;
    k.n = p * q;
    k.e = e;
    k.d = e.InverseMod(phi);
    return k;
}
 
// left-to-right square and multiply
// THIS IS THE VULNERABLE PART: the extra multiply only happens when the
// current bit of the exponent is 1, so run time depends on the secret exponent
Integer modexp_leak(const Integer& base, const Integer& exp, const Integer& n) {
    Integer result = 1;
    for (int i = (int)exp.BitCount() - 1; i >= 0; i--) {
        result = (result * result) % n;              // square, always happens
        if (exp.GetBit(i)) {
            result = (result * base) % n;            // multiply, only on a 1 bit
        }
    }
    return result;
}
 
Integer rsa_encrypt(const Integer& m, const RSAKey& k) {
    return modexp_leak(m, k.e, k.n);
}
 
Integer rsa_decrypt(const Integer& c, const RSAKey& k) {
    return modexp_leak(c, k.d, k.n);
}
 
// timings for single calls, same idea as time_verify in verifier.cpp
uint64_t time_modexp(const Integer& base, const Integer& exp, const Integer& n) {
    uint64_t start = __rdtsc();
    Integer r = modexp_leak(base, exp, n);
    uint64_t end = __rdtsc();
    return end - start;
}
 
uint64_t median(vector<uint64_t> v) {
    sort(v.begin(), v.end());
    return v[v.size() / 2];
}
 
int hamming_weight(const Integer& x) {
    int w = 0;
    for (unsigned i = 0; i < x.BitCount(); i++) if (x.GetBit(i)) w++;
    return w;
}
 
int main() {
    const int BITS = 1024;
    RSAKey k = keygen(BITS);
    CryptoPP::AutoSeededRandomPool rng;
 
    // 1. correctness check, decrypt(encrypt(m)) should give m back
    //    also compare against Crypto++'s own modexp
    cout << "correctness check:\n";
    bool ok = true;
    for (int t = 0; t < 20; t++) {
        Integer m(rng, 2, k.n - 1);
        Integer c = rsa_encrypt(m, k);
        Integer back = rsa_decrypt(c, k);
        if (back != m) ok = false;
        if (c != CryptoPP::ModularExponentiation(m, k.e, k.n)) ok = false;
    }
    cout << (ok ? "  all 20 round trips passed" : "  FAILED") << "\n\n";
 
    // 2. first look at the leak
    //    two exponents with the same bit length, one all zeros after the top
    //    bit (only squarings) and one all ones (a multiply on every bit)
    Integer e_low  = Integer::Power2(BITS - 1);       // 1000...0
    Integer e_high = Integer::Power2(BITS) - 1;       // 1111...1
    Integer base(rng, 2, k.n - 1);
 
    const int N = 2000;
    vector<uint64_t> t_low, t_high;
    for (int i = 0; i < N; i++) {
        t_low.push_back(time_modexp(base, e_low, k.n));
        t_high.push_back(time_modexp(base, e_high, k.n));
    }
 
    uint64_t m_low = median(t_low), m_high = median(t_high);
    cout << "exponent timing (" << N << " samples each, median cycles):\n";
    cout << "  weight " << hamming_weight(e_low)  << "   -> " << m_low  << "\n";
    cout << "  weight " << hamming_weight(e_high) << " -> " << m_high << "\n";
    cout << "  ratio high/low = " << (double)m_high / m_low << "\n";
 
    // 3. what the real private key looks like
    vector<uint64_t> t_d;
    for (int i = 0; i < N; i++) t_d.push_back(time_modexp(base, k.d, k.n));
    cout << "\nreal key d: weight " << hamming_weight(k.d) << " of " << k.d.BitCount()
         << " bits, median " << median(t_d) << " cycles\n";
 
    return 0;
}
