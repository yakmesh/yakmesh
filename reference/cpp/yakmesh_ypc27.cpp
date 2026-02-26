#include <iostream>
#include <vector>
#include <array>
#include <cstdint>
#include <numeric>
#include <iomanip>

// ============================================================================
// YAKMESH CORE: YPC-27 (27-Trit Polynomial Checksum)
// Ring: R = Z[x] / (x^27 - 1) mod 3
// Coefficients: Balanced Ternary {-1, 0, 1}
// ============================================================================

namespace yakmesh {

    constexpr int N = 27;

    // Balanced Ternary Trit: Can be -1, 0, or 1
    using Trit = int8_t;

    struct Poly27 {
        std::array<Trit, N> coeffs;

        Poly27() { coeffs.fill(0); }

        // Print representation (e.g., + - 0 + ...)
        void print() const {
            std::cout << "[ ";
            for (int i = 0; i < N; ++i) {
                if (coeffs[i] == 1) std::cout << "+";
                else if (coeffs[i] == -1) std::cout << "-";
                else std::cout << "0";
            }
            std::cout << " ]" << std::endl;
        }
    };

    // ------------------------------------------------------------------------
    // MATH HELPERS (Mod 3)
    // ------------------------------------------------------------------------

    // Canonical reduction to balanced ternary {-1, 0, 1}
    // (val % 3) -> {0, 1, 2} -> {-1, 0, 1}
    constexpr Trit reduce3(int val) {
        int r = val % 3;
        if (r < 0) r += 3; // Handle C++ negative modulo behavior
        // Map {0, 1, 2} => {0, 1, -1}
        return (r == 2) ? -1 : static_cast<Trit>(r);
    }

    // Polynomial Addition: A + B mod 3
    Poly27 add(const Poly27& a, const Poly27& b) {
        Poly27 res;
        for (int i = 0; i < N; ++i) {
            res.coeffs[i] = reduce3(a.coeffs[i] + b.coeffs[i]);
        }
        return res;
    }

    // Polynomial Multiplication: A * B mod (x^27 - 1) mod 3
    // Since N=27 is small, we use direct convolution O(N^2).
    // For x^N - 1, index wraps simply: (i + j) % N
    Poly27 multiply(const Poly27& a, const Poly27& b) {
        Poly27 res;
        for (int i = 0; i < N; ++i) {
            for (int j = 0; j < N; ++j) {
                int idx = (i + j) % N; // Cyclic convolution
                int prod = a.coeffs[i] * b.coeffs[j];
                // Accumulate without immediate reduction for speed (optional)
                // But doing it step-wise keeps ints small.
                int current = res.coeffs[idx] + prod;
                res.coeffs[idx] = reduce3(current);
            }
        }
        return res;
    }

    // ------------------------------------------------------------------------
    // DATA CONVERSION
    // ------------------------------------------------------------------------

    // Convert raw Bytes to Trits (5 Trits per Byte)
    // 3^5 = 243, so we can map 0-242 exactly.
    // Values 243-255 are wrapped (mod 243) to avoid bias, or just simple mod 3 loop.
    std::vector<Trit> bytesToTrits(const std::vector<uint8_t>& data) {
        std::vector<Trit> trits;
        trits.reserve(data.size() * 5);

        for (uint8_t b : data) {
            int val = static_cast<int>(b);
            // Extract 5 trits (Little Endian)
            for (int k = 0; k < 5; ++k) {
                trits.push_back(reduce3(val % 3));
                val /= 3;
            }
        }
        return trits;
    }

    // ------------------------------------------------------------------------
    // CHECKSUM ENGINE
    // ------------------------------------------------------------------------

    class YPC27Checksum {
        Poly27 state;
        Poly27 seed; // The "Challenge" or "Key" polynomial

    public:
        // Initialize with a "Seed" (e.g., derived from PeerID or Network Key)
        YPC27Checksum(const Poly27& network_seed) : seed(network_seed) {
            state.coeffs.fill(0);
        }

        // Rolling Update: State = (State + Input_Poly) * Seed
        // This makes order significant and diffuses the bits across the lattice.
        void update(const std::vector<uint8_t>& data) {
            std::vector<Trit> raw_trits = bytesToTrits(data);

            // Process in chunks of N (27) trits
            size_t num_chunks = (raw_trits.size() + N - 1) / N;

            for (size_t k = 0; k < num_chunks; ++k) {
                Poly27 chunk_poly;
                for (int i = 0; i < N; ++i) {
                    size_t src_idx = k * N + i;
                    if (src_idx < raw_trits.size()) {
                        chunk_poly.coeffs[i] = raw_trits[src_idx];
                    } else {
                        chunk_poly.coeffs[i] = 0; // Padding
                    }
                }

                // The Core "Lattice" Mix: S_new = (S_old + M) * G
                Poly27 sum = add(state, chunk_poly);
                state = multiply(sum, seed);
            }
        }

        Poly27 digest() const {
            return state;
        }
    };
}

// ----------------------------------------------------------------------------
// TEST HARNESS
// ----------------------------------------------------------------------------
int main() {
    using namespace yakmesh;

    // 1. Define a Network Seed (e.g., The "Yakmesh Gen 1" constant)
    // In production, this would be hardcoded or derived from the PeerID.
    Poly27 seed;
    for(int i=0; i<N; ++i) seed.coeffs[i] = (i % 3 == 0) ? 1 : (i % 3 == 1) ? -1 : 0;

    std::cout << "Yakmesh YPC-27 Initialization..." << std::endl;
    std::cout << "Seed Poly: "; seed.print();

    // 2. Create the Checksum Engine
    YPC27Checksum hasher(seed);

    // 3. Simulate a Packet (Hello World)
    std::string msg = "Yakmesh_Packet_v1:Keep_It_Ternary";
    std::vector<uint8_t> packet(msg.begin(), msg.end());

    // 4. Update
    hasher.update(packet);

    // 5. Final Digest
    Poly27 checksum = hasher.digest();

    std::cout << "\nInput Data: \"" << msg << "\"" << std::endl;
    std::cout << "YPC-27 Checksum: ";
    checksum.print();

    // Verification Logic:
    // A receiver does the same. If (Checksum_Calc - Checksum_Header) != 0, drop packet.
    return 0;
}