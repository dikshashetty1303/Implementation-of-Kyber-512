# Kyber512 on STM32F411CEU6: A Post-Quantum Cryptographic Implementation

This repository contains a practical and optimized implementation of the Kyber512 algorithm — a lattice-based Key Encapsulation Mechanism (KEM) selected by NIST for post-quantum cryptographic standardization — on the STM32F411CEU6 microcontroller, which features an ARM Cortex-M4 core.

## 🔐 About Kyber512

Kyber512 is part of the CRYSTALS (Cryptographic Suite for Algebraic Lattices) family and offers 128-bit post-quantum security. It is based on the hardness of the Module Learning With Errors (MLWE) problem, making it resilient against quantum attacks unlike classical schemes such as RSA or ECC.

## 🎯 Objective

This project demonstrates the feasibility of deploying post-quantum cryptography on resource-constrained embedded platforms. The implementation aims to:

- Integrate full Kyber512 functionality (KeyGen, Encapsulation, Decapsulation)
- Optimize for speed and memory on STM32F4
- Validate outputs via UART
- Evaluate cycle count and execution time for all operations

## ⚙️ Platform Details

- **Microcontroller**: STM32F411CEU6
- **Core**: ARM Cortex-M4 (100 MHz)
- **Toolchain**: STM32CubeIDE
- **Communication**: UART (PuTTY for log capture)

## 🧠 Features

- Full native C implementation of:
  - Keccak-f[1600] permutation
  - SHAKE128 absorb/squeeze
  - Number Theoretic Transform (NTT) and Inverse NTT
  - Key encapsulation flow
- Static memory allocation to avoid runtime failures
- Precomputed zeta tables for optimized NTT operations
- Serial output logging via UART for verification
- Custom ChaCha20-based PRNG (due to absence of hardware RNG)

## 📊 Performance Summary

| Operation      | STM32F411CEU6 (This Work) | Cycles     | Time (µs) |
|----------------|----------------------------|------------|-----------|
| Key Generation | ✅ Completed                | 659,272    | 41,204    |
| Encapsulation  | ✅ Completed                | 429,144    | 26,821    |
| Decapsulation  | ✅ Completed                | 380,092    | 23,755    |
| **Total**      |                            | 1,468,508  | 91,780    |

- ~4.5% fewer cycles compared to the official Kyber reference on x86
- Entire execution completed in under 100 ms on an embedded system

## 🧪 Validation

- Shared secrets validated via UART
- Intermediate buffers monitored to confirm NTT correctness and symmetric encryption
- No dynamic memory or interrupts used, ensuring timing consistency

## 🧱 Why Kyber512?

Kyber512 was chosen over Kyber768 and Kyber1024 for:
- Balanced security (128-bit post-quantum)
- Lower computational overhead
- Smaller key/ciphertext sizes
- Suitability for embedded and IoT devices

## 📚 Reference

The implementation draws from the official [PQClean Kyber Reference](https://github.com/PQClean/PQClean) and NIST’s submission by the CRYSTALS team. Cryptographic primitives, zeta tables, and Keccak operations were adapted and integrated into a single embedded project in STM32CubeIDE.

## 🛠️ Build Instructions

1. Clone the repository and open in **STM32CubeIDE**
2. Connect STM32F411CEU6 via ST-Link or USB-UART adapter
3. Flash the project and open a serial terminal (e.g., PuTTY) at 115200 baud
4. Monitor output for KeyGen, Encapsulation, and Decapsulation results

## 💡 Future Scope

- Add IND-CCA secure variants using full API
- Hardware acceleration
- Integration with automotive ECUs and IoT bootloaders
- Enhanced PRNG using TRNG or external entropy source
- Real-time tamper detection and side-channel resistance

Other Team Members
Sanjana V Hosmath
Pramod Chalageri
Haripriya P M
Rashmi V

---


