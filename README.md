Post-quantum cryptography has gained significant
 attention in information security because of the increasing threat
 that quantum computing poses to traditional cryptographic
 algorithms such as RSA and ECC. Kyber is a lattice-based
 key encapsulation mechanism (KEM) selected by the National
 Institute of Standards and Technology (NIST) for standardization
 as part of its post-quantum initiative. This work presents a
 practical and complete implementation of the Kyber512 algo
rithm on the STM32F411CEU6, an ARM Cortex-M4 based
 microcontroller, highlighting the feasibility of deploying post
quantum cryptography on constrained embedded platforms.
 The implementation, developed entirely within STM32CubeIDE,
 integrates all critical cryptographic functions such as key gen
eration, encapsulation, decapsulation, and serial communication
 via UART. UART communication was used for result verification,
 and the implementation was evaluated based on execution time
 and cycle counts.The proposed work was completed within a
 total of 1,468,508 cycles approximately.This is approximately
 4.5% fewer cycles than the official Kyber512 reference, with a
 combined execution time of 91,780 µs on a 100MHz Cortex-M4
 processor.The implementation can be further adapted for secure
 communication in automotive ECUs, enabling post-quantum
 protection for vehicle-to-vehicle (V2V) and in-vehicle networks
