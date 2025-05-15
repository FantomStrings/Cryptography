# SHA3SHAKE

## Description

The SHA3SHAKE class is a Java implementation of the SHA-3 and SHAKE 
cryptographic hash functions based on the Keccak algorithm. It uses the sponge construction, 
where data is absorbed and then squeezed to produce the final output. This class allows for both 
SHA-3 (with specific bit lengths like 224, 256, 384, and 512) and SHAKE (with variable output 
lengths of 128 or 256). Below is a detailed breakdown of the program. There are no known 
shortcomings at this time other than to say that the contents of the encrypted and decrypted files 
are not echoed to the terminal..

### Constants

  #### The program uses several constant arrays and variables for internal operations: 
  1. KECCAKF_ROTC: This array stores the rotation constants used in the Rho step of the 
  Keccak-f permutation. 
  2. KECCAKF_RNDC: This array contains the round constants used in the Iota step of the 
  Keccak-f permutation. 
  3. KECCAKF_ROUNDS: The number of rounds (24) to run the Keccak-f permutation. 
  4. SIZE_STATE: Defines the total size of the internal state in bits (1600 bits). 
  5. MASK: Used for byte-to-bit conversion (masking the least significant byte). 
  6. cap: The capacity of the sponge, in bits. 
  7. byte_rate: The rate of the sponge, in bytes. 
  8. pt: Position in the sponge, in bits. 
  9. state: The internal state used by the Keccak-f permutation, represented as a 5x5 matrix of 
  64-bit words (long[][]).

### Non-Static Methods 

  #### Constructor 
• The default constructor public SHA3SHAKE() initializes an empty state, with no specific 
  functionality implemented here beyond setup for later use. 
  
  #### Initialization (init) 
• The init(int suffix) method initializes the sponge function with the given suffix (which 
  corresponds to the desired output length for SHA-3 or SHAKE). It sets up 
  the cap, byte_rate, and state properties. 
  
  #### Absorbing Data (absorb) 
• The absorb methods take input data (in byte form) and add it to the internal state of the 
  sponge. They update the sponge’s state by XOR'ing the data into the state matrix. The 
  method can process data from any starting position (pos) and for any length (len). If the 
  sponge reaches its byte rate during absorption, it performs a Keccak-f permutation. 
  
  #### Squeezing Data (squeeze) 
• The squeeze methods extract output from the sponge. After applying padding (if needed), 
  the sponge is "squeezed" to generate the desired number of bytes (len), which are written 
  into the out buffer. 
The method can be called repeatedly to produce arbitrary-length outputs. It internally invokes 
Keccak-f to permute the state after each extraction. 

#### Digesting Data (digest) 
• The digest methods produce a fixed-length hash from the sponge, based on the padding 
and absorption. The resulting hash is output in the specified buffer size. 

#### SHA3 and SHAKE Static Methods 
• SHA3: This method is used to compute a SHA-3 hash with a specific output length 
(suffix). It absorbs input data and outputs the computed hash. 
• SHAKE: Similar to SHA3, this method computes the SHAKE hash with a variable 
output length (L). It uses the squeeze method to produce the hash.
  
