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

### Helper Methods 
  • keccakF: This method implements the Keccak-f permutation, which is the core 
    transformation for both SHA-3 and SHAKE. It performs the following steps: 
    o Theta: A step that mixes the columns of the state. 
    o Rho: A rotation of state values based on predefined constants. 
    o Pi: A permutation of the state values. 
    o Chi: A non-linear step that further mixes the state. 
    o Iota: Adds round constants to the state. 
  • ROTL64: A utility function that performs a bitwise left rotation on 64-bit values. This is 
    used for the Rho step and other rotations. 
  • longToBytes: Converts a 64-bit long value into an array of bytes (this method is partially 
    shown in the code and would be used to extract byte representations of the internal state).

### Additional Details 
  • Padding: Padding is applied to the data before it is processed by the sponge. This ensures 
    that the input data length is compatible with the Keccak-f function, which requires the 
    input to be a multiple of the rate. 
  • Security Level and Output Length: For SHAKE, the security level (suffix) defines the 
    number of bits for the security parameter. The SHAKE function also allows the user to 
    specify an arbitrary output length (L), making SHAKE more flexible compared to fixed
    length algorithms like SHA-3.
    
## Instructions 

The entire program is run from the terminal via command line arguments. 
  1. Hashing a File 
    This service computes a hash for a file using the SHA3/SHAKE hashing algorithm. You 
    can specify the hash security level (224, 256, 384, or 512). 
### Command: 
  java Main hash <security_level> <file_path> 
  • Arguments: 
    o <security_level>: One of 224, 256, 384, or 512. This defines the hash output size. 
    o <file_path>: Path to the file to be hashed. 
### Example: 
java Main hash 256 /path/to/file.txt 
  • Details: 
    o If no security level is specified, it defaults to 512. 
    o If the provided security level is invalid, it displays an error message. 
    o Computes the hash and outputs the result in hexadecimal format. 
  2. Message Authentication Code (MAC) Generation 
    This service generates a MAC using the SHA3/SHAKE algorithm, based on user
    provided inputs or a file. The MAC is used for ensuring data integrity and authentication. 
#### Command (using file input): 
  java Main mac <security_level> <password> <file_path> <output_length> 
#### Command (using user input): 
  java Main mac <security_level> <password> <output_length>
  • Arguments: 
    o <security_level>: Either 128 or 256, specifying the security level for the MAC 
      generation. 
    o <password>: The password (or secret key) used for the MAC. 
    o <file_path>: The file to use for generating the MAC (for file-based MAC 
      generation). 
    o <output_length>: The length (in bits) of the output MAC. 
• Example: 
  java Main mac 256 password /path/to/file.txt 128 
• Details: 
  o If using file input, it reads the file and generates the MAC. 
  o If using user input, it takes input from the terminal and generates the MAC. 
  3. File Encryption 
    This service encrypts a file using a symmetric encryption scheme (AES-like encryption) 
    with SHA3/SHAKE for key and nonce generation. 
#### Command: 
  java Main encrypt <password> <file_path> <output_file_path> 
    • Arguments: 
      o <password>: The passphrase used to generate the encryption key. 
      o <file_path>: Path to the file to be encrypted. 
      o <output_file_path>: Path to the output encrypted file (if not provided, defaults 
        to <file_path>.enc). 
    • Example: 
      java Main encrypt mysecretpassword /path/to/file.txt /path/to/output.enc 
    • Details: 
      o Generates a nonce and key using SHA3/SHAKE with the password. 
      o Encrypts the file contents using the XOR-based encryption. 
      o Computes a MAC of the encrypted content and appends it to the end of the 
        encrypted file for integrity verification.
  4. File Decryption 
    This service decrypts an encrypted file using the passphrase and ensures the integrity of 
    the decrypted content using the appended MAC. 
  #### Command: 
  java Main decrypt <password> <file_path> <output_file_path> 
    • Arguments: 
      o <password>: The passphrase used to generate the decryption key. 
      o <file_path>: Path to the encrypted file to be decrypted. 
      o <output_file_path>: Path to the output decrypted file (if not provided, it defaults 
        to removing .enc from the original file name). 
    • Example: 
        java Main decrypt mysecretpassword /path/to/file.enc /path/to/decrypted_file.txt 
    • Details: 
      o Verifies the integrity of the file by comparing the computed MAC to the one 
        stored in the encrypted file. 
      o Decrypts the file using the XOR operation, and writes the result to the output file. 
 5. Bytes-to-Hex Conversion (Helper Method) 
    This utility method converts a byte array into a hexadecimal string for readable output. 
      • Usage: This method is used internally in the program to print the result of the hashing, 
        MAC generation, and encryption operations in a human-readable format. 
  6. Main Program Logic 
      The main method handles the user input arguments and calls the appropriate function 
      based on the action requested. It supports the following actions: 
        • hash: Hashes a file using SHA3/SHAKE. 
        • mac: Generates a MAC based on file or user input. 
        • encrypt: Encrypts a file. 
        • decrypt: Decrypts a file. 
#### Error Handling 
  • FileNotFoundException: Occurs if the provided file path does not exist. 
  • IllegalArgumentException: Triggered for invalid input arguments, such as incorrect 
  security levels or negative MAC output lengths. 
  • IOException: Catches general I/O errors, such as issues reading from or writing to files. 
#### Example Use Cases: 
  #### Hashing: 
java Main hash 256 /home/user/data.txt 
    • Hash the file data.txt with a security level of 256 bits. 
    Generating MAC (User Input): 
    java Main mac 256 password 128 
    • Generate a MAC for the password password and user input with a length of 128 bits. 
### Generating MAC (File Input): 
java Main mac 256 password /home/user/data.txt 128 
    • Generate a MAC using the file data.txt and password password, with a length of 128 bits. 
### Encrypting a File: 
java Main encrypt mysecretpassword /home/user/data.txt /home/user/data.enc 
    • Encrypt data.txt using mysecretpassword, with the output written to data.enc. 
### Decrypting a File: 
java Main decrypt mysecretpassword /home/user/data.enc /home/user/decrypted.txt 
  • Decrypt data.enc using mysecretpassword, with the output written to decrypted.txt.  
