# Anti Brute Force - quantum resistance
## Key derivation function for defense against brute force attacks and protection from quantum computer attacks
## (Argon3 candidate)

This Key derivation function software is proposed as a valid alternative to Argon2, focusing on the simplicity of the solution and the easy understanding of the mechanisms adopted.

This project aims to create a simple solution, reduced to the minimum terms, understandable by anyone with a basic knowledge of cryptography.
Very complex, convoluted and daring systems generate many mechanisms in which dangerous pitfalls can hide. By reducing this process to the minimum terms with a minimalist solution to the problem, we wanted to create a system that is truly verifiable and testable by a large number of scholars interested in the topic. We have nominated this algorithm as Argon3 Candidate (improvement of Argon2 for the reasons described here).

This publication is an official presentation addressed to the scientific community

The source is published here: https://github.com/Andrea-Bruno/AntiBruteForce

## Key Derivation Functions - Concepts
In cryptography we often use passwords instead of binary keys, because passwords are easier to remember, to write down and can be shorter.
When a certain algorithm needs a key (e.g. for encryption or for digital signing) a key derivation function (password -> key) is needed.
We already noted that using SHA-256(password) as key-derivation is insecure! It is vulnerable to many attacks: brute-forcing, dictionary attacks, rainbow attacks and others, which may reverse the hash in practice and attacker can obtain the password.

A key derivation function (KDF) is a cryptographic algorithm that takes a secret key and generates a derived key, which can then be used in place of the original key in cryptographic systems. A KDF can help defend against attacks with quantum computers in a few ways:
1. **Increased key length:** A KDF can be used to increase the length of the secret key, making it more resistant to brute-force attacks. Quantum computers can perform certain calculations much faster than classical computers, so increasing the key length can help offset this advantage.
2. **Key stretching:** A KDF can also be used to slow down attackers by incorporating a "key stretching" mechanism. This involves repeatedly hashing the input key with a salt value, which can significantly increase the time required to perform a brute-force attack.
3. **Quantum-resistant algorithms:** Some KDFs are specifically designed to be resistant to attacks by quantum computers. For example, the NIST has been running a competition to standardize quantum-resistant KDFs, and several candidates have been identified.

It's important to note that while KDFs can help defend against attacks with quantum computers, they are not a silver bullet. Quantum computers are still in the early stages of development, and it's not yet clear how they will ultimately be used in practice. As a result, it's important to stay up-to-date with the latest developments in quantum cryptography and to follow best practices for securing cryptographic systems.

## Cryptographic Key Derivation Functions
PBKDF2, Bcrypt, Scrypt and Argon2 are significantly stronger key derivation functions and are designed to survive password guessing (brute force) attacks.
By design secure key derivation functions use salt (random number, which is different for each key derivation) + many iterations (to speed-down eventual password guessing process). This is a process, known as key stretching.
To calculate a secure KDF it takes some CPU time to derive the key (e.g. 0.2 sec) + some memory (RAM). Thus deriving the key is "computationally expensive", so password cracking will also be computationally expensive.
When a modern KDF function is used with appropriate config parameters, cracking passwords will be slow (e.g. 5-10 attempts per second, instead of thousands or millions attempts per second).
All of the above mentioned key-derivation algorithms (PBKDF2, Bcrypt, Scrypt and Argon2) are not patented and royalty-free for public use.

## Examples of use:

```csharp
using System.Diagnostics;
using System.Reflection;
using static AntiBruteForce.Perform;

const int MinLength = 8;

inputPassword:
Console.WriteLine("Create a password:");
string? password = Console.ReadLine();
if (password?.Length < MinLength)
{
    Console.WriteLine("The password must have at least " + MinLength + " characters");
    goto inputPassword;
}
Console.WriteLine("Computation in progress, please wait!");

// Function that updates the progression of the computation in the console
static void progressStatus(float progress) => Console.WriteLine((int)(progress * 100) + "%");

// Generate constant salt (recommended but not required)
var Salt = Assembly.GetEntryAssembly()?.GetTypes().First().GUID;

// Start the stopwatch to measure the time taken for the computation
var Stopwatch = new Stopwatch();
Stopwatch.Start();

// Compute the derivative with "Strong" level
var KeyDerivation = StringToKeyDerivation(password, (int)AntiBruteForceInteractions.Strong, 50, default, progressStatus, salt: Salt?.ToByteArray());

// Write the computation time
Stopwatch.Start();
Console.WriteLine("Computation time: " + Stopwatch.Elapsed);

// Write the derivation in hex format
Console.WriteLine("Key Derivation (hex) = " + BitConverter.ToString(KeyDerivation));
```

 - Test project
	- See the TestAntiBruteForce project included in the same repository as this library
	- Source code of the project: https://github.com/Andrea-Bruno/AntiBruteForce

 - Cross-platform dotnet encryption and decryption library
	- Use this algorithm to optionally prevent brute force attacks with encryption methods
	- Source code of the project: https://github.com/Andrea-Bruno/EncryptionAlgorithm

 - Passphrase Keeper
	- The seed that is entered is covered by brute force attacks via ParallelHash using entropy and several megabytes of memory
	- Source code of the project: https://github.com/Andrea-Bruno/PassphraseKeeper