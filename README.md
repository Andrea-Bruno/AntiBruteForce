# Anti Brute Force
## Key derivation function for defense against brute force attacks
## (Argon3 candidate)

This Key derivation function software is proposed as a valid alternative to Argon2, focusing on the simplicity of the solution and the easy understanding of the mechanisms adopted.

This project aims to create a simple solution, reduced to the minimum terms, understandable by anyone with a basic knowledge of cryptography.
Very complex, convoluted and daring systems generate many mechanisms in which dangerous pitfalls can hide. By reducing this process to the minimum terms with a minimalist solution to the problem, we wanted to create a system that is truly verifiable and testable by a large number of scholars interested in the topic. We have nominated this algorithm as Argon3 Candidate (improvement of Argon2 for the reasons described here).

This publication is an official presentation addressed to the scientific community

The source is published here: https://github.com/Andrea-Bruno/AntiBruteForce

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

// Generate an entropy constant (recommended but not required)
var Entropy = Assembly.GetEntryAssembly()?.GetTypes().First().GUID;

// Start the stopwatch to measure the time taken for the computation
var Stopwatch = new Stopwatch();
Stopwatch.Start();

// Compute the derivative with "Strong" level
var KeyDerivation = StringToKeyDerivation(password, (int)AntiBruteForceInteractions.Strong, 50, default, progressStatus, entropy: Entropy?.ToByteArray());

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