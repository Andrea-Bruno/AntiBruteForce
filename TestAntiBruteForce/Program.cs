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
