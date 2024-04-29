﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Threading;

namespace AntiBruteForce
{
    static public class Perform
    {

        /// <summary>
        /// Settings for protection against brute force attacks
        /// </summary>
        public enum AntiBruteForceInteractions
        {
            /// <summary>
            /// Brute force attack protection is not enabled
            /// </summary>
            Disabled = 0,
            /// <summary>
            /// Provides protection from standard brute force attacks
            /// </summary>
            Standard = 2000000,
            /// <summary>
            /// Strong protection against brute force attacks, an attack attempt would require a computational cloud
            /// </summary>
            Strong = 100000000,
            /// <summary>
            /// Useful for all scenarios in which the security level must be military (the computational force is very high and encryption/decryption will take a long time
            /// </summary>
            Military = 200000000
        }

        private const int DefaultThreads = 8;

        /// <summary>
        /// Support for anti brute force attack!
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="interactions">Number of iterations (The number of iterations must be greater than memory usage in bytes / 32 as they must completely fill the memory)</param>
        /// <param name="memoryMegabyte">Value of memory used for each individual thread: Forces the algorithm to require a large amount of memory (This value in bytes must be less than the number of interactions X 32, as the interactions must be able to completely fill the memory)</param>
        /// <param name="threads">Number of threads to use</param>
        /// <param name="refreshProgressBar">Action with a Float parameter useful for updating a progress in the calling application. The Float value returned ranges from 0 to 1 and represents progression.</param>
        /// <param name="refreshMs">How often to call the refresh ProgressBar function to update the progress bar (milliseconds)</param>
        /// <param name="entropy">If set, it adds an entropy to the data for which you want to compute the recursive hash: This will obviously change the result.</param>
        /// <returns>hash obtained following the iterations</returns>
        public static byte[] ParallelHash(byte[] data, int interactions = (int)AntiBruteForceInteractions.Standard, int memoryMegabyte = 0, int threads = DefaultThreads, Action<float> refreshProgressBar = null, int refreshMs = 5000, byte[] entropy = null)
        {
            if (threads == default)
                threads = DefaultThreads;
            if (entropy != null)
                data = data.Concat(entropy);
            var seeds = new byte[threads][];
            var sha256 = SHA256.Create();
            for (byte i = 0; i < threads; i++)
            {
                seeds[i] = sha256.ComputeHash(new byte[i].Concat(data));
            }
            var hashes = new byte[threads][];
#if DEBUG
            var x = new Stopwatch();
            x.Start();
#endif
            var functions = new List<Func<float>>();
            Timer RefreshProgressTimer = null;
            if (refreshProgressBar != null)
            {
                float getInteractionProgress()
                {
                    float total = 0;
                    float n = 0;
                    foreach (var func in functions.ToArray())
                    {
                        total += func();
                        n++;
                    }
                    return n == 0 ? 0 : total / n;
                };
                RefreshProgressTimer = new Timer((obj) => refreshProgressBar(getInteractionProgress()), null, refreshMs, refreshMs);
            }

            Parallel.For(0, threads, thread => hashes[thread] = RecursiveHash(seeds[thread], interactions, memoryMegabyte, functions));
            var result = new byte[hashes[0].Length];
            int progress = 0;
            for (progress = 0; progress < threads; progress++)
            {
                result = Xor(result, hashes[progress]);
            }
            RefreshProgressTimer?.Change(Timeout.Infinite, Timeout.Infinite);
#if DEBUG
            x.Stop();
            Debug.WriteLine(x.Elapsed);
#endif
            return result;
        }

        private static byte[] Concat(this byte[] thisArray, byte[] array)
        {
            var result = new byte[thisArray.Length + array.Length];
            Buffer.BlockCopy(thisArray, 0, result, 0, thisArray.Length);
            Buffer.BlockCopy(array, 0, result, thisArray.Length, array.Length);
            return result;
        }
        /// <summary>
        /// XOR tea two arrays
        /// </summary>
        /// <param name="key">The KEY</param>
        /// <param name="PAN">The PAN</param>
        /// <returns>The result of the binary XOR between the two input arrays</returns>
        public static byte[] Xor(byte[] key, byte[] PAN)
        {
            byte[] result = new byte[key.Length];
            for (int i = 0; i < key.Length; i++)
            {
                result[i] = (byte)(key[i] ^ PAN[i]);
            }
            return result;
        }

        private static byte[] RecursiveHash(byte[] data, int interactions, int memoryMegabyte = 0, List<Func<float>> progressList = null)
        {
            var sha256 = SHA256.Create();
            byte[] hash = data;
            int progress = 0;
            if (progressList != null)
            {
                lock (progressList)
                {
                    Func<float> getInteractionProgress = () => progress / (float)interactions;
                    progressList.Add(getInteractionProgress);
                }
            }
            if (memoryMegabyte > 0)
            {
                var memoryBytes = memoryMegabyte * 1000000;
                if (memoryBytes < (interactions * 32))
                {
                    throw new Exception("Insufficient number of interactions to fill memory! Each interaction fills 32 bytes. Memory must be greater than " + interactions * 32 + "bytes. Increase the memoryMegabyte value!");
                }
                var memory = new byte[memoryBytes];
                var memOffset = 0;
                for (progress = 0; progress < interactions; progress++)
                {
                    hash = sha256.ComputeHash(hash);
                    Buffer.BlockCopy(hash, 0, memory, memOffset, 32);
                    memOffset += 32;
                    if (memOffset >= memoryBytes || progress == interactions -1)
                    {
                        hash = sha256.ComputeHash(memory);
                        memOffset = 0;                       
                    }
                }
                hash = sha256.ComputeHash(memory);
            }
            for (progress = 0; progress < interactions; progress++)
            {
                hash = sha256.ComputeHash(hash);
            }
            return hash;
        }

    }
}
