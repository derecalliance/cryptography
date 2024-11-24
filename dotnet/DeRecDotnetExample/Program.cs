
using Grpc.Net.Client;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using System.Text;

namespace DeRec
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            // run gprc server first : docker run -p 50051:50051 scholtz2/derec-crypto-core-grpc

            Console.WriteLine("Hello Decentralized Recovery!");

            using var channel = GrpcChannel.ForAddress("http://localhost:50051");
            var client = new DerecCrypto.DeRecCryptographyService.DeRecCryptographyServiceClient(channel);
            var keys = await client.SignGenerateSigningKeyAsync(new DerecCrypto.SignGenerateSigningKeyRequest() { });

            var signed = await client.SignSignAsync(new DerecCrypto.SignSignRequest() { Message = Google.Protobuf.ByteString.CopyFromUtf8("Test"), SecretKey = keys.PrivateKey });
            var verify = await client.SignVerifyAsync(new DerecCrypto.SignVerifyRequest() { Message = Google.Protobuf.ByteString.CopyFromUtf8("Test"), PublicKey = keys.PublicKey, Signature = signed.Signature });

            Console.WriteLine("Signature: " + signed.Signature.ToBase64());
            Console.WriteLine("verify: " + verify);

            var ekeys = await client.EncryptGenerateEncryptionKeyAsync(new DerecCrypto.EncryptGenerateEncryptionKeyRequest() { });
            var encrypted = await client.EncryptEncryptAsync(new DerecCrypto.EncryptEncryptRequest() { Message = Google.Protobuf.ByteString.CopyFromUtf8("Test"), PublicKey = ekeys.PublicKey });
            var decrypted = await client.EncryptDecryptAsync(new DerecCrypto.EncryptDecryptRequest() { Ciphertext = encrypted.Ciphertext, SecretKey = ekeys.PrivateKey });

            Console.WriteLine("Decrypted text: " + decrypted.Message.ToStringUtf8());

            using RandomNumberGenerator rng = RandomNumberGenerator.Create();
            byte[] randomBytes = new byte[16];
            rng.GetBytes(randomBytes);

            var shares = await client.VSSShareAsync(new DerecCrypto.VSSShareRequest()
            {
                Message = Google.Protobuf.ByteString.CopyFromUtf8("Secret msg"),
                T = 3,
                N= 5,
                Rand = Google.Protobuf.ByteString.CopyFrom(randomBytes)
            });

            var request = new DerecCrypto.VSSRecoverRequest();
            request.Shares.AddRange(shares.Shares);
            var recovery = await client.VSSRecoverAsync(request);

            Console.WriteLine("Recovered text: " + recovery.Message.ToStringUtf8());

        }
    }
}
