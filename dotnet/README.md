# DeRec Cryptography in dotnet

The dotnet uses the derec-crypt-core-grpc server

DeRec is using cyrptography primitives coded in rust and grpc connection can provide this primitives in the c# application.

## Init grpc server
```
docker run -p 50051:50051 scholtz2/derec-crypto-core-grpc
```

## Create grpc client in c#

Generate the grpc client. Make sure in csproj you have this files and Protos/service.proto available.

```
		<PackageReference Include="Grpc.AspNetCore" Version="2.32.0" />
		<PackageReference Include="Google.Protobuf" Version="3.28.3" />
		<PackageReference Include="Grpc.Net.Client" Version="2.66.0" />
		<PackageReference Include="Grpc.Tools" Version="2.40.0">
			<IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
			<PrivateAssets>all</PrivateAssets>
		</PackageReference>
		<PackageReference Include="Microsoft.VisualStudio.Azure.Containers.Tools.Targets" Version="1.21.0" />
```

Create client

```
    using var channel = GrpcChannel.ForAddress("http://localhost:50051");
    var client = new DerecCrypto.DeRecCryptographyService.DeRecCryptographyServiceClient(channel);
```

## Sign message & Verify

```
    var signed = await client.SignSignAsync(new DerecCrypto.SignSignRequest() { Message = Google.Protobuf.ByteString.CopyFromUtf8("Test"), SecretKey = keys.PrivateKey });
    var verify = await client.SignVerifyAsync(new DerecCrypto.SignVerifyRequest() { Message = Google.Protobuf.ByteString.CopyFromUtf8("Test"), PublicKey = keys.PublicKey, Signature = signed.Signature });

    Console.WriteLine("Signature: " + signed.Signature.ToBase64());
    Console.WriteLine("verify: " + verify);
```

## Encrypt & Decrypt

```
    var ekeys = await client.EncryptGenerateEncryptionKeyAsync(new DerecCrypto.EncryptGenerateEncryptionKeyRequest() { });
    var encrypted = await client.EncryptEncryptAsync(new DerecCrypto.EncryptEncryptRequest() { Message = Google.Protobuf.ByteString.CopyFromUtf8("Test"), PublicKey = ekeys.PublicKey });
    var decrypted = await client.EncryptDecryptAsync(new DerecCrypto.EncryptDecryptRequest() { Ciphertext = encrypted.Ciphertext, SecretKey = ekeys.PrivateKey });

    Console.WriteLine("Decrypted text: " + decrypted.Message.ToStringUtf8());
```

## Split to shares & Recover

```
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
```
