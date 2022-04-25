using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

using Org.BouncyCastle.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;

namespace EmailCertificateGenerator
{
    public class Certificates
    {
        const string signatureAlgorithm = "SHA256WithRSA";

        public static X509Certificate2 GenerateCertificate(string email, string company, string password)
        {

            SecureRandom random = new SecureRandom();
            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();

            BigInteger serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            SubjectAlternativeNameBuilder builder = new SubjectAlternativeNameBuilder();
            builder.AddEmailAddress(email);
            builder.Build(critical: true);
            
            certificateGenerator.SetIssuerDN(new X509Name($"C=NL, O=Email Certificate Generator, CN=Email Certificate Generator"));
            certificateGenerator.SetSubjectDN(new X509Name($"C=NL, O={company}, CN={email}"));
            certificateGenerator.SetNotBefore(DateTime.UtcNow.Date);
            certificateGenerator.SetNotAfter(DateTime.UtcNow.Date.AddYears(5));
            certificateGenerator.AddExtension(X509Extensions.KeyUsage, false, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
            certificateGenerator.AddExtension(builder.Build().Oid.Value.ToString(), false,  builder.Build().RawData);
            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false, new ExtendedKeyUsage(KeyPurposeID.IdKPEmailProtection, KeyPurposeID.IdKPClientAuth));

            const int strength = 4096;
            var keyGenerationParameters = new KeyGenerationParameters(random, strength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            var issuerKeyPair = subjectKeyPair;
            var signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issuerKeyPair.Private);
            var bouncyCert = certificateGenerator.Generate(signatureFactory);

            X509Certificate2 certificate = null;

            Pkcs12Store store = new Pkcs12StoreBuilder().Build();
            store.SetKeyEntry($"{email}", new AsymmetricKeyEntry(subjectKeyPair.Private), new[] { new X509CertificateEntry(bouncyCert) });

            using (var ms = new System.IO.MemoryStream())
            {
                store.Save(ms, password.ToCharArray(), random);
                certificate = new X509Certificate2(ms.ToArray(), password, X509KeyStorageFlags.Exportable);
            }

            return certificate;
        }

        public static void SaveCertificate(X509Certificate2 certificate)
        {
            var userStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            userStore.Open(OpenFlags.ReadWrite);
            userStore.Add(certificate);
            userStore.Close();
        }
    }
}
