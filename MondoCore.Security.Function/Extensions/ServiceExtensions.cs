using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

using MondoCore.Azure.KeyVault;
using MondoCore.Security.Encryption;
using MondoCore.Common;

namespace MondoCore.Security.Function
{
    public static class ServiceExtensions
    {
        public static IServiceCollection AddEncryption(this IServiceCollection services)
        {
            return services.KeyStoreStrategy();
        }        
        
        public static IServiceCollection KeyStoreStrategy(this IServiceCollection services)
        {
            var config           = services.BuildServiceProvider().GetRequiredService<IConfiguration>()!;
            var encryptStore     = new KeyVaultBlobStore(new Uri(config["KeyvaultUri"]!), "Encrypt-");
            var decryptStore     = new KeyVaultBlobStore(new Uri(config["KeyvaultUri"]!), "Decrypt-");
            var encryptKeyStore  = new KeyStore(encryptStore, new PassThruEncryptor());
            var decryptKeyStore  = new KeyStore(decryptStore, new PassThruEncryptor());
            var keyFactory       = new KeyFactory(decryptKeyStore, encryptKeyStore, new EncryptionPolicy(), TimeSpan.FromDays(90));
            var cache            = new KeyFactoryCache(keyFactory, new MemoryCache(), 30);
            var encryptorFactory = new SymmetricEncryptorFactory();

            services.AddSingleton<IEncryptor>(new IndividuallyWrappedEncryptor(encryptorFactory, cache));
            return services;
        }
    }
}
