using System;
using System.Threading.Tasks;

using MondoCore.Common;

namespace MondoCore.Security.Encryption
{
    public class KeyFactoryCache(IKeyFactory source, ICache cache, int decryptionExpires) : IKeyFactory
    {
        #region IKeyFactory

        public async Task<IKey> GetDecryptionKey(Guid keyId)
        {
            return await cache.Get<IKey>(keyId.ToString(), async ()=>
            {
               return await source.GetDecryptionKey(keyId);
            },
            tsExpires: TimeSpan.FromDays(decryptionExpires)
            );
        }

        public async Task<IKey> GetEncryptionKey()
        {
            IKey? key = null;

            return await cache.Get<IKey>("encrypt", async ()=>
            {
               return key = await source.GetEncryptionKey();
            },
            dtExpires: key?.Policy?.Expires ?? DateTime.MaxValue
            );
        }

        #endregion
    }
}
