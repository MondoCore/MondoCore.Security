using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

using MondoCore.Common;

namespace MondoCore.Security.Encryption
{
    /****************************************************************************/
    /****************************************************************************/
    public class IndividuallyWrappedEncryptor(IEncryptorFactory encryptorFactory, IKeyFactory keyFactory) : IEncryptor
    {
        public EncryptionPolicy Policy => throw new NotSupportedException();
        private const int GuidSize = 16;

        /****************************************************************************/
        public async Task<byte[]> Decrypt(byte[] aEncrypted, int offset = 0)
        {
            var keyBytes  = aEncrypted.DeepClone(offset, GuidSize); 
            var keyId     = new Guid(keyBytes!);
            var key       = await keyFactory.GetDecryptionKey(keyId);
            var encryptor = encryptorFactory.Create(key);
            
            return await encryptor.Decrypt(aEncrypted, offset + GuidSize);
        }

        /****************************************************************************/
        public async Task Decrypt(Stream input, Stream output)
        {
            var keyBytes  = new byte[GuidSize];

            input.Read(keyBytes, 0, GuidSize);

            var keyId     = new Guid(keyBytes);
            var key       = await keyFactory.GetEncryptionKey();
            var encryptor = encryptorFactory.Create(key);
            
            await encryptor.Decrypt(input, output);
        }

        /****************************************************************************/
        public async Task<byte[]> Encrypt(byte[] aData)
        {
            var key       = await keyFactory.GetEncryptionKey();
            var encryptor = encryptorFactory.Create(key);
            var result    = await encryptor.Encrypt(aData);
            
            return result.Prepend(key.Id.ToByteArray());
        }

        /****************************************************************************/
        public async Task Encrypt(Stream input, Stream output)
        {
            var key       = await keyFactory.GetEncryptionKey();
            var encryptor = encryptorFactory.Create(key);
            
            output.Write(key.Id.ToByteArray(), 0, GuidSize);

            await encryptor.Encrypt(input, output);
        }
    }
}
