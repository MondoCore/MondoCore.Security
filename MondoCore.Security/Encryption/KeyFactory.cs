/***************************************************************************
 *                                                                          
 *    The MondoCore Libraries  							                    
 *                                                                          
 *        Namespace: MondoCore.Security.Encryption				            
 *             File: KeyFactory.cs			 		    		            
 *        Class(es): KeyFactory				           		                
 *          Purpose: Class for producing encryption keys                    
 *                                                                          
 *  Original Author: Jim Lightfoot                                          
 *    Creation Date: 19 Jan 2020                                            
 *                                                                          
 *   Copyright (c) 2025 - Jim Lightfoot, All rights reserved                
 *                                                                          
 *  Licensed under the MIT license:                                         
 *    http://www.opensource.org/licenses/mit-license.php                    
 *                                                                          
 ****************************************************************************/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MondoCore.Security.Encryption
{
    /****************************************************************************/
    /****************************************************************************/
    public class KeyFactory(IKeyStore        _decryptStore,
                            IKeyStore        _encryptStore,
                            EncryptionPolicy _policyTemplate,
                            TimeSpan         _expires)
               : IKeyFactory
    {   
        #region IKeyFactory

        /****************************************************************************/
        public async Task<IKey> GetDecryptionKey(Guid keyId)
        {
            var key = await _decryptStore.Get(keyId);

            if(key == null)
                throw new KeyNotFoundException();

            return key;
        }

        /****************************************************************************/
        public async Task<IKey> GetEncryptionKey()
        {
            // Get all keys in encryption store
            var key = await _encryptStore.GetUnexpired();

            if(key != null)
                return key;

            // Create a brand new key
            var newKey = new Key(_policyTemplate.Clone(_expires));

            newKey.Policy.IsReadOnly = true;

            // Save to both stores
            await _decryptStore.Add(newKey); // Make sure it's saved here successfully before putting it in encrypt store
            await _encryptStore.Add(newKey);

            return newKey;
        }

        #endregion

        #region Private

        private async Task RemoveKey(Guid id)
        {
            try
            {
                await _encryptStore.Remove(id);
            }
            catch
            {
                // Perhaps already removed by another thread/process
            }
        }
        #endregion
    }
}
