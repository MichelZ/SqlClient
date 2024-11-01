using System;
using System.Buffers;
using System.Diagnostics;
using Microsoft.Data.Common;
using System.Threading.Tasks;

#nullable enable

namespace Microsoft.Data.SqlClient
{
    internal partial class TdsParser
    {
        internal void ProcessSSPI(int receivedLength)
        {
            Debug.Assert(_authenticationProvider is not null);

            SniContext outerContext = _physicalStateObj.SniContext;
            _physicalStateObj.SniContext = SniContext.Snix_ProcessSspi;
            // allocate received buffer based on length from SSPI message
            byte[] receivedBuff = ArrayPool<byte>.Shared.Rent(receivedLength);

            // read SSPI data received from server
            Debug.Assert(_physicalStateObj._syncOverAsync, "Should not attempt pends in a synchronous call");
            TdsOperationStatus result = _physicalStateObj.TryReadByteArray(receivedBuff, receivedLength);
            if (result != TdsOperationStatus.Done)
            {
                throw SQL.SynchronousCallMayNotPend();
            }

            // allocate send buffer and initialize length
            byte[] rentedSendBuff = ArrayPool<byte>.Shared.Rent((int)_authenticationProvider!.MaxSSPILength);
            byte[] sendBuff = rentedSendBuff; // need to track these separately in case someone updates the ref parameter
            uint sendLength = _authenticationProvider.MaxSSPILength;

            // make call for SSPI data
            _authenticationProvider.SSPIData(receivedBuff.AsMemory(0, receivedLength), ref sendBuff, ref sendLength, _sniSpnBuffer);

            // DO NOT SEND LENGTH - TDS DOC INCORRECT!  JUST SEND SSPI DATA!
            _physicalStateObj.WriteByteArray(sendBuff, (int)sendLength, 0);

            ArrayPool<byte>.Shared.Return(rentedSendBuff, clearArray: true);
            ArrayPool<byte>.Shared.Return(receivedBuff, clearArray: true);

            // set message type so server knows its a SSPI response
            _physicalStateObj._outputMessageType = TdsEnums.MT_SSPI;

            // send to server
            _physicalStateObj.WritePacket(TdsEnums.HARDFLUSH);
            _physicalStateObj.SniContext = outerContext;
        }

#nullable disable

        internal void TdsLogin(
            SqlLogin rec,
            TdsEnums.FeatureExtension requestedFeatures,
            SessionData recoverySessionData,
            FederatedAuthenticationFeatureExtensionData fedAuthFeatureExtensionData,
            SqlConnectionEncryptOption encrypt)
        {
            _physicalStateObj.SetTimeoutSeconds(rec.timeout);

            Debug.Assert(recoverySessionData == null || (requestedFeatures & TdsEnums.FeatureExtension.SessionRecovery) != 0, "Recovery session data without session recovery feature request");
            Debug.Assert(TdsEnums.MAXLEN_HOSTNAME >= rec.hostName.Length, "_workstationId.Length exceeds the max length for this value");

            Debug.Assert(!(rec.useSSPI && _connHandler._fedAuthRequired), "Cannot use SSPI when server has responded 0x01 for FedAuthRequired PreLogin Option.");
            Debug.Assert(!rec.useSSPI || (requestedFeatures & TdsEnums.FeatureExtension.FedAuth) == 0, "Cannot use both SSPI and FedAuth");
            Debug.Assert(fedAuthFeatureExtensionData == null || (requestedFeatures & TdsEnums.FeatureExtension.FedAuth) != 0, "fedAuthFeatureExtensionData provided without fed auth feature request");
            Debug.Assert(fedAuthFeatureExtensionData != null || (requestedFeatures & TdsEnums.FeatureExtension.FedAuth) == 0, "Fed Auth feature requested without specifying fedAuthFeatureExtensionData.");

            Debug.Assert(rec.userName == null || (rec.userName != null && TdsEnums.MAXLEN_CLIENTID >= rec.userName.Length), "_userID.Length exceeds the max length for this value");
            Debug.Assert(rec.credential == null || (rec.credential != null && TdsEnums.MAXLEN_CLIENTID >= rec.credential.UserId.Length), "_credential.UserId.Length exceeds the max length for this value");

            Debug.Assert(rec.password == null || (rec.password != null && TdsEnums.MAXLEN_CLIENTSECRET >= rec.password.Length), "_password.Length exceeds the max length for this value");
            Debug.Assert(rec.credential == null || (rec.credential != null && TdsEnums.MAXLEN_CLIENTSECRET >= rec.credential.Password.Length), "_credential.Password.Length exceeds the max length for this value");

            Debug.Assert(rec.credential != null || rec.userName != null || rec.password != null, "cannot mix the new secure password system and the connection string based password");
            Debug.Assert(rec.newSecurePassword != null || rec.newPassword != null, "cannot have both new secure change password and string based change password");
            Debug.Assert(TdsEnums.MAXLEN_APPNAME >= rec.applicationName.Length, "_applicationName.Length exceeds the max length for this value");
            Debug.Assert(TdsEnums.MAXLEN_SERVERNAME >= rec.serverName.Length, "_dataSource.Length exceeds the max length for this value");
            Debug.Assert(TdsEnums.MAXLEN_LANGUAGE >= rec.language.Length, "_currentLanguage .Length exceeds the max length for this value");
            Debug.Assert(TdsEnums.MAXLEN_DATABASE >= rec.database.Length, "_initialCatalog.Length exceeds the max length for this value");
            Debug.Assert(TdsEnums.MAXLEN_ATTACHDBFILE >= rec.attachDBFilename.Length, "_attachDBFileName.Length exceeds the max length for this value");

            Debug.Assert(_connHandler != null, "SqlConnectionInternalTds handler can not be null at this point.");
            _connHandler!.TimeoutErrorInternal.EndPhase(SqlConnectionTimeoutErrorPhase.LoginBegin);
            _connHandler.TimeoutErrorInternal.SetAndBeginPhase(SqlConnectionTimeoutErrorPhase.ProcessConnectionAuth);

            // get the password up front to use in sspi logic below
            byte[] encryptedPassword = null;
            byte[] encryptedChangePassword = null;
            int encryptedPasswordLengthInBytes;
            int encryptedChangePasswordLengthInBytes;
            bool useFeatureExt = (requestedFeatures != TdsEnums.FeatureExtension.None);

            string userName;

            if (rec.credential != null)
            {
                userName = rec.credential.UserId;
                encryptedPasswordLengthInBytes = rec.credential.Password.Length * 2;
            }
            else
            {
                userName = rec.userName;
                encryptedPassword = TdsParserStaticMethods.ObfuscatePassword(rec.password);
                encryptedPasswordLengthInBytes = encryptedPassword.Length;  // password in clear text is already encrypted and its length is in byte
            }

            if (rec.newSecurePassword != null)
            {
                encryptedChangePasswordLengthInBytes = rec.newSecurePassword.Length * 2;
            }
            else
            {
                encryptedChangePassword = TdsParserStaticMethods.ObfuscatePassword(rec.newPassword);
                encryptedChangePasswordLengthInBytes = encryptedChangePassword.Length;
            }

            // set the message type
            _physicalStateObj._outputMessageType = TdsEnums.MT_LOGIN7;

            // length in bytes
            int length = TdsEnums.SQL2005_LOG_REC_FIXED_LEN;

            string clientInterfaceName = TdsEnums.SQL_PROVIDER_NAME;
            Debug.Assert(TdsEnums.MAXLEN_CLIENTINTERFACE >= clientInterfaceName.Length, "cchCltIntName can specify at most 128 unicode characters. See Tds spec");

            // add up variable-len portions (multiply by 2 for byte len of char strings)
            //
            checked
            {
                length += (rec.hostName.Length + rec.applicationName.Length +
                            rec.serverName.Length + clientInterfaceName.Length +
                            rec.language.Length + rec.database.Length +
                            rec.attachDBFilename.Length) * 2;
                if (useFeatureExt)
                {
                    length += 4;
                }
            }

            // allocate memory for SSPI variables
            byte[] rentedSSPIBuff = null;
            byte[] outSSPIBuff = null; // track the rented buffer as a separate variable in case it is updated via the ref parameter
            uint outSSPILength = 0;

            // only add lengths of password and username if not using SSPI or requesting federated authentication info
            if (!rec.useSSPI && !(_connHandler._federatedAuthenticationInfoRequested || _connHandler._federatedAuthenticationRequested))
            {
                checked
                {
                    length += (userName.Length * 2) + encryptedPasswordLengthInBytes
                    + encryptedChangePasswordLengthInBytes;
                }
            }
            else
            {
                if (rec.useSSPI)
                {
                    // now allocate proper length of buffer, and set length
                    outSSPILength = _authenticationProvider.MaxSSPILength;
                    rentedSSPIBuff = ArrayPool<byte>.Shared.Rent((int)outSSPILength);
                    outSSPIBuff = rentedSSPIBuff;

                    // Call helper function for SSPI data and actual length.
                    // Since we don't have SSPI data from the server, send null for the
                    // byte[] buffer and 0 for the int length.
                    Debug.Assert(SniContext.Snix_Login == _physicalStateObj.SniContext, $"Unexpected SniContext. Expecting Snix_Login, actual value is '{_physicalStateObj.SniContext}'");
                    _physicalStateObj.SniContext = SniContext.Snix_LoginSspi;
                    _authenticationProvider.SSPIData(ReadOnlyMemory<byte>.Empty, ref outSSPIBuff, ref outSSPILength, _sniSpnBuffer);

                    if (outSSPILength > int.MaxValue)
                    {
                        throw SQL.InvalidSSPIPacketSize();  // SqlBu 332503
                    }
                    _physicalStateObj.SniContext = SniContext.Snix_Login;

                    checked
                    {
                        length += (int)outSSPILength;
                    }
                }
            }

            int feOffset = length;
            // calculate and reserve the required bytes for the featureEx
            length = ApplyFeatureExData(requestedFeatures, recoverySessionData, fedAuthFeatureExtensionData, useFeatureExt, length);

            WriteLoginData(rec,
                           requestedFeatures,
                           recoverySessionData,
                           fedAuthFeatureExtensionData,
                           encrypt,
                           encryptedPassword,
                           encryptedChangePassword,
                           encryptedPasswordLengthInBytes,
                           encryptedChangePasswordLengthInBytes,
                           useFeatureExt,
                           userName,
                           length,
                           feOffset,
                           clientInterfaceName,
                           outSSPIBuff,
                           outSSPILength);

            if (rentedSSPIBuff != null)
            {
                ArrayPool<byte>.Shared.Return(rentedSSPIBuff, clearArray: true);
            }

            _physicalStateObj.WritePacket(TdsEnums.HARDFLUSH);
            _physicalStateObj.ResetSecurePasswordsInformation();     // Password information is needed only from Login process; done with writing login packet and should clear information
            _physicalStateObj.HasPendingData = true;
            _physicalStateObj._messageStatus = 0;
        }// tdsLogin

        internal TdsParserStateObject GetSession(object owner)
        {
            TdsParserStateObject session = null;
            if (MARSOn)
            {
                session = _sessionPool.GetSession(owner);

                Debug.Assert(!session.HasPendingData, "pending data on a pooled MARS session");
                SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.TdsParser.GetSession|ADV> {0} getting session {1} from pool", ObjectID, session.ObjectID);
            }
            else
            {
                session = _physicalStateObj;
                SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.TdsParser.GetSession|ADV> {0} getting physical session {1}", ObjectID, session.ObjectID);
            }
            Debug.Assert(session._outputPacketNumber == 1, "The packet number is expected to be 1");
            return session;
        }

        internal void PutSession(TdsParserStateObject session)
        {
            session.AssertStateIsClean();

            if (MARSOn)
            {
                // This will take care of disposing if the parser is closed
                _sessionPool.PutSession(session);
            }
            else if ((_state == TdsParserState.Closed) || (_state == TdsParserState.Broken))
            {
                // Parser is closed\broken - dispose the stateObj
                Debug.Assert(session == _physicalStateObj, "MARS is off, but session to close is not the _physicalStateObj");
                _physicalStateObj.SniContext = SniContext.Snix_Close;
#if DEBUG
                _physicalStateObj.InvalidateDebugOnlyCopyOfSniContext();
#endif
                _physicalStateObj.Dispose();
            }
            else
            {
                // Non-MARS, and session is ok - remove its owner
                _physicalStateObj.Owner = null;
            }
        }

        // Fires a single InfoMessageEvent
        private void FireInfoMessageEvent(SqlConnection connection, SqlCommand command, TdsParserStateObject stateObj, SqlError error)
        {

            string serverVersion = null;

            Debug.Assert(connection != null && _connHandler.Connection == connection);

            if (_state == TdsParserState.OpenLoggedIn)
            {
                serverVersion = _connHandler.ServerVersion;
            }

            SqlErrorCollection sqlErs = new SqlErrorCollection();

            sqlErs.Add(error);

            SqlException exc = SqlException.CreateException(sqlErs, serverVersion, _connHandler, innerException: null, batchCommand: command?.GetCurrentBatchCommand());

            bool notified;
            connection.OnInfoMessage(new SqlInfoMessageEventArgs(exc), out notified);
            if (notified)
            {
                // observable side-effects, no retry
                stateObj._syncOverAsync = true;
            }
            return;
        }

        internal void DisconnectTransaction(SqlInternalTransaction internalTransaction)
        {
            Debug.Assert(_currentTransaction != null && _currentTransaction == internalTransaction, "disconnecting different transaction");

            if (_currentTransaction != null && _currentTransaction == internalTransaction)
            {
                _currentTransaction = null;
            }
        }

        internal void RollbackOrphanedAPITransactions()
        {
            // Any active, non-distributed transaction must be rolled back.
            SqlInternalTransaction currentTransaction = CurrentTransaction;

            if (currentTransaction != null && currentTransaction.HasParentTransaction && currentTransaction.IsOrphaned)
            {
                currentTransaction.CloseFromConnection();
                Debug.Assert(CurrentTransaction == null, "rollback didn't clear current transaction?");
            }
        }

        internal void ThrowUnsupportedCollationEncountered(TdsParserStateObject stateObj)
        {
            stateObj.AddError(new SqlError(0, 0, TdsEnums.MIN_ERROR_CLASS, _server, SQLMessage.CultureIdError(), "", 0));

            if (stateObj != null)
            {
                DrainData(stateObj);

                stateObj.HasPendingData = false;
            }

            ThrowExceptionAndWarning(stateObj);
        }

        //
        // we always send over nullable types for parameters so we always write the varlen fields
        //
        internal void WriteParameterVarLen(MetaType type, int size, bool isNull, TdsParserStateObject stateObj, bool unknownLength = false)
        {
            if (type.IsLong)
            { // text/image/SQLVariant have a 4 byte length, plp datatypes have 8 byte lengths
                if (isNull)
                {
                    if (type.IsPlp)
                    {
                        WriteLong(unchecked((long)TdsEnums.SQL_PLP_NULL), stateObj);
                    }
                    else
                    {
                        WriteInt(unchecked((int)TdsEnums.VARLONGNULL), stateObj);
                    }
                }
                else if (type.NullableType is TdsEnums.SQLXMLTYPE or TdsEnums.SQLJSON || unknownLength)
                {
                    WriteUnsignedLong(TdsEnums.SQL_PLP_UNKNOWNLEN, stateObj);
                }
                else if (type.IsPlp)
                {
                    // Non-xml plp types
                    WriteLong((long)size, stateObj);
                }
                else
                {
                    WriteInt(size, stateObj);
                }
            }
            else if (type.IsVarTime)
            {
                if (isNull)
                {
                    stateObj.WriteByte(TdsEnums.FIXEDNULL);
                }
                else
                {
                    stateObj.WriteByte((byte)size);
                }
            }
            else if (false == type.IsFixed)
            { // non-long but variable length column, must be a BIG* type: 2 byte length
                if (isNull)
                {
                    WriteShort(TdsEnums.VARNULL, stateObj);
                }
                else
                {
                    WriteShort(size, stateObj);
                }
            }
            else
            {
                if (isNull)
                {
                    stateObj.WriteByte(TdsEnums.FIXEDNULL);
                }
                else
                {
                    Debug.Assert(type.FixedLength <= 0xff, "WriteParameterVarLen: invalid one byte length!");
                    stateObj.WriteByte((byte)(type.FixedLength & 0xff)); // 1 byte for everything else
                }
            }
        }



        /// <summary>
        /// <para> Parses the TDS message to read single CIPHER_INFO entry.</para>
        /// </summary>
        internal TdsOperationStatus TryReadCipherInfoEntry(TdsParserStateObject stateObj, out SqlTceCipherInfoEntry entry)
        {
            byte cekValueCount = 0;
            entry = new SqlTceCipherInfoEntry(ordinal: 0);

            // Read the DB ID
            int dbId;
            TdsOperationStatus result = stateObj.TryReadInt32(out dbId);
            if (result != TdsOperationStatus.Done)
            {
                return result;
            }

            // Read the keyID
            int keyId;
            result = stateObj.TryReadInt32(out keyId);
            if (result != TdsOperationStatus.Done)
            {
                return result;
            }

            // Read the key version
            int keyVersion;
            result = stateObj.TryReadInt32(out keyVersion);
            if (result != TdsOperationStatus.Done)
            {
                return result;
            }

            // Read the key MD Version
            byte[] keyMDVersion = new byte[8];
            result = stateObj.TryReadByteArray(keyMDVersion, 8);
            if (result != TdsOperationStatus.Done)
            {
                return result;
            }

            // Read the value count
            result = stateObj.TryReadByte(out cekValueCount);
            if (result != TdsOperationStatus.Done)
            {
                return result;
            }

            for (int i = 0; i < cekValueCount; i++)
            {
                // Read individual CEK values
                byte[] encryptedCek;
                string keyPath;
                string keyStoreName;
                byte algorithmLength;
                string algorithmName;
                ushort shortValue;
                byte byteValue;
                int length;

                // Read the length of encrypted CEK
                result = stateObj.TryReadUInt16(out shortValue);
                if (result != TdsOperationStatus.Done)
                {
                    return result;
                }

                length = shortValue;
                encryptedCek = new byte[length];

                // Read the actual encrypted CEK
                result = stateObj.TryReadByteArray(encryptedCek, length);
                if (result != TdsOperationStatus.Done)
                {
                    return result;
                }

                // Read the length of key store name
                result = stateObj.TryReadByte(out byteValue);
                if (result != TdsOperationStatus.Done)
                {
                    return result;
                }

                length = byteValue;

                // And read the key store name now
                result = stateObj.TryReadString(length, out keyStoreName);
                if (result != TdsOperationStatus.Done)
                {
                    return result;
                }

                // Read the length of key Path
                result = stateObj.TryReadUInt16(out shortValue);
                if (result != TdsOperationStatus.Done)
                {
                    return result;
                }

                length = shortValue;

                // Read the key path string
                result = stateObj.TryReadString(length, out keyPath);
                if (result != TdsOperationStatus.Done)
                {
                    return result;
                }

                // Read the length of the string carrying the encryption algo
                result = stateObj.TryReadByte(out algorithmLength);
                if (result != TdsOperationStatus.Done)
                {
                    return result;
                }

                length = (int)algorithmLength;

                // Read the string carrying the encryption algo  (eg. RSA_PKCS_OAEP)
                result = stateObj.TryReadString(length, out algorithmName);
                if (result != TdsOperationStatus.Done)
                {
                    return result;
                }

                // Add this encrypted CEK blob to our list of encrypted values for the CEK
                entry.Add(encryptedCek,
                    databaseId: dbId,
                    cekId: keyId,
                    cekVersion: keyVersion,
                    cekMdVersion: keyMDVersion,
                    keyPath: keyPath,
                    keyStoreName: keyStoreName,
                    algorithmName: algorithmName);
            }

            return TdsOperationStatus.Done;
        }
        
        /// <summary>
        /// <para> Parses the TDS message to read a single CIPHER_INFO table.</para>
        /// </summary>
        internal TdsOperationStatus TryProcessCipherInfoTable(TdsParserStateObject stateObj, out SqlTceCipherInfoTable cipherTable)
        {
            // Read count
            short tableSize = 0;
            cipherTable = null;
            TdsOperationStatus result = stateObj.TryReadInt16(out tableSize);
            if (result != TdsOperationStatus.Done)
            {
                return result;
            }

            if (0 != tableSize)
            {
                SqlTceCipherInfoTable tempTable = new SqlTceCipherInfoTable(tableSize);

                // Read individual entries
                for (int i = 0; i < tableSize; i++)
                {
                    SqlTceCipherInfoEntry entry;
                    result = TryReadCipherInfoEntry(stateObj, out entry);
                    if (result != TdsOperationStatus.Done)
                    {
                        return result;
                    }

                    tempTable[i] = entry;
                }

                cipherTable = tempTable;
            }

            return TdsOperationStatus.Done;
        }

        private void WriteDecimal(decimal value, TdsParserStateObject stateObj)
        {
            stateObj._decimalBits = decimal.GetBits(value);
            Debug.Assert(stateObj._decimalBits != null, "decimalBits should be filled in at TdsExecuteRPC time");

            /*
             Returns a binary representation of a Decimal. The return value is an integer
             array with four elements. Elements 0, 1, and 2 contain the low, middle, and
             high 32 bits of the 96-bit integer part of the Decimal. Element 3 contains
             the scale factor and sign of the Decimal: bits 0-15 (the lower word) are
             unused; bits 16-23 contain a value between 0 and 28, indicating the power of
             10 to divide the 96-bit integer part by to produce the Decimal value; bits 24-
             30 are unused; and finally bit 31 indicates the sign of the Decimal value, 0
             meaning positive and 1 meaning negative.

             SQLDECIMAL/SQLNUMERIC has a byte stream of:
             struct {
                 BYTE sign; // 1 if positive, 0 if negative
                 BYTE data[];
             }

             For TDS 7.0 and above, there are always 17 bytes of data
            */

            // write the sign (note that COM and SQL are opposite)
            if (0x80000000 == (stateObj._decimalBits[3] & 0x80000000))
                stateObj.WriteByte(0);
            else
                stateObj.WriteByte(1);

            WriteInt(stateObj._decimalBits[0], stateObj);
            WriteInt(stateObj._decimalBits[1], stateObj);
            WriteInt(stateObj._decimalBits[2], stateObj);
            WriteInt(0, stateObj);
        }

        private void WriteIdentifier(string s, TdsParserStateObject stateObj)
        {
            if (s != null)
            {
                stateObj.WriteByte(checked((byte)s.Length));
                WriteString(s, stateObj);
            }
            else
            {
                stateObj.WriteByte((byte)0);
            }
        }

        private void WriteIdentifierWithShortLength(string s, TdsParserStateObject stateObj)
        {
            if (s != null)
            {
                WriteShort(checked((short)s.Length), stateObj);
                WriteString(s, stateObj);
            }
            else
            {
                WriteShort(0, stateObj);
            }
        }

        private Task WriteString(string s, TdsParserStateObject stateObj, bool canAccumulate = true)
        {
            return WriteString(s, s.Length, 0, stateObj, canAccumulate);
        }

        internal byte[] SerializeCharArray(char[] carr, int length, int offset)
        {
            int cBytes = ADP.CharSize * length;
            byte[] bytes = new byte[cBytes];

            CopyCharsToBytes(carr, offset, bytes, 0, length);
            return bytes;
        }

        internal Task WriteCharArray(char[] carr, int length, int offset, TdsParserStateObject stateObj, bool canAccumulate = true)
        {
            int cBytes = ADP.CharSize * length;

            // Perf shortcut: If it fits, write directly to the outBuff
            if (cBytes < (stateObj._outBuff.Length - stateObj._outBytesUsed))
            {
                CopyCharsToBytes(carr, offset, stateObj._outBuff, stateObj._outBytesUsed, length);
                stateObj._outBytesUsed += cBytes;
                return null;
            }
            else
            {
                if (stateObj._bTmp == null || stateObj._bTmp.Length < cBytes)
                {
                    stateObj._bTmp = new byte[cBytes];
                }

                CopyCharsToBytes(carr, offset, stateObj._bTmp, 0, length);
                return stateObj.WriteByteArray(stateObj._bTmp, cBytes, 0, canAccumulate);
            }
        }

        internal byte[] SerializeString(string s, int length, int offset)
        {
            int cBytes = ADP.CharSize * length;
            byte[] bytes = new byte[cBytes];

            CopyStringToBytes(s, offset, bytes, 0, length);
            return bytes;
        }

        internal Task WriteString(string s, int length, int offset, TdsParserStateObject stateObj, bool canAccumulate = true)
        {
            int cBytes = ADP.CharSize * length;

            // Perf shortcut: If it fits, write directly to the outBuff
            if (cBytes < (stateObj._outBuff.Length - stateObj._outBytesUsed))
            {
                CopyStringToBytes(s, offset, stateObj._outBuff, stateObj._outBytesUsed, length);
                stateObj._outBytesUsed += cBytes;
                return null;
            }
            else
            {
                if (stateObj._bTmp == null || stateObj._bTmp.Length < cBytes)
                {
                    stateObj._bTmp = new byte[cBytes];
                }

                CopyStringToBytes(s, offset, stateObj._bTmp, 0, length);
                return stateObj.WriteByteArray(stateObj._bTmp, cBytes, 0, canAccumulate);
            }
        }

        // Reads the next chunk in a nvarchar(max) data stream.
        // This call must be preceded by a call to ReadPlpLength or ReadDataLength.
        // Will not start reading into the next chunk if bytes requested is larger than
        // the current chunk length. Do another ReadPlpLength, ReadPlpUnicodeChars in that case.
        // Returns the actual chars read
        private TdsOperationStatus TryReadPlpUnicodeCharsChunk(char[] buff, int offst, int len, TdsParserStateObject stateObj, out int charsRead)
        {
            Debug.Assert((buff == null && len == 0) || (buff.Length >= offst + len), "Invalid length sent to ReadPlpUnicodeChars()!");
            Debug.Assert((stateObj._longlen != 0) && (stateObj._longlen != TdsEnums.SQL_PLP_NULL),
                "Out of sync plp read request");
            if (stateObj._longlenleft == 0)
            {
                Debug.Fail("Out of sync read request");
                charsRead = 0;
                return TdsOperationStatus.Done;
            }

            int charsToRead = len;

            // stateObj._longlenleft is in bytes
            if ((stateObj._longlenleft / 2) < (ulong)len)
            {
                charsToRead = (int)(stateObj._longlenleft >> 1);
            }

            TdsOperationStatus result = stateObj.TryReadChars(buff, offst, charsToRead, out charsRead);
            if (result != TdsOperationStatus.Done)
            {
                charsRead = 0;
                return result;
            }
            stateObj._longlenleft -= ((ulong)charsRead << 1);
            return TdsOperationStatus.Done;
        }


    }
}
