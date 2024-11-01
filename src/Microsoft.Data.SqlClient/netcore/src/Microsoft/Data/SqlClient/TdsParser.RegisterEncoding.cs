// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Text;

namespace Microsoft.Data.SqlClient
{
    internal sealed partial class TdsParser
    {
        static TdsParser()
        {
            // For CoreCLR, we need to register the ANSI Code Page encoding provider before attempting to get an Encoding from a CodePage
            // For a default installation of SqlServer the encoding exchanged during Login is 1252. This encoding is not loaded by default
            // See Remarks at https://learn.microsoft.com/dotnet/api/system.text.encodingprovider
            // SqlClient needs to register the encoding providers to make sure that even basic scenarios work with Sql Server.
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        }
    }
}
