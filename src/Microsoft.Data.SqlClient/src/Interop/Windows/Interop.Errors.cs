// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

internal partial class Interop
{
    // https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-
    internal partial class Errors
    {
        internal const int ERROR_FILE_NOT_FOUND = 0x2;
        internal const int ERROR_INVALID_HANDLE = 0x6;
        internal const int ERROR_SHARING_VIOLATION = 0x20;
        internal const int ERROR_INVALID_PARAMETER = 0x57;
    }
}
