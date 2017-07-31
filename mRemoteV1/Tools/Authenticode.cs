using System;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Reflection;
// ReSharper disable UnusedMember.Local
// ReSharper disable NotAccessedField.Local
// ReSharper disable UnusedAutoPropertyAccessor.Local
#pragma warning disable 414
#pragma warning disable 169

namespace mRemoteNG.Tools
{
	/// <summary>
	/// This class provides Authenticode signature verification services in 
	/// managed C# code.
	/// </summary>
	public class Authenticode
	{
		private string _thumbprint;
		private int _trustProviderErrorCode;

		/// <summary>
		/// The style of display to present to the user when verifying trust 
		/// for an assembly on this system.
		/// </summary>
		public DisplayValue Display { get; } = DisplayValue.None;

		/// <summary>
		/// Certificate revocation check options. This member can be set to 
		/// add revocation checking to that done by the selected policy provider.
		/// </summary>
		public RevocationCheckOptions RevocationCheck { get; set; } = RevocationCheckOptions.WholeChain;

		private DisplayContextValue DisplayContext { get; set; }
		private Form DisplayParentForm { get; set; }

		#region Public Enums
		public enum DisplayValue : uint
		{
			/// <summary>
			/// Display all UI.
			/// </summary>
			All = NativeMethods.WTD_UI_ALL,
			/// <summary>
			/// Display no UI.
			/// </summary>
			None = NativeMethods.WTD_UI_NONE,
			/// <summary>
			/// Do not display any negative UI.
			/// </summary>
			NoBad = NativeMethods.WTD_UI_NOBAD,
			/// <summary>
			/// Do not display any positive UI.
			/// </summary>
			NoGood = NativeMethods.WTD_UI_NOGOOD
		}

		/// <summary>
		/// Specifies the user interface context for the
		/// WinVerifyTrust function. This causes the text in the Authenticode
		/// dialog box to match the action taken on the file.
		/// </summary>
		private enum DisplayContextValue : uint
		{
			/// <summary>
			/// Use when calling WinVerifyTrust for a file that is to be run.
			/// </summary>
			Execute = NativeMethods.WTD_UICONTEXT_EXECUTE,
			/// <summary>
			/// Use when calling WinVerifyTrust for a file that is to be installed.
			/// </summary>
			Install = NativeMethods.WTD_UICONTEXT_INSTALL
		}

		public enum StatusValue
		{
			Unknown = 0,
			Verified,
			FileNotExist,
			FileEmpty,
			NoSignature,
			ThumbprintNotMatch,
			TrustProviderError,
			UnhandledException
		}

		public enum RevocationCheckOptions : uint
		{
			/// <summary>
			/// No additional revocation checking will be done when the 
			/// WTD_REVOKE_NONE flag is used in conjunction with the 
			/// HTTPSPROV_ACTION value set in the pgActionID parameter 
			/// of the WinVerifyTrust function. To ensure the WinVerifyTrust 
			/// function does not attempt any network retrieval when 
			/// verifying code signatures, WTD_CACHE_ONLY_URL_RETRIEVAL 
			/// must be set in the dwProvFlags parameter.
			/// </summary>
			None = NativeMethods.WTD_REVOKE_NONE,
			/// <summary>
			/// Revocation checking will be done on the whole chain.
			/// </summary>
			WholeChain = NativeMethods.WTD_REVOKE_WHOLECHAIN
		}
		#endregion

		public StatusValue Verify(string filePath)
		{
			return Verify(filePath, "");
		}

		public StatusValue VerifyWithThumbprint(string filePath, string thumbprintToMatch)
		{
			if (string.IsNullOrEmpty(thumbprintToMatch))
				throw new ArgumentException(@"Cannot be null or empty", nameof(thumbprintToMatch));

			return Verify(filePath, thumbprintToMatch);
		}

		private StatusValue Verify(string filePath, string thumbprintToMatch)
		{
			if (string.IsNullOrEmpty(filePath))
				throw new ArgumentException(@"Cannot be null or empty", nameof(filePath));

			var trustFileInfoPointer = default(IntPtr);
			var trustDataPointer = default(IntPtr);
			try
			{
				var fileInfo = new FileInfo(filePath);
				if (!fileInfo.Exists)
					return StatusValue.FileNotExist;

				if (fileInfo.Length == 0)
					return StatusValue.FileEmpty;
					
				if (!string.IsNullOrEmpty(thumbprintToMatch))
				{
					var certificate = X509Certificate.CreateFromSignedFile(filePath);
					var certificate2 = new X509Certificate2(certificate);
					_thumbprint = certificate2.Thumbprint;
					if (_thumbprint != thumbprintToMatch)
						return StatusValue.ThumbprintNotMatch;
				}

			    var trustFileInfo = new NativeMethods.WINTRUST_FILE_INFO {pcwszFilePath = filePath};
			    trustFileInfoPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf(trustFileInfo));
				Marshal.StructureToPtr(trustFileInfo, trustFileInfoPointer, false);

			    var trustData = new NativeMethods.WINTRUST_DATA
			    {
			        dwUIChoice = (uint) Display,
			        fdwRevocationChecks = (uint) RevocationCheck,
			        dwUnionChoice = NativeMethods.WTD_CHOICE_FILE,
			        pFile = trustFileInfoPointer,
			        dwStateAction = NativeMethods.WTD_STATEACTION_IGNORE,
			        dwProvFlags = NativeMethods.WTD_DISABLE_MD2_MD4,
			        dwUIContext = (uint) DisplayContext
			    };
			    trustDataPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf(trustData));
				Marshal.StructureToPtr(trustData, trustDataPointer, false);

			    var windowHandle = DisplayParentForm?.Handle ?? IntPtr.Zero;
					
				_trustProviderErrorCode = NativeMethods.WinVerifyTrust(windowHandle, NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2, trustDataPointer);
			    // ReSharper disable once SwitchStatementMissingSomeCases
				switch (_trustProviderErrorCode)
				{
					case NativeMethods.TRUST_E_NOSIGNATURE:
						return StatusValue.NoSignature;
					case NativeMethods.TRUST_E_SUBJECT_NOT_TRUSTED:
						break;
				}
				return _trustProviderErrorCode != 0 ? StatusValue.TrustProviderError : StatusValue.Verified;
			}
			catch (CryptographicException ex)
			{
				var hResultProperty = ex.GetType().GetProperty("HResult", BindingFlags.NonPublic | BindingFlags.Instance);
				var hResult = Convert.ToInt32(hResultProperty.GetValue(ex, null));
				return hResult == NativeMethods.CRYPT_E_NO_MATCH ? StatusValue.NoSignature : StatusValue.UnhandledException;
			}
			catch (Exception)
			{
				return StatusValue.UnhandledException;
			}
			finally
			{
				if (trustDataPointer != IntPtr.Zero)
					Marshal.FreeCoTaskMem(trustDataPointer);

				if (trustFileInfoPointer != IntPtr.Zero)
					Marshal.FreeCoTaskMem(trustFileInfoPointer);
			}
		}

        #region Protected Classes
	    private static class NativeMethods
		{
			// ReSharper disable InconsistentNaming
			[DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
			public static extern int WinVerifyTrust([In]IntPtr hWnd, [In, MarshalAs(UnmanagedType.LPStruct)]Guid pgActionOID, [In]IntPtr pWVTData);
				
			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public class WINTRUST_DATA
			{
				private uint cbStruct;
				public IntPtr pPolicyCallbackData;
				public IntPtr pSIPClientData;
				public uint dwUIChoice;
				public uint fdwRevocationChecks;
				public uint dwUnionChoice;
				public IntPtr pFile;
				public uint dwStateAction;
				public IntPtr hWVTStateData;
				public IntPtr pwszURLReference;
				public uint dwProvFlags;
				public uint dwUIContext;

				public WINTRUST_DATA()
				{
					cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
				}
			}
				
			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public class WINTRUST_FILE_INFO
			{
				private uint cbStruct;
				[MarshalAs(UnmanagedType.LPTStr)]
				public string pcwszFilePath;
				public IntPtr hFile;
				public IntPtr pgKnownSubject;

				public WINTRUST_FILE_INFO()
				{
					cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
				}
			}
				
			public const int CRYPT_E_NO_MATCH = unchecked ((int) 0x80092009);
				
			public const int TRUST_E_SUBJECT_NOT_TRUSTED = unchecked ((int) 0x800B0004);
			public const int TRUST_E_NOSIGNATURE = unchecked ((int) 0x800B0100);
				
			public static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");
				
			public const uint WTD_CHOICE_FILE = 1;
			public const uint WTD_DISABLE_MD2_MD4 = 0x2000;
			public const uint WTD_REVOKE_NONE = 0;
			public const uint WTD_REVOKE_WHOLECHAIN = 1;
				
			public const uint WTD_STATEACTION_IGNORE = 0x0;
			public const uint WTD_STATEACTION_VERIFY = 0x1;
			public const uint WTD_STATEACTION_CLOSE = 0x2;
				
			public const uint WTD_UI_ALL = 1;
			public const uint WTD_UI_NONE = 2;
			public const uint WTD_UI_NOBAD = 3;
			public const uint WTD_UI_NOGOOD = 4;
				
			public const uint WTD_UICONTEXT_EXECUTE = 0;
			public const uint WTD_UICONTEXT_INSTALL = 1;
			// ReSharper restore InconsistentNaming
		}
        #endregion
	}
}
