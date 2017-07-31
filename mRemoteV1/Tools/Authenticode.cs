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
		/// <summary>
		/// The style of display to present to the user when verifying trust 
		/// for an assembly on this system.
		/// </summary>
		public WinTrustDataUiChoice Display { get; } = WinTrustDataUiChoice.None;

		/// <summary>
		/// Certificate revocation check options. This member can be set to 
		/// add revocation checking to that done by the selected policy provider.
		/// </summary>
		public RevocationCheckOptions RevocationCheck { get; set; } = RevocationCheckOptions.WholeChain;

		private WinTrustDataUiContext DisplayContext { get; set; }

		/// <summary>
		/// The parent form to use for any windows spawned by this class.
		/// </summary>
		private Form DisplayParentForm { get; set; }

		#region Public Enums
		public enum WinTrustDataUiChoice : uint
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
		private enum WinTrustDataUiContext : uint
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

		public enum WinVerifyTrustResult : uint
		{
			Verified = 0,
			ProviderUnknown = 0x800b0001,           // Trust provider is not recognized on this system
			ActionUnknown = 0x800b0002,         // Trust provider does not support the specified action
			SubjectFormUnknown = 0x800b0003,        // Trust provider does not support the form specified for the subject
			SubjectNotTrusted = 0x800b0004,         // Subject failed the specified verification action
			FileNotSigned = 0x800B0100,         // TRUST_E_NOSIGNATURE - File was not signed
			SubjectExplicitlyDistrusted = 0x800B0111,   // Signer's certificate is in the Untrusted Publishers store
			SignatureOrFileCorrupt = 0x80096010,    // TRUST_E_BAD_DIGEST - file was probably corrupt
			SubjectCertExpired = 0x800B0101,        // CERT_E_EXPIRED - Signer's certificate was expired
			SubjectCertificateRevoked = 0x800B010C,     // CERT_E_REVOKED Subject's certificate was revoked
			UntrustedRoot = 0x800B0109,          // CERT_E_UNTRUSTEDROOT - A certification chain processed correctly but terminated in a root certificate that is not trusted by the trust provider.
			FileNotExist,
			FileEmpty,
			ThumbprintNotMatch,
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
			/// must be set in the ProvFlags parameter.
			/// </summary>
			None = 0,
			/// <summary>
			/// Revocation checking will be done on the whole chain.
			/// </summary>
			WholeChain = 1
		}

		public enum WinTrustDataChoice : uint
		{
			File = 1,
			Catalog = 2,
			Blob = 3,
			Signer = 4,
			Certificate = 5
		}

		public enum WinTrustDataStateAction : uint
		{
			Ignore = 0x00000000,
			Verify = 0x00000001,
			Close = 0x00000002,
			AutoCache = 0x00000003,
			AutoCacheFlush = 0x00000004
		}

		[Flags]
		public enum WinTrustDataProvFlags : uint
		{
			UseIe4TrustFlag = 0x00000001,
			NoIe4ChainFlag = 0x00000002,
			NoPolicyUsageFlag = 0x00000004,
			RevocationCheckNone = 0x00000010,
			RevocationCheckEndCert = 0x00000020,
			RevocationCheckChain = 0x00000040,
			RevocationCheckChainExcludeRoot = 0x00000080,
			SaferFlag = 0x00000100,        // Used by software restriction policies. Should not be used.
			HashOnlyFlag = 0x00000200,
			UseDefaultOsverCheck = 0x00000400,
			LifetimeSigningFlag = 0x00000800,
			CacheOnlyUrlRetrieval = 0x00001000,      // affects CRL retrieval and AIA retrieval
			DisableMD2andMD4 = 0x00002000      // Win7 SP1+: Disallows use of MD2 or MD4 in the chain except for the root 
		}
		#endregion

		public WinVerifyTrustResult Verify(string filePath)
		{
			return Verify(filePath, "");
		}

		public WinVerifyTrustResult VerifyWithThumbprint(string filePath, string thumbprintToMatch)
		{
			if (string.IsNullOrEmpty(thumbprintToMatch))
				throw new ArgumentException(@"Cannot be null or empty", nameof(thumbprintToMatch));

			return Verify(filePath, thumbprintToMatch);
		}

		private WinVerifyTrustResult Verify(string filePath, string thumbprintToMatch)
		{
			if (string.IsNullOrEmpty(filePath))
				throw new ArgumentException(@"Cannot be null or empty", nameof(filePath));

			var trustDataPointer = default(IntPtr);
			try
			{
				var fileInfo = new FileInfo(filePath);
				if (!fileInfo.Exists)
					return WinVerifyTrustResult.FileNotExist;

				if (fileInfo.Length == 0)
					return WinVerifyTrustResult.FileEmpty;
					
				if (!string.IsNullOrEmpty(thumbprintToMatch))
				{
					var certificate = X509Certificate.CreateFromSignedFile(filePath);
					var certificate2 = new X509Certificate2(certificate);
					var thumbprint = certificate2.Thumbprint;
					if (thumbprint != thumbprintToMatch)
						return WinVerifyTrustResult.ThumbprintNotMatch;
				}

				using (var winTrustFileInfo = new NativeMethods.WinTrustFileInfo(filePath))
				{
					using (var winTrustData = new NativeMethods.WinTrustData(winTrustFileInfo)
						{
							UiChoice = Display,
							RevocationChecks = RevocationCheck,
							ProvFlags = WinTrustDataProvFlags.DisableMD2andMD4,
							UiContext = DisplayContext
						})
					{
						trustDataPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf(winTrustData));
						Marshal.StructureToPtr(winTrustData, trustDataPointer, false);

						var windowHandle = DisplayParentForm?.Handle ?? IntPtr.Zero;

						var trustProviderReturnCode = NativeMethods.WinVerifyTrust(windowHandle,
							NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2, trustDataPointer);

						return trustProviderReturnCode;
					}
				}
			}
			catch (CryptographicException ex)
			{
				var hResultProperty = ex.GetType().GetProperty("HResult", BindingFlags.NonPublic | BindingFlags.Instance);
				var hResult = Convert.ToInt32(hResultProperty.GetValue(ex, null));
				return hResult == NativeMethods.CRYPT_E_NO_MATCH
					? WinVerifyTrustResult.FileNotSigned
					: WinVerifyTrustResult.UnhandledException;
			}
			catch (Exception)
			{
				return WinVerifyTrustResult.UnhandledException;
			}
			finally
			{
				if (trustDataPointer != IntPtr.Zero)
					Marshal.FreeCoTaskMem(trustDataPointer);
			}
		}

        #region Protected Classes
	    private static class NativeMethods
		{
			// ReSharper disable InconsistentNaming
			[DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
			public static extern WinVerifyTrustResult WinVerifyTrust([In]IntPtr hWnd, [In, MarshalAs(UnmanagedType.LPStruct)]Guid pgActionOID, [In]IntPtr pWVTData);
				
			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public class WinTrustData : IDisposable
			{
				private uint cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustData));
				public IntPtr pPolicyCallbackData;
				public IntPtr pSIPClientData;
				public WinTrustDataUiChoice UiChoice;
				public RevocationCheckOptions RevocationChecks = RevocationCheckOptions.None;
				public WinTrustDataChoice dwUnionChoice = WinTrustDataChoice.File;
				private readonly IntPtr FileInfoPtr;
				public WinTrustDataStateAction StateAction = WinTrustDataStateAction.Ignore;
				public IntPtr hWVTStateData;
				public IntPtr pwszURLReference;
				public WinTrustDataProvFlags ProvFlags;
				public WinTrustDataUiContext UiContext;

				public WinTrustData(WinTrustFileInfo winTrustFileInfo)
				{
					FileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(winTrustFileInfo));
					Marshal.StructureToPtr(winTrustFileInfo, FileInfoPtr, false);
				}

				private void ReleaseUnmanagedResources()
				{
					if (FileInfoPtr != IntPtr.Zero)
						Marshal.FreeCoTaskMem(FileInfoPtr);
				}

				public void Dispose()
				{
					ReleaseUnmanagedResources();
					GC.SuppressFinalize(this);
				}
			}
				
			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public class WinTrustFileInfo : IDisposable
			{
				private uint cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustFileInfo));
				private readonly IntPtr pszFilePath;
				public IntPtr hFile;
				public IntPtr pgKnownSubject;

				public WinTrustFileInfo(string filePath)
				{
					pszFilePath = Marshal.StringToCoTaskMemAuto(filePath);
				}

				private void ReleaseUnmanagedResources()
				{
					Marshal.FreeCoTaskMem(pszFilePath);
				}

				public void Dispose()
				{
					ReleaseUnmanagedResources();
					GC.SuppressFinalize(this);
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
