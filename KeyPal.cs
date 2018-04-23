//********************************************************************************
//
// KeyPal
// CryptoAPI key container lister and public private key display/exporter
//
// Copyright (C) 2011.  JavaScience Consulting
//
//********************************************************************************
//
// KeyPal.cs
//
// This C# utility for .NET Framework 2 lists all Current User or Machine
// key containers, the key types (exchange and/or signature) and sizes they 
// contain and if the  key-container has an associated certificate in the CU/LM MY store.
//
// Exports any enumerated public key as:
//	- PUBLICKEYBLOB
//	- XML Public Key
//	- X509 SubjectPublicKeyInfo
// 	- PEM public key
// Exports public&private keypairs as:
//	- unencrypted PRIVATEKEYBLOB Microsoft format
//	- PKCS #8 PrivateKeyInfo format
//	- encrypted PKCS#12 format
//
//  Usage:   KeyPal  [M | m]
//    If no command arguments, uses CurrentUser keys and cert store
//    If single "M" or "m" is specified, uses Machine keys and cert store
//**************************************************************************

using System;
using System.Collections;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace KeyPal
{
    public class Win32
    {

        [DllImport("msvcrt.dll")]
        public static extern int system(
            string syscommand);

        //--------  CryptoAPI  CSP and key functions ----------------------
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptAcquireContext(
           ref IntPtr hProv,
           string pszContainer,
           string pszProvider,
           uint dwProvType,
           uint dwFlags);

        [DllImport("advapi32.dll")]
        public static extern bool CryptReleaseContext(
           IntPtr hProv,
           uint dwFlags);

        [DllImport("advapi32.dll")]
        public static extern bool CryptGetUserKey(
           IntPtr hProv,
           uint dwKeySpec,
           ref IntPtr hKey);


        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptExportKey(
           IntPtr hKey,
           IntPtr hExpKey,
           uint dwBlobType,
           uint dwFlags,
           [In, Out] byte[] pbData,
           ref uint dwDataLen);


        [DllImport("advapi32.dll")]
        public static extern bool CryptDestroyKey(
           IntPtr hKey);


        [DllImport("advapi32.dll")]
        public static extern bool CryptGetKeyParam(
           IntPtr hKey,
           uint dwParam,
           ref uint prop,
           ref uint dwDataLen,
           uint dwFlags);


        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptGetProvParam(
           IntPtr hProv,
           uint dwParam,
           [In, Out] byte[] pbData,
           ref uint dwDataLen,
           uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptGetProvParam(
           IntPtr hProv,
           uint dwParam,
           [MarshalAs(UnmanagedType.LPStr)] StringBuilder pbData,
           ref uint dwDataLen,
           uint dwFlags);


        [DllImport("crypt32.dll")]
        public static extern bool CryptEncodeObject(
           uint CertEncodingType,
           uint lpszStructType,
           byte[] pbData,
           [In, Out] byte[] pbEncoded,
           ref uint cbEncoded);

        [DllImport("crypt32.dll")]
        public static extern bool CryptEncodeObject(
           uint CertEncodingType,
           uint lpszStructType,
           ref CERT_PUBLIC_KEY_INFO pvStructInfo,
           [In, Out] byte[] pbEncoded,
           ref uint cbEncoded);


        //---------- CryptoAPI certificate functions --------------------

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)] //overloaded
        public static extern IntPtr CertOpenStore(
           [MarshalAs(UnmanagedType.LPStr)] String storeProvider,
           uint dwMsgAndCertEncodingType,
           IntPtr hCryptProv,
           uint dwFlags,
           String cchNameString);


        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CertOpenSystemStore(
           IntPtr hCryptProv,
           string storename);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertCloseStore(
           IntPtr hCertStore,
           uint dwFlags);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertFreeCertificateContext(
           IntPtr hCertStore);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CertEnumCertificatesInStore(
           IntPtr hCertStore,
           IntPtr pPrevCertContext);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertGetCertificateContextProperty(
         IntPtr pCertContext, uint dwPropId, IntPtr pvData, ref uint pcbData);



        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CertFindCertificateInStore(
           IntPtr pCertStore,
           uint dwCertEncodingType,
           uint dwFindFlags,
           uint dwFindType,
           ref HASH_BLOB phash,
           IntPtr pPrevCertCntxt);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CertFindCertificateInStore(
           IntPtr hCertStore,
           uint dwCertEncodingType,
           uint dwFindFlags,
           uint dwFindType,
           IntPtr pvFindPara,
           IntPtr pPrevCertCntxt);



        [DllImport("cryptui.dll", SetLastError = true)]
        public static extern bool CryptUIDlgViewCertificate(
           ref PCCRYPTUI_VIEWCERTIFICATE_STRUCT pCertViewInfo,
           ref bool pfPropertiesChanged);




        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CryptExportPublicKeyInfoEx(
           IntPtr hProv,
           uint dwKeySpec,
           uint dwCertEncodingType,
           String pxzPublicKeyObjId,
           uint dwFlags,
           IntPtr pvAuxInfo,
           IntPtr pInfo,
           ref uint pcbInfo);


        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern int CertGetPublicKeyLength(
           uint dwCertEncodingType,
           IntPtr pPublicKeyInfo);




        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CertCreateSelfSignCertificate(
           IntPtr hProv,
           ref CERT_NAME_BLOB pSubjectIssuerBlob,
           uint dwFlagsm,
           ref CRYPT_KEY_PROV_INFO pKeyProvInfo,
           IntPtr pSignatureAlgorithm,
           IntPtr pStartTime,
           IntPtr pEndTime,
           IntPtr other);


        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertStrToName(
           uint dwCertEncodingType,
           String pszX500,
           uint dwStrType,
           IntPtr pvReserved,
           [In, Out] byte[] pbEncoded,
           ref uint pcbEncoded,
           IntPtr other);



        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CryptExportPKCS8Ex(
           ref CRYPT_PKCS8_EXPORT_PARAMS psExportParams,
           uint dwFlags,
           IntPtr pvAuxInfo,
           [In, Out] byte[] pbPrivateKeyBlob,
           ref uint pcbPrivateKeyBlob);



        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CryptExportPKCS8(
           IntPtr hCryptProv,
           uint dwKeySpec,
           String pszPrivateKeyObjId,
           uint dwFlags,
           IntPtr pvAuxInfo,
           [In, Out] byte[] pbPrivateKeyBlob,
           ref uint pcbPrivateKeyBlob);
    }




    //--------  Win32 structs prototypes ---------------


    [StructLayout(LayoutKind.Sequential)]
    public struct PUBKEYBLOBHEADERS
    {
        public byte bType;  //BLOBHEADER
        public byte bVersion;   //BLOBHEADER
        public short reserved;  //BLOBHEADER
        public uint aiKeyAlg;   //BLOBHEADER
        public uint magic;  //RSAPUBKEY
        public uint bitlen; //RSAPUBKEY
        public uint pubexp; //RSAPUBKEY
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_KEY_PROV_INFO
    {
        [MarshalAs(UnmanagedType.LPWStr)] public String pwszContainerName;
        [MarshalAs(UnmanagedType.LPWStr)] public String pwszProvName;
        public uint dwProvType;
        public uint dwFlags;
        public uint cProvParam;
        public IntPtr rgProvParam;
        public uint dwKeySpec;
    }



    [StructLayout(LayoutKind.Sequential)]
    public struct PCCRYPTUI_VIEWCERTIFICATE_STRUCT
    {
        public uint dwSize;     //required
        public IntPtr hwndParent;
        public uint dwFlags;
        public String szTitle;
        public IntPtr pCertContext; //required
        public IntPtr rgszPurposes;
        uint cPurposes;
        IntPtr hWVTStateData;
        bool fpCryptProviderDataTrustedUsage;
        uint idxSigner;
        uint idxCert;
        bool fCounterSigner;
        uint idxCounterSigner;
        uint cStores;
        IntPtr rghStores;
        uint cPropSheetPages;
        IntPtr rgPropSheetPages;
        public uint nStartPage; //required
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct HASH_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_NAME_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }



    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_PUBLIC_KEY_INFO
    {
        public String SubjPKIAlgpszObjId;
        public int SubjPKIAlgParameterscbData;
        public IntPtr SubjPKIAlgParameterspbData;
        public int PublicKeycbData;
        public IntPtr PublicKeypbData;
        public int PublicKeycUnusedBits;
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_CONTEXT
    {
        public uint dwCertEncodingType;
        public IntPtr pbCertEncoded;
        public int cbCertEncoded;
        public IntPtr pCertInfo;
        public IntPtr hCertStore;
    }



    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_PKCS8_EXPORT_PARAMS
    {
        public IntPtr hCryptProv;
        public uint dwKeySpec;
        public String pszPrivateKeyObjId;
        public IntPtr pEncryptPrivateKeyFunc;
        public IntPtr pVoidEncryptFunc;
    }



    //---  Convenience class to hold properties of certs. that have private key -------
    public sealed class CERTPROPS_INFO
    {
        public CERTPROPS_INFO(byte[] hash, string certsubjname)
        {
            this.sha1hash = hash;
            this.SubjectNameCN = certsubjname;
        }
        public byte[] Hash
        {
            get
            {
                return sha1hash;
            }
        }
        public String Name
        {
            get
            {
                return SubjectNameCN;
            }
        }

        private byte[] sha1hash;
        private String SubjectNameCN;
    }






    public class KeyPal
    {
        const String TITLE = "KeyPal";
        const uint PKCS_7_ASN_ENCODING = 0x00010000;
        const uint X509_ASN_ENCODING = 0x00000001;
        const uint PROV_RSA_FULL = 0x00000001;
        const uint CRYPT_VERIFYCONTEXT = 0xF0000000;     //no private key access flag
        const uint CRYPT_MACHINE_KEYSET = 0x00000020;
        const uint CRYPT_FIRST = 0x00000001;
        const uint PP_ENUMCONTAINERS = 0x00000002;
        const uint PP_UNIQUE_CONTAINER = 0x00000024;
        const uint AT_KEYEXCHANGE = 0x00000001;
        const uint AT_SIGNATURE = 0x00000002;
        const uint KP_KEYLEN = 0x00000009;
        const uint PUBLICKEYBLOB = 0x00000006;
        const uint PRIVATEKEYBLOB = 0x00000007;
        const uint KP_PERMISSIONS = 0x00000006;
        const uint CRYPT_EXPORT = 0x00000004;
        const uint CRYPT_DELETEKEYSET = 0x00000010;
        const uint RSA_CSP_PUBLICKEYBLOB = 19;
        const String szOID_RSA_RSA = "1.2.840.113549.1.1.1";
        const uint X509_PUBLIC_KEY_INFO = 8;
        static String[] keyspecs = { null, "AT_KEYEXCHANGE", "AT_SIGNATURE" };

        const uint CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000;
        const uint CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000;
        const uint CERT_STORE_READONLY_FLAG = 0x00008000;
        const uint CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;
        const uint CERT_CREATE_SELFSIGN_NO_SIGN = 1;
        const uint CERT_FIND_PUBLIC_KEY = 6 << 16;

        const uint CERT_KEY_PROV_INFO_PROP_ID = 0x00000002;
        const String MS_DEF_PROV = "Microsoft Base Cryptographic Provider v1.0";
        const String MS_STRONG_PROV = "Microsoft Strong Cryptographic Provider";
        const String MS_ENHANCED_PROV = "Microsoft Enhanced Cryptographic Provider v1.0";
        const string MYSTORE = "MY";
        const string OTHERSSTORE = "AddressBook";
        const uint CERT_FIND_HASH = 0x00010000;
        static uint ENCODING_TYPE = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
        static String[] blobnames = { "", "", "", "", "", "", "publickeyblob", "privatekeyblob" };
        static string[] containernames;
        static Hashtable certcontainernames;
        static int ccount;
        static uint storetype = CERT_SYSTEM_STORE_CURRENT_USER;
        static uint CSPKEYTYPE = 0; //default is CU keystores
        static StoreLocation storeloc = StoreLocation.CurrentUser;
        static bool displayarrayform = false;

        public static void Main(String[] args)
        {

            if (args.Length > 2)
            {
                Console.WriteLine("Usage:  Keypal   [CU | M]   [longform]");
                return;
            }


            if (args.Length == 0)
            {
                storetype = CERT_SYSTEM_STORE_CURRENT_USER;
                storeloc = StoreLocation.CurrentUser;
                CSPKEYTYPE = 0;   //Current User keystores
            }


            if (args.Length >= 1)
                if (args[0].ToUpper() == "M" || args[0].ToUpper() == "LM")
                {    //  Machine store
                    storetype = CERT_SYSTEM_STORE_LOCAL_MACHINE;
                    storeloc = StoreLocation.LocalMachine;
                    CSPKEYTYPE = CRYPT_MACHINE_KEYSET;
                }
                else
                if (args[0].ToUpper() == "CU")
                {    //  Current User store
                    storetype = CERT_SYSTEM_STORE_CURRENT_USER;
                    storeloc = StoreLocation.CurrentUser;
                    CSPKEYTYPE = 0;
                }

                else
                {
                    Console.WriteLine("Unrecognized argument '{0}'", args[0]);
                    return;
                }

            if (args.Length == 2)
                displayarrayform = true;

            KeyPal.UpdateContainerInfo();
            showInfo();

            //------- Process commands loop  ----------
            string[] splitargs = null;
            string arg1 = null;
            string arg2 = null;
            int itemtoview = -1;
            int keytoexport = -1;
            int containerid = -1;
            byte[] Sha1Hash = null;

            while (true)
            {
                Console.Write("> ");
                string fullline = Console.ReadLine().Trim();
                splitargs = fullline.Split(' ');

                if (splitargs.Length < 1)
                    break;
                arg1 = splitargs[0].Trim().ToLower(); //if here, we have at least 1 arg

                //---- if 2nd arg provided, get and screen container/cert number --------------
                itemtoview = -1;
                if (arg1 != "cl" && arg1 != "cls" && arg1 != "r" && arg1 != "l" && arg1 != "a" && arg1 != "q")
                    if (splitargs.Length > 1)
                    {   //if an item number was specified ...
                        arg2 = splitargs[1].Trim(); //if here, we have at least 2 args; ignore remainder
                        itemtoview = GetArgNumber(arg2, 0, (uint)(ccount - 1));
                    }


                if (string.IsNullOrWhiteSpace(arg1))
                    continue;


                if (arg1.Equals("q"))
                    break;


                switch (arg1)
                {

                    case "c":
                        int certtoview = itemtoview;
                        if (certtoview < 0)
                        {  //if not passed as 2nd arg ...
                            Console.Write("\nEnter keycontainer number to view Certificate:  ");
                            certtoview = GetArgNumber(Console.ReadLine(), 0, (uint)(ccount - 1));
                            if (certtoview < 0)
                                break;
                        }

                        try
                        {
                            String certcontainer = containernames[certtoview];
                            if (certtoview >= 0 && certtoview < ccount && certcontainernames.ContainsKey(certcontainer + "EX"))
                            {
                                Console.WriteLine("\nKeycontainer {0}", certcontainer);
                                Console.WriteLine("CertE: {0}", ((CERTPROPS_INFO)certcontainernames[certcontainer + "EX"]).Name);
                                Sha1Hash = ((CERTPROPS_INFO)certcontainernames[certcontainer + "EX"]).Hash;
                                ShowCertbyHash(Sha1Hash);
                            }
                            else if (certtoview >= 0 && certtoview < ccount && certcontainernames.ContainsKey(certcontainer + "SIG"))
                            {
                                Console.WriteLine("\nKeycontainer {0}", certcontainer);
                                Console.WriteLine("CertS: {0}", ((CERTPROPS_INFO)certcontainernames[certcontainer + "SIG"]).Name);
                                Sha1Hash = ((CERTPROPS_INFO)certcontainernames[certcontainer + "SIG"]).Hash;
                                ShowCertbyHash(Sha1Hash);
                            }
                            else
                                Console.WriteLine("No cert associated with this container");
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine(exc.Message);
                        }
                        break;


                    case "a":       //show all certs dialog
                        ShowAllCertsDialog(5, storeloc);  //default is My store
                        break;
                    case "a1":  //show all certs dialog
                        ShowAllCertsDialog(1, storeloc);  //AddressBook
                        break;
                    case "a2":  //show all certs dialog
                        ShowAllCertsDialog(2, storeloc);  //AuthRoot
                        break;
                    case "a3":  //show all certs dialog
                        ShowAllCertsDialog(3, storeloc);  //CertificateAuthority
                        break;
                    case "a4":  //show all certs dialog
                        ShowAllCertsDialog(4, storeloc);  //Disallowed
                        break;
                    case "a5":  //show all certs dialog
                        ShowAllCertsDialog(5, storeloc);  //My
                        break;
                    case "a6":  //show all certs dialog
                        ShowAllCertsDialog(6, storeloc);  //Root
                        break;
                    case "a7":  //show all certs dialog
                        ShowAllCertsDialog(7, storeloc);  //TrustedPeople
                        break;
                    case "a8":  //show all certs dialog
                        ShowAllCertsDialog(8, storeloc);  //TrustedPublisher
                        break;


                    case "p":       //export PUBLICKEYBLOB(s)
                        keytoexport = itemtoview;
                        if (keytoexport < 0)
                        {  //if not passed as 2nd arg ...
                            Console.Write("\nEnter keycontainer number to export:  ");
                            keytoexport = GetArgNumber(Console.ReadLine(), 0, (uint)(ccount - 1));
                            if (keytoexport < 0)
                                break;
                        }

                        try
                        {
                            Console.WriteLine("\nKeycontainer {0} to export: {1}", keytoexport, containernames[keytoexport]);
                            if (KeyPal.ExportKeyBlobs(keytoexport, containernames[keytoexport], PUBLICKEYBLOB, true))
                                Console.WriteLine("Successfully exported PUBLICKEYBLOB(s)");
                            else
                                Console.WriteLine("Failed to export PUBLICKEYBLOB(s)");
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine(exc.Message);
                        }
                        break;

                    case "pv":  //export unencrypted PRIVATEKEYBLOB(s)
                        keytoexport = itemtoview;
                        if (keytoexport < 0)
                        {  //if not passed as 2nd arg ...
                            Console.Write("\nEnter keycontainer number to export:  ");
                            keytoexport = GetArgNumber(Console.ReadLine(), 0, (uint)(ccount - 1));
                            if (keytoexport < 0)
                                break;
                        }

                        try
                        {
                            Console.WriteLine("\nKeycontainer {0} to export: {1}", keytoexport, containernames[keytoexport]);
                            if (KeyPal.ExportKeyBlobs(keytoexport, containernames[keytoexport], PRIVATEKEYBLOB, true))
                                Console.WriteLine("Successfully exported PRIVATEKEYBLOB(s)");
                            else
                                Console.WriteLine("Failed to export PRIVATEKEYBLOB(s)");
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine(exc.Message);
                        }
                        break;



                    case "p8":  //export unencrypted asn.1 encoded pkcs #8 PrivateKeyInfo
                        keytoexport = itemtoview;
                        if (keytoexport < 0)
                        {  //if not passed as 2nd arg ...
                            Console.Write("\nEnter keycontainer number to export:  ");
                            keytoexport = GetArgNumber(Console.ReadLine(), 0, (uint)(ccount - 1));
                            if (keytoexport < 0)
                                break;
                        }

                        try
                        {
                            Console.WriteLine("\nKeycontainer {0} to export: {1}", keytoexport, containernames[keytoexport]);
                            if (KeyPal.ExportPkcs8(keytoexport, containernames[keytoexport]))
                                Console.WriteLine("Successfully exported to PKCS #8 PrivateKeyInfo");
                            else
                                Console.WriteLine("Failed to export to PKCS #8 PrivateKeyInfo");
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine(exc.Message);
                        }
                        break;




                    case "p12s":    //export Signature keyapair to pkcs#12
                        keytoexport = itemtoview;
                        if (keytoexport < 0)
                        {  //if not passed as 2nd arg ...
                            Console.Write("\nEnter keycontainer number to export:  ");
                            keytoexport = GetArgNumber(Console.ReadLine(), 0, (uint)(ccount - 1));
                            if (keytoexport < 0)
                                break;
                        }
                        try
                        {
                            Console.WriteLine("\nKeycontainer {0} to export: {1}", keytoexport, containernames[keytoexport]);
                            if (KeyPal.ExportPkcs12(keytoexport, containernames[keytoexport], AT_SIGNATURE))
                                Console.WriteLine("Successfully exported Signature keypair to PKCS#12");
                            else
                                Console.WriteLine("Failed to export Signature keypair to PKCS#12");
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine(exc.Message);
                        }
                        break;


                    case "p12e":    //export Exchange keypair to pkcs#12
                        keytoexport = itemtoview;
                        if (keytoexport < 0)
                        {  //if not passed as 2nd arg ...
                            Console.Write("\nEnter keycontainer number to export:  ");
                            keytoexport = GetArgNumber(Console.ReadLine(), 0, (uint)(ccount - 1));
                            if (keytoexport < 0)
                                break;
                        }
                        try
                        {
                            Console.WriteLine("\nKeycontainer {0} to export: {1}", keytoexport, containernames[keytoexport]);
                            if (KeyPal.ExportPkcs12(keytoexport, containernames[keytoexport], AT_KEYEXCHANGE))
                                Console.WriteLine("Successfully exported Exchange keypair to PKCS#12");
                            else
                                Console.WriteLine("Failed to export Exchange keypair to PKCS#12");
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine(exc.Message);
                        }
                        break;





                    case "j":       //export Java X509 SubjectPublicKeyInfo blobs
                        keytoexport = itemtoview;
                        if (keytoexport < 0)
                        {  //if not passed as 2nd arg ...
                            Console.Write("\nEnter keycontainer number to export:  ");
                            keytoexport = GetArgNumber(Console.ReadLine(), 0, (uint)(ccount - 1));
                            if (keytoexport < 0)
                                break;
                        }

                        try
                        {
                            Console.WriteLine("\nKeycontainer {0} to export: {1}", keytoexport, containernames[keytoexport]);
                            if (KeyPal.ExportX509Public(keytoexport, containernames[keytoexport]))
                                Console.WriteLine("Successfully exported X509 SubjectPublicKeyInfo key");
                            else
                                Console.WriteLine("Failed to export X509 SubjectPublicKeyInfo key ");
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine(exc.Message);
                        }
                        break;





                    case "u":   //display unique key container name
                        containerid = itemtoview;
                        if (containerid < 0)
                        {  //if not passed as 2nd arg ...
                            Console.Write("\nEnter keycontainer number to display unique keycontainer:  ");
                            containerid = GetArgNumber(Console.ReadLine(), 0, (uint)(ccount - 1));
                            if (containerid < 0)
                                break;
                        }

                        try
                        {
                            Console.WriteLine("\nKeycontainer {0} : {1}", containerid, containernames[containerid]);
                            String uniquename = KeyPal.GetUniqueContainerName(containernames[containerid]);
                            Console.WriteLine("Uniquecontainer:\n{0}", uniquename);
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine(exc.Message);
                        }
                        break;

                    case "d":   //view PUBLICkey details
                        keytoexport = itemtoview;
                        if (keytoexport < 0)
                        {  //if not passed as 2nd arg ...
                            Console.Write("\nEnter keycontainer number to display:  ");
                            keytoexport = GetArgNumber(Console.ReadLine(), 0, (uint)(ccount - 1));
                            if (keytoexport < 0)
                                break;
                        }

                        try
                        {
                            Console.WriteLine("\nKeycontainer {0} to display: {1}", keytoexport, containernames[keytoexport]);
                            KeyPal.ExportKeyBlobs(keytoexport, containernames[keytoexport], PUBLICKEYBLOB, false);
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine(exc.Message);
                        }
                        break;


                    case "dv"://view PRIVATEkey details
                        keytoexport = itemtoview;
                        if (keytoexport < 0)
                        {  //if not passed as 2nd arg ...
                            Console.Write("\nEnter keycontainer number to display:  ");
                            keytoexport = GetArgNumber(Console.ReadLine(), 0, (uint)(ccount - 1));
                            if (keytoexport < 0)
                                break;
                        }

                        try
                        {
                            Console.WriteLine("\nKeycontainer {0} to display: {1}", keytoexport, containernames[keytoexport]);
                            KeyPal.ExportKeyBlobs(keytoexport, containernames[keytoexport], PRIVATEKEYBLOB, false);
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine(exc.Message);
                        }
                        break;




                    case "del": //delete key container
                        containerid = itemtoview;
                        if (containerid < 0)
                        {  //if not passed as 2nd arg ...
                            Console.Write("\nEnter keycontainer number to DELETE:  ");
                            containerid = GetArgNumber(Console.ReadLine(), 0, (uint)(ccount - 1));
                            if (containerid < 0)
                                break;
                        }
                        Console.WriteLine("\nKeycontainer {0} : {1}", containerid, containernames[containerid]);
                        if (DeletePROVRSAFULLKeyContainer(containernames[containerid]))
                            Console.WriteLine("Deleted key container {0}", containernames[containerid]);
                        else
                            Console.WriteLine("FAILED to delete key container {0}", containernames[containerid]);
                        break;


                    case "cu":
                        setCUStore();
                        Console.WriteLine("Using Current User keystore");
                        break;

                    case "m":
                        setLMStore();
                        Console.WriteLine("Using Machine keystore");
                        break;

                    case "lm":
                        setLMStore();
                        Console.WriteLine("Using Machine keystore");
                        break;


                    case "r":   //refresh
                        UpdateContainerInfo();
                        break;

                    case "l":   //refresh
                        UpdateContainerInfo();
                        break;

                    case "cls": //clear screen
                        Win32.system("cls");
                        break;

                    case "cl":  //clear screen
                        Win32.system("cls");
                        break;

                    case "i":       //show command information
                        showInfo();
                        break;

                    default:  //ignore any other arguments
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("\nUnrecognized command  '{0}'", arg1);
                        Console.ForegroundColor = ConsoleColor.White;
                        showInfo();
                        break;
                }  //end switch
            }  //end while(true)
        }





        private static IntPtr CreateUnsignedCertCntxt(String keycontainer, uint KEYSPEC, uint cspflags, String DN)
        {

            const uint X509_ASN_ENCODING = 0x00000001;
            const uint CERT_X500_NAME_STR = 3;
            IntPtr hCertCntxt = IntPtr.Zero;
            byte[] encodedName = null;
            uint cbName = 0;

            if (Win32.CertStrToName(X509_ASN_ENCODING, DN, CERT_X500_NAME_STR, IntPtr.Zero, null, ref cbName, IntPtr.Zero))
            {
                encodedName = new byte[cbName];
                Win32.CertStrToName(X509_ASN_ENCODING, DN, CERT_X500_NAME_STR, IntPtr.Zero, encodedName, ref cbName, IntPtr.Zero);
                //Console.WriteLine("Encoded name string has {0} bytes", cbName) ;
                //showBytes("Encoded SubjectName: ", encodedName, ConsoleColor.Yellow) ;
            }

            CERT_NAME_BLOB subjectblob = new CERT_NAME_BLOB();
            subjectblob.pbData = Marshal.AllocHGlobal(encodedName.Length);
            Marshal.Copy(encodedName, 0, subjectblob.pbData, encodedName.Length);
            subjectblob.cbData = encodedName.Length;


            CRYPT_KEY_PROV_INFO pInfo = new CRYPT_KEY_PROV_INFO();
            pInfo.pwszContainerName = keycontainer;
            pInfo.pwszProvName = MS_DEF_PROV;
            pInfo.dwProvType = PROV_RSA_FULL;
            pInfo.dwFlags = cspflags;
            pInfo.cProvParam = 0;
            pInfo.rgProvParam = IntPtr.Zero;
            pInfo.dwKeySpec = KEYSPEC;


            hCertCntxt = Win32.CertCreateSelfSignCertificate(IntPtr.Zero, ref subjectblob, CERT_CREATE_SELFSIGN_NO_SIGN, ref pInfo, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            if (hCertCntxt == IntPtr.Zero)
            {
                Console.WriteLine("Couldn't create unsigned certificate");
                showWin32Error(Marshal.GetLastWin32Error());
            }

            Marshal.FreeHGlobal(subjectblob.pbData);
            return hCertCntxt;
        }



        private static int GetArgNumber(String arg, uint minnumber, uint maxnumber)
        {
            int ret = -1;
            try
            {
                ret = Int32.Parse(arg);
                if (ret < minnumber || ret > maxnumber)
                {  //out of valid range
                    Console.WriteLine("Number out of range [{0} to {1}]", minnumber, maxnumber);
                    ret = -1;
                }
            }
            catch
            {   //number format exceptions; 
                Console.WriteLine("Not a valid number");
                ret = -1;
            }
            return ret;
        }


        private static void UpdateContainerInfo()
        {
            uint type = PROV_RSA_FULL;
            uint cspflags = CSPKEYTYPE;
            uint keylength = 0;
            uint datalen = 4;  //bytes
            IntPtr hProv = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            ccount = 0;

            //--------- Get all CU keycontainers -------------------
            containernames = KeyPal.GetContainerNames();
            //---- Get all CU keycontainers associated with CU MY store certs ----
            //---- Store as hastable: key=containername; value= CERTPROPS_INFO instance ---
            certcontainernames = KeyPal.GetCertContainernames();


            if (containernames == null)
            {
                Console.WriteLine("Couldn't get containernames");
                return;
            }

            if (CSPKEYTYPE == CRYPT_MACHINE_KEYSET)
                Console.WriteLine("\n--------- {0}:  MACHINE store: {1} keycontainers ---------", TITLE, containernames.Length);
            else
                Console.WriteLine("\n--------- {0}:  CurrentUser store: {1} keycontainers ---------", TITLE, containernames.Length);


            foreach (String container in containernames)
            {
                Console.WriteLine("[{0}] {1}  ", ccount++, container);
                hProv = IntPtr.Zero;

                if (Win32.CryptAcquireContext(ref hProv, container, MS_DEF_PROV, type, cspflags)
                   || Win32.CryptAcquireContext(ref hProv, container, MS_STRONG_PROV, type, cspflags)
                   || Win32.CryptAcquireContext(ref hProv, container, MS_ENHANCED_PROV, type, cspflags))

                {
                    if (Win32.CryptGetUserKey(hProv, AT_KEYEXCHANGE, ref hKey))
                    {
                        Console.Write("     Exchange  ");
                        if (Win32.CryptGetKeyParam(hKey, KP_KEYLEN, ref keylength, ref datalen, 0))
                            Console.Write("{0}", keylength);
                        Console.WriteLine("");
                        Win32.CryptDestroyKey(hKey);
                    }
                    if (Win32.CryptGetUserKey(hProv, AT_SIGNATURE, ref hKey))
                    {
                        Console.Write("     Signature ");
                        if (Win32.CryptGetKeyParam(hKey, KP_KEYLEN, ref keylength, ref datalen, 0))
                            Console.Write("{0}", keylength);
                        Console.WriteLine("");
                        Win32.CryptDestroyKey(hKey);
                    }
                }
                else
                    showWin32Error(Marshal.GetLastWin32Error());


                // Note that there is a possibility that a given key container which has both
                // KEYEXCHANGE and SIGNATURE keypairs, will have certs associated with BOTH keypairs.

                if (certcontainernames.ContainsKey(container + "EX"))
                    Console.WriteLine("     CertE: {0}", ((CERTPROPS_INFO)certcontainernames[container + "EX"]).Name);
                if (certcontainernames.ContainsKey(container + "SIG"))
                    Console.WriteLine("     CertS: {0}", ((CERTPROPS_INFO)certcontainernames[container + "SIG"]).Name);

                if (hProv != IntPtr.Zero)
                    Win32.CryptReleaseContext(hProv, 0);
            }

            Console.WriteLine("-------------------------------------------------");
        }



        private static void ShowAllCertsDialog(int storenameindex, StoreLocation loc)
        {
            String storename = null;
            // foreach ( string s in Enum.GetNames(typeof(StoreName)))
            // Console.WriteLine( "{0}", s);
            try
            {
                storename = Enum.GetName(typeof(StoreName), storenameindex);
                X509Store store = new X509Store(storename, loc);
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                String Title = storename + "  " + loc + " store";
                String certtext = store.Certificates.Count + " certificates in " + storename + " store";
                X509Certificate2Collection fcollection = (X509Certificate2Collection)store.Certificates;
                X509Certificate2UI.SelectFromCollection(fcollection, Title, certtext, X509SelectionFlag.SingleSelection);
            }
            catch (Exception) { Console.WriteLine("Couldn't open {0}  {1} store", storename, loc); }
        }





        // ---- finds by sha1 hash cert in CU MY cert store ---
        private static void ShowCertbyHash(byte[] sha1hash)
        {
            IntPtr hSysStore = IntPtr.Zero;
            IntPtr hCertCntxt = IntPtr.Zero;

            if (sha1hash.Length != 20)   //not a sha1 hash
                return;

            uint openflags = storetype | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG;
            hSysStore = Win32.CertOpenStore("System", ENCODING_TYPE, IntPtr.Zero, openflags, MYSTORE);
            //  hSysStore = Win32.CertOpenSystemStore(IntPtr.Zero, MYSTORE) ;
            if (hSysStore == IntPtr.Zero)
                return;

            //--- initialize struct and allocate memory for hashblob data --
            HASH_BLOB hashb = new HASH_BLOB();
            hashb.pbData = Marshal.AllocHGlobal(sha1hash.Length);
            Marshal.Copy(sha1hash, 0, hashb.pbData, sha1hash.Length);
            hashb.cbData = sha1hash.Length;

            //----  Is there a MY store matching certificate? -----
            hCertCntxt = Win32.CertFindCertificateInStore(
               hSysStore,
               ENCODING_TYPE,
               0,
               CERT_FIND_HASH,
               ref hashb,
               IntPtr.Zero);

            if (hCertCntxt != IntPtr.Zero)
            {  //show certificate properties panel
                PCCRYPTUI_VIEWCERTIFICATE_STRUCT vcstruct = new PCCRYPTUI_VIEWCERTIFICATE_STRUCT();
                vcstruct.dwSize = (uint)Marshal.SizeOf(vcstruct);
                vcstruct.pCertContext = hCertCntxt;
                vcstruct.szTitle = "KeyPal Certificate Display";
                vcstruct.nStartPage = 0;
                bool propschanged = false;
                Win32.CryptUIDlgViewCertificate(ref vcstruct, ref propschanged); //show the cert
            }

            //-------  Clean Up  -----------
            Marshal.FreeHGlobal(hashb.pbData);
            if (hCertCntxt != IntPtr.Zero)
                Win32.CertFreeCertificateContext(hCertCntxt);
            if (hSysStore != IntPtr.Zero)
                Win32.CertCloseStore(hSysStore, 0);
        }




        private static string GetUniqueContainerName(String containername)
        {
            const int BUFFSIZE = 256;
            uint pcbData = BUFFSIZE;
            uint cspflags = CSPKEYTYPE;
            uint dwFlags = 0;
            uint type = PROV_RSA_FULL;
            uint dwparam = PP_UNIQUE_CONTAINER;
            string retname = null;
            IntPtr hProv = IntPtr.Zero;

            if (Win32.CryptAcquireContext(ref hProv, containername, MS_DEF_PROV, type, cspflags)
               || Win32.CryptAcquireContext(ref hProv, containername, MS_STRONG_PROV, type, cspflags)
               || Win32.CryptAcquireContext(ref hProv, containername, MS_ENHANCED_PROV, type, cspflags))

            {
                StringBuilder sb = new StringBuilder(BUFFSIZE);
                if (Win32.CryptGetProvParam(hProv, dwparam, sb, ref pcbData, dwFlags))
                    retname = sb.ToString();
            }
            if (hProv != IntPtr.Zero)
                Win32.CryptReleaseContext(hProv, 0);
            return retname;
        }



        private static bool ExportPkcs12(int number, String keycontainer, uint KEYSPEC)
        {
            byte[] pfxblob = null;
            IntPtr hProv = IntPtr.Zero;
            IntPtr hCertCntxt = IntPtr.Zero;
            IntPtr hCertStore = IntPtr.Zero;
            IntPtr pKeyInfo = IntPtr.Zero;

            String DN = "CN=KeyPal Unsigned Certificate";

            uint cspflags = CSPKEYTYPE;
            uint pcbInfo = 0;

            Console.WriteLine();

            if (!Win32.CryptAcquireContext(ref hProv, keycontainer, MS_DEF_PROV, PROV_RSA_FULL, cspflags))
            {
                Console.WriteLine("Couldn't get crypt context for keycontainer {0}", keycontainer);
                return false;
            }


            if (!Win32.CryptExportPublicKeyInfoEx(hProv, KEYSPEC, ENCODING_TYPE, szOID_RSA_RSA, 0, IntPtr.Zero, IntPtr.Zero, ref pcbInfo))
            {
                Console.WriteLine("Keycontainer does not have a keypair of type {0}", keyspecs[KEYSPEC]);
                Win32.CryptReleaseContext(hProv, 0);
                return false;
            }

            pKeyInfo = Marshal.AllocHGlobal((int)pcbInfo);
            Win32.CryptExportPublicKeyInfoEx(hProv, KEYSPEC, ENCODING_TYPE, szOID_RSA_RSA, 0, IntPtr.Zero, pKeyInfo, ref pcbInfo);
            //Console.WriteLine("\nMemory allocated for exported CERT_PUBLIC_KEY_INFO  {0} bytes", pcbInfo) ; 

            int keylength = Win32.CertGetPublicKeyLength(ENCODING_TYPE, pKeyInfo);
            Console.WriteLine("Keylength: {0} bits", keylength);

            uint openflags = storetype | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG;
            hCertStore = Win32.CertOpenStore("System", ENCODING_TYPE, IntPtr.Zero, openflags, MYSTORE);


            hCertCntxt = Win32.CertFindCertificateInStore(hCertStore, ENCODING_TYPE, 0, CERT_FIND_PUBLIC_KEY, pKeyInfo, IntPtr.Zero);

            if (hCertCntxt != IntPtr.Zero)
                Console.WriteLine("Found certificate matching the specified container keypair\n");
            else
            {
                Console.WriteLine("NO certificate matching the specified container keypair.\nCreating an unsigned dummy certificate ..");
                hCertCntxt = CreateUnsignedCertCntxt(keycontainer, KEYSPEC, cspflags, DN);
                if (hCertCntxt != IntPtr.Zero)
                    Console.WriteLine("Created an unsigned-certificate context\n");

            }

            Console.WriteLine("Trying to export {0} keypair and certificate to pkcs12 ... ", keyspecs[KEYSPEC]);

            try
            {
                X509Certificate cert = new X509Certificate(hCertCntxt);  //create certificate object from cert context.
                SecureString pswd = GetSecPswd();
                pfxblob = cert.Export(X509ContentType.Pkcs12, pswd);
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.Message);
                pfxblob = null;
            }

            if (pfxblob != null)
                Console.WriteLine("Successfully exported to pkcs12\n");
            else
            {
                Console.WriteLine("PROBLEM exporting to pkcs12\n");
                return false;
            }


            if (KEYSPEC == AT_KEYEXCHANGE)
            {
                DumpCert(hCertCntxt, "dercert_EX.cer");
                Console.WriteLine();
                showBytes("pfx blob:", pfxblob, ConsoleColor.Magenta);
                WriteBlob("pfxselfsigned" + number + "_EX.pfx", pfxblob);
            }
            else
            {
                DumpCert(hCertCntxt, "dercert_SIG.cer");
                Console.WriteLine();
                showBytes("pfx blob:", pfxblob, ConsoleColor.Magenta);
                WriteBlob("pfxselfsigned" + number + "_SIG.pfx", pfxblob);
            }


            if (pKeyInfo != IntPtr.Zero)
                Marshal.FreeHGlobal(pKeyInfo);
            if (hCertCntxt != IntPtr.Zero)
                Win32.CertFreeCertificateContext(hCertCntxt);
            if (hCertStore != IntPtr.Zero)
                Win32.CertCloseStore(hCertStore, 0);
            if (hProv != IntPtr.Zero)
                Win32.CryptReleaseContext(hProv, 0);

            return true;
        }




        //-------  Export or display either PUBLICKEYBLOB, or unencrypted PRIVATEKEYBLOB -------------
        private static bool ExportKeyBlobs(int number, String containername, uint blobspec, bool fileblob)
        {
            uint type = PROV_RSA_FULL;
            uint cspflags = CSPKEYTYPE;
            IntPtr hProv = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            IntPtr hExpKey = IntPtr.Zero;
            uint blobtype = blobspec;
            if (blobtype != PUBLICKEYBLOB && blobtype != PRIVATEKEYBLOB)
                return false;

            String blobname = blobnames[blobtype];

            uint dataLen = 0;
            byte[] pbData;
            bool retvalue = true;

            if (Win32.CryptAcquireContext(ref hProv, containername, MS_DEF_PROV, type, cspflags)
               || Win32.CryptAcquireContext(ref hProv, containername, MS_STRONG_PROV, type, cspflags)
               || Win32.CryptAcquireContext(ref hProv, containername, MS_ENHANCED_PROV, type, cspflags))

            {
                if (Win32.CryptGetUserKey(hProv, AT_KEYEXCHANGE, ref hKey))
                {
                    if (!Win32.CryptExportKey(hKey, hExpKey, blobtype, 0, null, ref dataLen))
                    {
                        showWin32Error(Marshal.GetLastWin32Error());
                        retvalue = false;
                    }
                    else
                    {
                        pbData = new byte[dataLen];  //assign buffer
                        if (!Win32.CryptExportKey(hKey, hExpKey, blobtype, 0, pbData, ref dataLen))
                            retvalue = false;
                        else
                        {
                            Console.WriteLine("Got exchange {0}: {1} bytes", blobname, dataLen);
                            if (fileblob)
                            {
                                WriteKeyBlob(blobname + number + "_EX", pbData);
                                WriteXMLKey(blobname + number + "_EX.txt", blobtype, CSPKEYTYPE, containername, AT_KEYEXCHANGE);
                            }
                            else
                                if (blobtype == PUBLICKEYBLOB)
                                DisplayKeyblob(pbData);
                            else
                                DisplayPVK(CSPKEYTYPE, containername, AT_KEYEXCHANGE);
                        }
                    }
                    Win32.CryptDestroyKey(hKey);
                }


                if (Win32.CryptGetUserKey(hProv, AT_SIGNATURE, ref hKey))
                {
                    if (!Win32.CryptExportKey(hKey, hExpKey, blobtype, 0, null, ref dataLen))
                    {
                        showWin32Error(Marshal.GetLastWin32Error());
                        retvalue = false;
                    }
                    else
                    {
                        pbData = new byte[dataLen];  //assign buffer
                        if (!Win32.CryptExportKey(hKey, hExpKey, blobtype, 0, pbData, ref dataLen))
                            retvalue = false;
                        else
                        {
                            Console.WriteLine("Got signature {0}: {1} bytes", blobname, dataLen);
                            if (fileblob)
                            {
                                WriteKeyBlob(blobname + number + "_SIG", pbData);
                                WriteXMLKey(blobname + number + "_SIG.txt", blobtype, CSPKEYTYPE, containername, AT_SIGNATURE);
                            }

                            else
                                if (blobtype == PUBLICKEYBLOB)
                                DisplayKeyblob(pbData);
                            else
                                DisplayPVK(CSPKEYTYPE, containername, AT_SIGNATURE);
                        }
                    }
                    Win32.CryptDestroyKey(hKey);
                }

                if (hProv != IntPtr.Zero)
                    Win32.CryptReleaseContext(hProv, 0);
                return retvalue;
            }
            return retvalue;
        }




        //-------  Export to pkcs #8 unencrypted PrivateKeyInfo (for Java and OpenSSL usage)  -------------
        private static bool ExportPkcs8(int number, String containername)
        {
            String blobname = "pkcs8_";
            uint type = PROV_RSA_FULL;
            uint cspflags = CSPKEYTYPE;
            IntPtr hProv = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;

            uint cbPkcs8 = 0;
            bool retvalue = false;

            if (Win32.CryptAcquireContext(ref hProv, containername, MS_DEF_PROV, type, cspflags)
               || Win32.CryptAcquireContext(ref hProv, containername, MS_STRONG_PROV, type, cspflags)
               || Win32.CryptAcquireContext(ref hProv, containername, MS_ENHANCED_PROV, type, cspflags))

            {
                if (Win32.CryptExportPKCS8(hProv, AT_KEYEXCHANGE, szOID_RSA_RSA, 0, IntPtr.Zero, null, ref cbPkcs8))
                {
                    byte[] pbPkcs8 = new byte[cbPkcs8];
                    Win32.CryptExportPKCS8(hProv, AT_KEYEXCHANGE, szOID_RSA_RSA, 0x8000, IntPtr.Zero, pbPkcs8, ref cbPkcs8);
                    showBytes("PKCS #8 exchange", pbPkcs8, ConsoleColor.DarkGray);
                    WriteKeyBlob(blobname + number + "_EX", pbPkcs8);
                    retvalue = true;
                }

                if (Win32.CryptExportPKCS8(hProv, AT_SIGNATURE, szOID_RSA_RSA, 0, IntPtr.Zero, null, ref cbPkcs8))
                {
                    byte[] pbPkcs8 = new byte[cbPkcs8];
                    Win32.CryptExportPKCS8(hProv, AT_SIGNATURE, szOID_RSA_RSA, 0x8000, IntPtr.Zero, pbPkcs8, ref cbPkcs8);
                    showBytes("PKCS #8 signature", pbPkcs8, ConsoleColor.DarkGray);
                    WriteKeyBlob(blobname + number + "_SIG", pbPkcs8);
                    retvalue = true;
                }

                if (hProv != IntPtr.Zero)
                    Win32.CryptReleaseContext(hProv, 0);
            }
            return retvalue;
        }




        //-------  Export public key as X509 SubjectPublicKeyInfo  and PEM encoded version (for Java, OpenSSL etc..)  -------------
        private static bool ExportX509Public(int number, String containername)
        {
            uint type = PROV_RSA_FULL;
            uint cspflags = CSPKEYTYPE;
            IntPtr hProv = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            IntPtr hExpKey = IntPtr.Zero;

            uint dataLen = 0;
            byte[] RSAkey;  // the asn.1 RSAPublicKey
            byte[] X509key; // the ans.1 SubjectPublicKeyInfo
            byte[] pbData;  // the PUBLICKEYBLOB
            bool retvalue = true;
            uint blobtype = PUBLICKEYBLOB;
            String blobname = "X509public" + number;
            String pemname = "PEMpublic" + number;

            if (Win32.CryptAcquireContext(ref hProv, containername, MS_DEF_PROV, type, cspflags)
               || Win32.CryptAcquireContext(ref hProv, containername, MS_STRONG_PROV, type, cspflags)
               || Win32.CryptAcquireContext(ref hProv, containername, MS_ENHANCED_PROV, type, cspflags))

            {
                if (Win32.CryptGetUserKey(hProv, AT_KEYEXCHANGE, ref hKey))
                {
                    if (!Win32.CryptExportKey(hKey, hExpKey, blobtype, 0, null, ref dataLen))
                    {
                        showWin32Error(Marshal.GetLastWin32Error());
                        retvalue = false;
                    }
                    else
                    {
                        pbData = new byte[dataLen];  //assign buffer
                        if (!Win32.CryptExportKey(hKey, hExpKey, blobtype, 0, pbData, ref dataLen))
                            retvalue = false;
                        else
                        {
                            RSAkey = EncodetoRSAKey(pbData);
                            X509key = EncodetoSubjectPublicKeyInfo(RSAkey);
                            Console.WriteLine("Got exchange public key:\n  PUBLICKEYBLOB {0} bytes  RSAKey {1} bytes  X509Key {2} bytes",
                                pbData.Length, RSAkey.Length, X509key.Length);
                            WriteKeyBlob(blobname + "_EX", X509key);
                            WriteKeyBlob(pemname + "_EX.txt", Encoding.ASCII.GetBytes(GetPEMPublicKey(X509key)));
                        }
                    }
                    Win32.CryptDestroyKey(hKey);
                }


                if (Win32.CryptGetUserKey(hProv, AT_SIGNATURE, ref hKey))
                {
                    if (!Win32.CryptExportKey(hKey, hExpKey, blobtype, 0, null, ref dataLen))
                    {
                        showWin32Error(Marshal.GetLastWin32Error());
                        retvalue = false;
                    }
                    else
                    {
                        pbData = new byte[dataLen];  //assign buffer
                        if (!Win32.CryptExportKey(hKey, hExpKey, blobtype, 0, pbData, ref dataLen))
                            retvalue = false;
                        else
                        {
                            RSAkey = EncodetoRSAKey(pbData);
                            X509key = EncodetoSubjectPublicKeyInfo(RSAkey);
                            Console.WriteLine("Got signature public key:\n  PUBLICKEYBLOB {0} bytes  RSAKey {1} bytes  X509Key {2} bytes",
                                pbData.Length, RSAkey.Length, X509key.Length);
                            WriteKeyBlob(blobname + "_SIG", X509key);
                            WriteKeyBlob(pemname + "_SIG.txt", Encoding.ASCII.GetBytes(GetPEMPublicKey(X509key)));
                        }
                    }
                    Win32.CryptDestroyKey(hKey);
                }

                if (hProv != IntPtr.Zero)
                    Win32.CryptReleaseContext(hProv, 0);
                return retvalue;
            }
            return retvalue;
        }





        // ---  Encode from  PUBLICKEYBLOB to ans.1 RSAPublicKey format ----
        private static byte[] EncodetoRSAKey(byte[] keydata)
        {
            uint cbytes = 0;
            if (Win32.CryptEncodeObject(ENCODING_TYPE, RSA_CSP_PUBLICKEYBLOB, keydata, null, ref cbytes))
            {
                byte[] rsakey = new byte[cbytes];
                Win32.CryptEncodeObject(ENCODING_TYPE, RSA_CSP_PUBLICKEYBLOB, keydata, rsakey, ref cbytes);
                return rsakey;
            }
            else
            {
                return null;
            }
        }




        // ---  Encode from  asn.1 RSAPublicKey  to ans.1 SubjectPublicKeyInfo format ----
        private static byte[] EncodetoSubjectPublicKeyInfo(byte[] keydata)
        {
            IntPtr p1 = Marshal.AllocHGlobal(2);
            Marshal.WriteInt16(p1, 0x0005);  // write 2 byte BER asn.1 null sequence  {05, 00} ;
            IntPtr p2 = Marshal.AllocHGlobal(keydata.Length);
            Marshal.Copy(keydata, 0, p2, keydata.Length);

            CERT_PUBLIC_KEY_INFO certpublickeyinfo = new CERT_PUBLIC_KEY_INFO();
            certpublickeyinfo.SubjPKIAlgpszObjId = szOID_RSA_RSA;
            certpublickeyinfo.SubjPKIAlgParameterscbData = 2;
            certpublickeyinfo.SubjPKIAlgParameterspbData = p1;
            certpublickeyinfo.PublicKeycbData = keydata.Length;
            certpublickeyinfo.PublicKeypbData = p2;

            uint cbytes = 0;
            if (Win32.CryptEncodeObject(ENCODING_TYPE, X509_PUBLIC_KEY_INFO, ref certpublickeyinfo, null, ref cbytes))
            {
                byte[] encoded = new byte[cbytes];
                Win32.CryptEncodeObject(ENCODING_TYPE, X509_PUBLIC_KEY_INFO, ref certpublickeyinfo, encoded, ref cbytes);
                Marshal.FreeHGlobal(p1);
                Marshal.FreeHGlobal(p2);
                return encoded;
            }
            else
            {
                return null;
            }
        }






        private static void DisplayKeyblob(byte[] keyblob)
        {
            PUBKEYBLOBHEADERS pkheaders = new PUBKEYBLOBHEADERS();
            int headerslength = Marshal.SizeOf(pkheaders);
            IntPtr buffer = Marshal.AllocHGlobal(headerslength);
            Marshal.Copy(keyblob, 0, buffer, headerslength);
            pkheaders = (PUBKEYBLOBHEADERS)Marshal.PtrToStructure(buffer, typeof(PUBKEYBLOBHEADERS));
            Marshal.FreeHGlobal(buffer);

            Console.WriteLine("\n ---- PUBLICKEYBLOB headers ------");
            Console.WriteLine("  btype     {0}", pkheaders.bType);
            Console.WriteLine("  bversion  {0}", pkheaders.bVersion);
            Console.WriteLine("  reserved  {0}", pkheaders.reserved);
            Console.WriteLine("  aiKeyAlg  0x{0:x8}", pkheaders.aiKeyAlg);
            String magicstring = (new ASCIIEncoding()).GetString(BitConverter.GetBytes(pkheaders.magic));
            Console.WriteLine("  magic     0x{0:x8}     '{1}'", pkheaders.magic, magicstring);
            Console.WriteLine("  bitlen    {0}", pkheaders.bitlen);
            Console.WriteLine("  pubexp    {0}", pkheaders.pubexp);
            Console.WriteLine(" --------------------------------");

            //-----  Get public exponent ------
            byte[] exponent = BitConverter.GetBytes(pkheaders.pubexp); //little-endian ordered
            Array.Reverse(exponent);    //convert to big-endian order
            showBytes("\nPublic key exponent (big-endian order):", exponent, ConsoleColor.Green);

            //-----  Get modulus  -----
            int modulusbytes = (int)pkheaders.bitlen / 8;
            byte[] modulus = new byte[modulusbytes];
            try
            {
                Array.Copy(keyblob, headerslength, modulus, 0, modulusbytes);
                Array.Reverse(modulus);   //convert from little to big-endian ordering.
                showBytes("\nPublic key modulus  (big-endian order):", modulus, ConsoleColor.Green);
            }
            catch (Exception)
            {
                Console.WriteLine("Problem getting modulus from publickeyblob");
            }
        }


        private static bool DeletePROVRSAFULLKeyContainer(String containername)
        {
            IntPtr hCryptProv = IntPtr.Zero;
            if (containername == null)
                return false;

            Console.WriteLine("Do you want to DELETE key container:\n'" + containername + "'  ? ");
            string ans = Console.ReadLine();
            if (ans == null || !ans.StartsWith("y", StringComparison.InvariantCultureIgnoreCase))
                return false;


            if (Win32.CryptAcquireContext(ref hCryptProv, containername, null, PROV_RSA_FULL, CRYPT_DELETEKEYSET | CSPKEYTYPE))
            {
                return true;
            }
            else
            {
                showWin32Error(Marshal.GetLastWin32Error());
                return false;
            }
        }


        private static void WriteKeyBlob(String keyblobfile, byte[] keydata)
        {
            FileStream fs = null;
            if (File.Exists(keyblobfile))
            {
                Console.WriteLine("File '{0}' already exists!", keyblobfile);
                return;
            }
            try
            {
                fs = new FileStream(keyblobfile, FileMode.CreateNew);
                fs.Write(keydata, 0, keydata.Length);
                Console.WriteLine("Wrote keyblob file '{0}'", keyblobfile);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                fs.Close();
            }
        }



        private static void WriteBlob(String keyblobfile, byte[] keydata)
        {
            if (keydata == null)
            {
                Console.WriteLine("No data to write");
                return;
            }
            FileStream fs = null;
            try
            {
                fs = new FileStream(keyblobfile, FileMode.Create);
                fs.Write(keydata, 0, keydata.Length);
                Console.WriteLine("Wrote file '{0}'", keyblobfile);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                fs.Close();
            }
        }



        //-----------  Uses existing keycontainer keys (with given keyspec) to export XML key file.
        //----- NOTE:  If the named keycontainer does not exist, it will be created! ------
        // ---- NOTE:  If the keycontainer exists, but the keyspec type doesn't, it will BE CREATED ----

        private static void WriteXMLKey(String fname, uint blobspec, uint CSPKEYTYPE, String keycontainer, uint keyspec)
        {
            String keyblobfile = null;
            keyblobfile = "XML" + fname;

            CspParameters csparms = new CspParameters();
            csparms.KeyContainerName = keycontainer;
            csparms.KeyNumber = (int)keyspec;
            if (CSPKEYTYPE == CRYPT_MACHINE_KEYSET)
                csparms.Flags = CspProviderFlags.UseMachineKeyStore;

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csparms);
            if (blobspec == PRIVATEKEYBLOB)
                WriteKeyBlob(keyblobfile, Encoding.ASCII.GetBytes(rsa.ToXmlString(true)));
            else
                WriteKeyBlob(keyblobfile, Encoding.ASCII.GetBytes(rsa.ToXmlString(false)));
        }




        private static void DisplayPVK(uint CSPKEYTPE, String keycontainer, uint keyspec)
        {
            RSAParameters rsaParams;
            CspParameters csparms = new CspParameters();
            csparms.KeyContainerName = keycontainer;
            csparms.KeyNumber = (int)keyspec;
            if (CSPKEYTYPE == CRYPT_MACHINE_KEYSET)
                csparms.Flags = CspProviderFlags.UseMachineKeyStore;
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csparms);
            try
            {
                rsaParams = rsa.ExportParameters(true);
            }
            catch (Exception)
            {
                Console.WriteLine("Private key is not exportable\n");
                return;
            }

            //Display all private key components
            showBytes("Modulus", rsaParams.Modulus, ConsoleColor.DarkGray);
            Console.Write("\n\n");
            showBytes("Exponent", rsaParams.Exponent, ConsoleColor.DarkGray);
            Console.Write("\n\n");
            showBytes("P", rsaParams.P, ConsoleColor.DarkGray);
            Console.Write("\n\n");
            showBytes("Q", rsaParams.Q, ConsoleColor.DarkGray);
            Console.Write("\n\n");
            showBytes("DP", rsaParams.DP, ConsoleColor.DarkGray);
            Console.Write("\n\n");
            showBytes("DQ", rsaParams.DQ, ConsoleColor.DarkGray);
            Console.Write("\n\n");
            showBytes("InverseQ", rsaParams.InverseQ, ConsoleColor.DarkGray);
            Console.Write("\n\n");
            showBytes("D", rsaParams.D, ConsoleColor.DarkGray);
            Console.Write("\n\n");
        }


        private static String GetPEMPublicKey(byte[] x509key)
        {
            StringBuilder sb = new StringBuilder("-----BEGIN PUBLIC KEY-----\r\n");
            sb.Append(Convert.ToBase64String(x509key));
            sb.Append("\r\n-----END PUBLIC KEY-----");
            return sb.ToString();
        }



        private static string[] GetContainerNames()
        {
            int BUFFSIZE = 512;
            ArrayList containernames = new ArrayList();
            uint pcbData = 0;
            String provider = null; //can use null, for default provider
            String container = null;   //required for crypt_verifycontext 
            uint type = PROV_RSA_FULL;
            uint cspflags = CRYPT_VERIFYCONTEXT | CSPKEYTYPE;   //no private key access required.
            uint enumflags = PP_ENUMCONTAINERS;  //specify container enumeration functdionality
            IntPtr hProv = IntPtr.Zero;
            uint dwFlags = CRYPT_FIRST;

            bool gotcsp = Win32.CryptAcquireContext(ref hProv, container, provider, type, cspflags);
            if (!gotcsp)
            {
                showWin32Error(Marshal.GetLastWin32Error());
                return null;
            }


            StringBuilder sb = null;
            Win32.CryptGetProvParam(hProv, enumflags, sb, ref pcbData, dwFlags);
            BUFFSIZE = (int)(2 * pcbData);
            sb = new StringBuilder(BUFFSIZE);

            /*  ----------  Get KeyContainer Names ------------- */
            dwFlags = CRYPT_FIRST;  //required initalization
            while (Win32.CryptGetProvParam(hProv, enumflags, sb, ref pcbData, dwFlags))
            {
                dwFlags = 0;            //required to continue entire enumeration
                containernames.Add(sb.ToString());
            }
            if (hProv != IntPtr.Zero)
                Win32.CryptReleaseContext(hProv, 0);

            if (containernames.Count == 0)
                return null;
            else
                return (string[])containernames.ToArray(Type.GetType("System.String"));
        }



        // -- Find all certs in MY store that have associated private keys -----
        // -- Two different certs may be associated with the 2 different keypairs in a given
        //   container. Therefore, annotate Hashtable key value keycontainer with "SIG" and "EX" 
        //   suffix to differentiate.

        private static Hashtable GetCertContainernames()
        {
            IntPtr hSysStore = IntPtr.Zero;
            IntPtr hCertCntxt = IntPtr.Zero;
            IntPtr pProvInfo = IntPtr.Zero;
            uint provinfosize = 0;
            Hashtable containernames = new Hashtable();  //zero Count
            X509Certificate foundcert = null;
            uint openflags = storetype | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG;

            hSysStore = Win32.CertOpenStore("System", ENCODING_TYPE, IntPtr.Zero, openflags, MYSTORE);
            if (hSysStore == IntPtr.Zero)
            {
                Console.WriteLine("Couldn't get certificate store handle");
                return containernames;
            }

            while ((hCertCntxt = Win32.CertEnumCertificatesInStore(hSysStore, hCertCntxt)) != IntPtr.Zero)
            {
                if (Win32.CertGetCertificateContextProperty(hCertCntxt, CERT_KEY_PROV_INFO_PROP_ID, IntPtr.Zero, ref provinfosize))
                {
                    pProvInfo = Marshal.AllocHGlobal((int)provinfosize);
                }
                else
                {
                    showWin32Error(Marshal.GetLastWin32Error());
                    continue;
                }
                if (Win32.CertGetCertificateContextProperty(hCertCntxt, CERT_KEY_PROV_INFO_PROP_ID, pProvInfo, ref provinfosize))
                {
                    CRYPT_KEY_PROV_INFO ckinfo = (CRYPT_KEY_PROV_INFO)Marshal.PtrToStructure(pProvInfo, typeof(CRYPT_KEY_PROV_INFO));
                    // Marshal.FreeHGlobal(pProvInfo);
                    foundcert = new X509Certificate(hCertCntxt);
                    CERTPROPS_INFO certpinfo = new CERTPROPS_INFO(foundcert.GetCertHash(), foundcert.Subject);
                    //----- key is container name with keytype suffix;  value is CERTPROPS_INFO instance
                    if (ckinfo.dwKeySpec == AT_KEYEXCHANGE)
                        containernames.Add(ckinfo.pwszContainerName + "EX", certpinfo);
                    else if (ckinfo.dwKeySpec == AT_SIGNATURE)
                        containernames.Add(ckinfo.pwszContainerName + "SIG", certpinfo);
                }
            } // end while

            //-------  Clean Up  -----------
            if (pProvInfo != IntPtr.Zero)
                Marshal.FreeHGlobal(pProvInfo);
            if (hCertCntxt != IntPtr.Zero)
                Win32.CertFreeCertificateContext(hCertCntxt);
            if (hSysStore != IntPtr.Zero)
                Win32.CertCloseStore(hSysStore, 0);
            return containernames;
        }



        private static void DumpCert(IntPtr hCertCntxt, String fname)
        {
            CERT_CONTEXT cntxt = (CERT_CONTEXT)Marshal.PtrToStructure(hCertCntxt, typeof(CERT_CONTEXT));
            Console.WriteLine("Certificate blob size: {0} bytes", cntxt.cbCertEncoded);
            byte[] dercert = new byte[cntxt.cbCertEncoded];
            Marshal.Copy(cntxt.pbCertEncoded, dercert, 0, cntxt.cbCertEncoded);    //get the DER certificate
            showBytes("\nDER unsigned certificate: ", dercert, ConsoleColor.Yellow);
            WriteBlob(fname, dercert);
        }



        private static void showBytes(String info, byte[] data, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine("{0}  [{1} bytes]", info, data.Length);

            if (displayarrayform)
            {
                for (int i = 1; i < data.Length; i++)
                {
                    Console.Write("0x{0:X2}, ", data[i - 1]);
                    if (i % 12 == 0)
                        Console.WriteLine();
                }
                Console.Write("0x{0:X2}", data[data.Length - 1]);
            }
            else
                for (int i = 1; i <= data.Length; i++)
                {
                    Console.Write("{0:X2}  ", data[i - 1]);
                    if (i % 16 == 0)
                        Console.WriteLine();
                }

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
        }


        private static SecureString GetSecPswd()
        {
            SecureString password = new SecureString();

            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Set PFX Password ==> ");
            Console.ForegroundColor = ConsoleColor.Magenta;

            while (true)
            {
                ConsoleKeyInfo cki = Console.ReadKey(true);
                if (cki.Key == ConsoleKey.Enter)
                {
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine();
                    return password;
                }
                else if (cki.Key == ConsoleKey.Backspace)
                {
                    // remove the last asterisk from the screen...
                    if (password.Length > 0)
                    {
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                        Console.Write(" ");
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                        password.RemoveAt(password.Length - 1);
                    }
                }
                else if (cki.Key == ConsoleKey.Escape)
                {
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine();
                    return password;
                }
                else if (Char.IsLetterOrDigit(cki.KeyChar) || Char.IsSymbol(cki.KeyChar))
                {
                    if (password.Length < 20)
                    {
                        password.AppendChar(cki.KeyChar);
                        Console.Write("*");
                    }
                    else
                    {
                        Console.Beep();
                    }
                }
                else
                {
                    Console.Beep();
                }
            }
        }




        private static void setCUStore()
        {
            storetype = CERT_SYSTEM_STORE_CURRENT_USER;
            storeloc = StoreLocation.CurrentUser;
            CSPKEYTYPE = 0;
            KeyPal.UpdateContainerInfo();
        }

        private static void setLMStore()
        {
            storetype = CERT_SYSTEM_STORE_LOCAL_MACHINE;
            storeloc = StoreLocation.LocalMachine;
            CSPKEYTYPE = CRYPT_MACHINE_KEYSET;
            KeyPal.UpdateContainerInfo();
        }



        private static void showInfo()
        {
            Console.WriteLine(
             "\n'i' to display this information\n" +
             "'CU' to use Current User keystore; 'LM' or 'M' to use Machine keystore\n" +
             "'P n'  to export to PUBLICKEYBLOB and XML publickey\n" +
             "'PV n' to export to PRIVATEKEYBLOB and XML privatekey\n" +
             "'J n'  to export to X509 SubjectPublicKeyInfo and PEM public key\n" +
             "'P8 n' to export to PKCS #8 PrivateKeyInfo\n" +
             "'P12S/E' to export Signature or Exchange keypair to pkcs#12\n" +
             "'D n' to display PUBLICKEYBLOB, 'C n' to view Cert, 'A' to view all certs\n" +
             "'DV n' to display all PRIVATE key components\n" +
             "'An' to view store n where:\n" +
             "   1=AddressBook 2=AuthRoot 3=CertificateAuthority 4=Disallowed\n" +
             "   5=My 6=Root 7=TrustedPeople 8=TrustedPublisher\n" +
             "'U n' to show uniquecontainername, 'DEL n' to delete key container\n" +
             "'R/L' to refresh, 'CLS' to clear screen, or 'Q/<Return>' to Exit");
        }

        private static void showWin32Error(int errorcode)
        {
            Win32Exception myEx = new Win32Exception(errorcode);
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Error code:\t 0x{0:X}", myEx.ErrorCode);
            Console.WriteLine("Error message:\t {0}\n", myEx.Message);
            Console.ForegroundColor = ConsoleColor.White;
        }

    }
}