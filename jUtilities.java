package nz.ope.jutilities;

import anywheresoftware.b4a.BA;
import anywheresoftware.b4a.BA.Author;
import anywheresoftware.b4a.BA.DependsOn;
import anywheresoftware.b4a.BA.ShortName;
import anywheresoftware.b4a.BA.Version;
import anywheresoftware.b4a.keywords.Common;
import anywheresoftware.b4a.objects.collections.Map;
import anywheresoftware.b4a.objects.collections.List;

import java.net.URI;
import java.net.URL;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.Socket;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;

import java.text.Normalizer;
import java.text.SimpleDateFormat;
import java.text.DateFormat;

import javax.net.ssl.HttpsURLConnection;

import javax.xml.XMLConstants;
import javax.xml.transform.*;
import javax.xml.transform.stream.*;

import java.awt.Desktop;

import java.io.File;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import java.util.UUID;
import java.util.Date;
import java.util.HashMap;
import java.util.Scanner;
import java.util.Date;
import java.util.TimeZone;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Locale;
import java.util.Base64;

import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.ProtectionDomain;
import java.security.CodeSource;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.CopyOption;
import java.nio.file.StandardCopyOption;
import java.nio.file.*;
import java.nio.file.attribute.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

@Version(1.3f)
@ShortName("jUtilities")

public class jUtilities {
	// Opens an address in the default browser
	public void OpenAddressInBrowser(String paramString) {
		try {
			Desktop localDesktop = Desktop.getDesktop();
			localDesktop.browse(new URI(paramString));
		} catch (Exception e) {
			Common.Log(e.toString());
		}
	}

	// Sleep for X milliseconds
	public void Sleep(int milliseconds) {
		try {
			Thread.sleep(milliseconds);
		} catch (Exception e) {
			Common.Log(e.toString());
		}
	}

	public String PathSeparator() {
		return File.pathSeparator;
	}

	public String FileSeparator() {
		return File.separator;
	}

	public boolean Rename(String From, String To) {
		try {
			File fileFrom = new File(From);
			File fileTo = new File(To);
			// if ((fileFrom.exists() ? 0 : !fileTo.exists() ? 1 : 0) != 0)
			// {
			return fileFrom.renameTo(fileTo);
			// }
		} catch (Exception e) {
			Common.Log(e.toString());
		}

		return false;
	}

	public String randomUUID() {
		UUID uuid = UUID.randomUUID();
		return uuid.toString();
	}

	public String randomUUIDNoDashes() {
		String uuid = randomUUID();
		uuid = uuid.replace("-", "");
		uuid = uuid.replace("{", "");
		uuid = uuid.replace("}", "");
		return uuid;
	}

	public String randomPasswordString(int Length) {
		String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		SecureRandom rnd = new SecureRandom();

		StringBuilder sb = new StringBuilder(Length);
		for (int i = 0; i < Length; i++)
			sb.append(AB.charAt(rnd.nextInt(AB.length())));
		return sb.toString();
	}

	public String FileExt(String paramString) {
		int i = paramString.lastIndexOf(File.separator);
		int j;
		if (((j = paramString.lastIndexOf(".")) > i ? 1 : 0) != 0) {
			return paramString.substring(j);
		}
		return "";
	}

	public String FileName(String paramString) {
		int i;
		if (((i = paramString.lastIndexOf(File.separator)) < 0 ? 1 : 0) != 0) {
			return paramString;
		}
		if (paramString.endsWith(File.separator)) {
			return "";
		}
		return paramString.substring(i + File.separator.length());
	}

	public String FileDir(String paramString) {
		int i;
		if (((i = paramString.lastIndexOf(File.separator)) < 0 ? 1 : 0) != 0) {
			return "";
		}
		return paramString.substring(0, i);
	}

	public String JavaVersion() {
		return System.getProperty("java.version");
	}

	public String getHostAddress() {
		try {
			InetAddress localInetAddress = InetAddress.getLocalHost();
			return localInetAddress.getHostAddress();
		} catch (Exception e) {
			return e.toString();
		}
	}

	public String getExternalAddress() {
		try {
			URL url = new URL("http://checkip.amazonaws.com/");
			BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));
			return br.readLine();
		} catch (Exception e) {
			return e.toString();
		}
	}

	public String getHostName() {
		try {
			InetAddress localInetAddress = InetAddress.getLocalHost();
			return localInetAddress.getHostName();
		} catch (Exception e) {
			Common.Log(e.toString());
			return "";
		}
	}

	public String getCanonicalHostName() {
		try {
			InetAddress localInetAddress = InetAddress.getLocalHost();
			return localInetAddress.getCanonicalHostName();
		} catch (Exception e) {
			Common.Log(e.toString());
		}
		return "";
	}

	public String getCanonicalHostNameFromIP(String IP) {
		try {
			InetAddress addr = InetAddress.getByName(IP);
			return addr.getCanonicalHostName();
		} catch (Exception e) {
			Common.Log("ERROR: " + e.getMessage());
		}
		return "";
	}

	public String getHostNameFromIP(String IP) {
		try {
			InetAddress addr = InetAddress.getByName(IP);
			return addr.getHostName();
		} catch (Exception e) {
			Common.Log("ERROR: " + e.getMessage());
		}
		return "";
	}

	public boolean IsReachableHostName(String HostName, int timeOut) {
		try {
			InetAddress inet;
			inet = InetAddress.getByName(HostName);
			if (inet.isReachable(timeOut))
				return true;
		} catch (IOException e) {
			Common.Log("ERROR: " + e.getMessage());
		}
		return false;
	}

	public boolean IsReachableIP(String IP, int timeOut) {
		try {
			String[] arrIP = IP.split("\\.");

			if (arrIP.length == 4) {
				InetAddress inet;
				inet = InetAddress
						.getByAddress(new byte[] { (byte) Integer.parseInt(arrIP[0]), (byte) Integer.parseInt(arrIP[1]),
								(byte) Integer.parseInt(arrIP[2]), (byte) Integer.parseInt(arrIP[3]) });
				if (inet.isReachable(timeOut))
					return true;
			}
		} catch (Exception e) {
			Common.Log("ERROR: " + e.getMessage());
		}

		return false;
	}

	public static boolean isPortInUse(String host, int port, int timeout) {
        try (Socket socket = new Socket()) {
            InetSocketAddress socketAddress = new InetSocketAddress(host, port);
            socket.connect(socketAddress, timeout);
            return true; // Port is in use
        } catch (Exception e) {
            return false; // Port is available or an error occurred
        }
    }

	public Long PingPort(String address, int port, int timeout) {
		Long t1 = System.currentTimeMillis();

		Socket psocket = new Socket();
		try {
			// Connects this socket to the server with a specified timeout value.
			psocket.connect(new InetSocketAddress(address, port), timeout);
			psocket.close();
		} catch (Exception e) {
			Common.Log("ERROR: Ping timeout");
			// return -1L;
		}

		return System.currentTimeMillis() - t1;
	}

	public String MacAddressFromClient() {
		String macAddress = "";
		String str = "";
		try {
			InetAddress localInetAddress = InetAddress.getLocalHost();

			macAddress += localInetAddress.getHostAddress();
			NetworkInterface localNetworkInterface = NetworkInterface.getByInetAddress(localInetAddress);
			byte[] arrayOfByte1 = localNetworkInterface.getHardwareAddress();

			int i = 0;
			for (int m : arrayOfByte1) {
				if (m < 0) {
					m = 256 + m;
				}
				if (m == 0) {
					str = str.concat("00");
				}
				if (m > 0) {
					int n = m / 16;
					if (n == 10) {
						str = str.concat("A");
					} else if (n == 11) {
						str = str.concat("B");
					} else if (n == 12) {
						str = str.concat("C");
					} else if (n == 13) {
						str = str.concat("D");
					} else if (n == 14) {
						str = str.concat("E");
					} else if (n == 15) {
						str = str.concat("F");
					} else {
						str = str.concat(String.valueOf(n));
					}
					n = m % 16;
					if (n == 10) {
						str = str.concat("A");
					} else if (n == 11) {
						str = str.concat("B");
					} else if (n == 12) {
						str = str.concat("C");
					} else if (n == 13) {
						str = str.concat("D");
					} else if (n == 14) {
						str = str.concat("E");
					} else if (n == 15) {
						str = str.concat("F");
					} else {
						str = str.concat(String.valueOf(n));
					}
				}
				if (i < arrayOfByte1.length - 1) {
					str = str.concat("-");
				}
				i++;
			}
		} catch (UnknownHostException localUnknownHostException) {
			str = localUnknownHostException.getMessage();
		} catch (SocketException localSocketException) {
			str = localSocketException.getMessage();
		}
		return str;
	}

	public String GetDefaultGateway() {
		try {
			Process process = Runtime.getRuntime().exec("nslookup localhost");

			try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
				String line;
				while ((line = bufferedReader.readLine()) != null) {
					line = line.trim().toLowerCase();
					if (line.startsWith("server:") || line.startsWith("address:")) {
						String address = line.substring(line.indexOf(":") + 1).trim();
						if (address.contains("."))
							return address;
					}

					if (line.length() == 0)
						return "";
				}
			}
		} catch (Exception e) {
			Common.Log("ERROR: " + e.getMessage());
		}

		return "";
	}

	public static String GetTimeStamp() {
		String _day = "";
		String _mon = "";
		String _yr = "";
		String _hr = "";
		String _mi = "";
		String _ss = "";
		long _now = 0L;

		_day = "";
		_mon = "";
		_yr = "";
		_hr = "";
		_mi = "";
		_ss = "";

		_now = anywheresoftware.b4a.keywords.Common.DateTime.getNow();

		_day = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetDayOfMonth(_now));
		if (_day.length() == 1)
			_day = "0" + _day;

		_mon = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetMonth(_now));
		if (_mon.length() == 1)
			_mon = "0" + _mon;

		_yr = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetYear(_now));

		_hr = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetHour(_now));
		if (_hr.length() == 1)
			_hr = "0" + _hr;

		_mi = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetMinute(_now));
		if (_mi.length() == 1)
			_mi = "0" + _mi;

		_ss = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetSecond(_now));
		if (_ss.length() == 1)
			_ss = "0" + _ss;

		return _yr + _mon + _day + "_" + _hr + _mi + "_" + _ss;
	}

	public static int CountOccurences(String sPattern, String sText) {
		int _spatternlength = 0;
		int _stextlength = 0;
		int _i = 0;
		int _result = 0;

		_spatternlength = 0;
		_stextlength = 0;
		_i = 0;
		_result = 0;

		_spatternlength = sPattern.length();
		_stextlength = sText.length();

		_result = (int) (0);

		final int step7 = 1;
		final int limit7 = (int) (_stextlength - _spatternlength);

		for (_i = (int) (0); (step7 > 0 && _i <= limit7)
				|| (step7 < 0 && _i >= limit7); _i = ((int) (0 + _i + step7))) {
			if ((sPattern).equals(sText.substring(_i, (int) (_i + _spatternlength))))
				_result = (int) (_result + 1);
		}

		return _result;
	}

	public static String Boolean2Required(boolean Input) {
		if (Input == anywheresoftware.b4a.keywords.Common.True)
			return " required";
		return "";
	}

	public static String Boolean2Text(boolean Input) {
		if (Input == anywheresoftware.b4a.keywords.Common.True)
			return "True";
		return "False";
	}

	public static boolean Int2Boolean(int Input) {
		if (Input == 1)
			return anywheresoftware.b4a.keywords.Common.True;
		return anywheresoftware.b4a.keywords.Common.False;
	}

	public static String ReverseBoolean2Required(boolean Input) {
		if (Input == anywheresoftware.b4a.keywords.Common.True)
			return "";
		return " required";
	}

	public static String ReverseBoolean2Text(boolean Input) {
		if (Input == anywheresoftware.b4a.keywords.Common.True)
			return "False";
		return "True";
	}

	public String EncodeUrl(String Url, String CharSet) {
		try {
			return URLEncoder.encode(Url, CharSet);
		} catch (Exception e) {
			return e.toString();
		}
	}

	public String DecodeUrl(String Url, String CharSet) {
		try {
			return URLDecoder.decode(Url, CharSet);
		} catch (Exception e) {
			return e.toString();
		}
	}

	public String DecryptString(String InputText, String Password)
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException,
			NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		byte[] Data = DecodeBase64(InputText);

		byte[] salt = new byte[8];
		byte[] iv = new byte[16];
		System.arraycopy(Data, 0, salt, 0, 8);
		System.arraycopy(Data, 8, iv, 0, 16);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec keySpec = new PBEKeySpec(Password.toCharArray(), salt, 1024, 128);
		SecretKey tmp = factory.generateSecret(keySpec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES"); 
		Cipher d = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Should use AES/GCM/NoPadding
		d.init(2, secret, new IvParameterSpec(iv));
		byte[] t = new byte[Data.length - 24];
		System.arraycopy(Data, 24, t, 0, t.length);

		byte[] dec = d.doFinal(t);

		String output = new String(dec);

		return output;
	}

	public String EncryptString(String InputText, String Password)
			throws InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException,
			NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		byte[] Data = InputText.getBytes();

		SecureRandom rnd = new SecureRandom();
		byte[] salt = new byte[8];
		rnd.nextBytes(salt);
		byte[] iv = new byte[16];
		rnd.nextBytes(iv);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec keySpec = new PBEKeySpec(Password.toCharArray(), salt, 1024, 128);
		SecretKey tmp = factory.generateSecret(keySpec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
		Cipher d = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Should use AES/GCM/NoPadding
		d.init(1, secret, new IvParameterSpec(iv));
		byte[] enc = d.doFinal(Data);
		byte[] plain = new byte[enc.length + 24];
		System.arraycopy(salt, 0, plain, 0, 8);
		System.arraycopy(iv, 0, plain, 8, 16);
		System.arraycopy(enc, 0, plain, 24, enc.length);

		return EncodeBase64(plain);
	}

	public String EncodeBase64(byte[] Data) {
		//return Base64.encodeBytes(Data);
		return Base64.getEncoder().encodeToString(Data);
	}

	public byte[] DecodeBase64(String Data) throws IOException {
		//return Base64.decode(Data);
		return Base64.getDecoder().decode(Data);
	}

	public String StringToHex(String Data) {
		StringBuffer sb = new StringBuffer();
		
		try{
			char ch[] = Data.toCharArray();
			for (int i = 0; i < ch.length; i++) {
				String hexString = Integer.toHexString(ch[i]);
				sb.append(hexString);
			}
		}
		catch (Exception e){
			Common.Log("ERROR: " + e.getMessage());
		}
		
		return sb.toString().toUpperCase();
	}

	public String HexToString(String Data) {
		String result = new String();
		
		try{
			char[] charArray = Data.toCharArray();
			for (int i = 0; i < charArray.length; i = i + 2) {
				String st = "" + charArray[i] + "" + charArray[i + 1];
				char ch = (char) Integer.parseInt(st, 16);
				result = result + ch;
			}
		}
		catch (Exception e){
			Common.Log("ERROR: " + e.getMessage());
		}		
		
		return result;
	}

	public static boolean IsAdmin() {
		String groups[] = (new com.sun.security.auth.module.NTSystem()).getGroupIDs();
		for (String group : groups) {
			if (group.equals("S-1-5-32-544"))
				return true;
		}
		return false;
	}

	/*
	 * public static boolean IsAdmin2(){ Preferences prefs =
	 * Preferences.systemRoot(); PrintStream systemErr = System.err;
	 * synchronized(systemErr){ // better synchroize to avoid problems with other
	 * threads that access System.err System.setErr(null); try{ prefs.put("foo",
	 * "bar"); // SecurityException on Windows prefs.remove("foo"); prefs.flush();
	 * // BackingStoreException on Linux return true; }catch(Exception e){ return
	 * false; }finally{ System.setErr(systemErr); } } }
	 */

	public static boolean IsWindows(){
		return System.getProperty("os.name").toLowerCase().contains("windows");
	}

	public void extractFolder(String zipFile, String extractFolder) {
		try {
			int BUFFER = 2048;
			File file = new File(zipFile);

			ZipFile zip = new ZipFile(file);
			String newPath = extractFolder;

			newPath = newPath.replaceAll(" - /", " - Blank/");

			Common.Log(newPath);

			new File(newPath).mkdir();
			Enumeration zipFileEntries = zip.entries();

			// Process each entry
			while (zipFileEntries.hasMoreElements()) {
				// grab a zip file entry
				ZipEntry entry = (ZipEntry) zipFileEntries.nextElement();
				String currentEntry = entry.getName();

				File destFile;

				// if (currentEntry.endsWith(" - ")) currentEntry = currentEntry+"_";

				currentEntry = currentEntry.replaceAll(" - /", " - Blank/");

				Common.Log(currentEntry);

				// if (currentEntry.endsWith(".json") || currentEntry.endsWith(".arc"))
				// {
				// URI outputURI = new URI(("file:///"+ newPath.replaceAll(" ",
				// "%20").replaceAll("\\", "/") + "/" + currentEntry));
				// destFile = new File(outputURI);
				// }
				// else
				// {
				destFile = new File(newPath, currentEntry);
				// }

				File destinationParent = destFile.getParentFile();

				// create the parent directory structure if needed
				destinationParent.mkdirs();

				if (!entry.isDirectory()) {
					BufferedInputStream is = new BufferedInputStream(zip.getInputStream(entry));
					int currentByte;
					// establish buffer for writing file
					byte data[] = new byte[BUFFER];

					// write the current file to disk
					FileOutputStream fos = new FileOutputStream(destFile);
					BufferedOutputStream dest = new BufferedOutputStream(fos, BUFFER);

					// read and write until last byte is encountered
					while ((currentByte = is.read(data, 0, BUFFER)) != -1) {
						dest.write(data, 0, currentByte);
					}
					dest.flush();
					dest.close();
					is.close();
				}
			}
		} catch (Exception e) {
			Common.Log("ERROR: " + e.getMessage());
		}
	}

	public long getServerCertificateExpiry(String URL) throws Exception {
		try {
			URL destinationURL = new URL(URL);

			HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
			conn.connect();

			Certificate[] certs = conn.getServerCertificates();
			for (Certificate cert : certs) {
				if (cert instanceof X509Certificate) {
					X509Certificate x509cert = (X509Certificate) cert;
					Date date = x509cert.getNotAfter();
					long epoch = date.getTime();
					conn.disconnect();
					return epoch;
				}
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return -1;
	}

	// Java method to create SHA-25 checksum
	public String getSHA256Hash(String data) {
		String result = null;
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(data.getBytes("UTF-8"));

			StringBuilder sb = new StringBuilder();
			for (byte b : hash) {
				sb.append(String.format("%02x", b));
			}
			return sb.toString();

		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return result;
	}

	// Java method to create MD5 checksum
	public String getMD5Hash(String data) {
		String result = null;
		try {
			MessageDigest digest = MessageDigest.getInstance("MD5");
			byte[] hash = digest.digest(data.getBytes("UTF-8"));

			StringBuilder sb = new StringBuilder();
			for (byte b : hash) {
				sb.append(String.format("%02x", b));
			}
			return sb.toString();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return result;
	}

	// Return the process id of the current process
	public long getJVMPID() {
		String processName = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
		return Long.parseLong(processName.split("@")[0]);
	}

	// Return uptime of the VM
	public long getJVMUptime() {
		return java.lang.management.ManagementFactory.getRuntimeMXBean().getUptime();
	}

	// Return VM system properties
	public Map getJVMSystemProperties() {
		java.util.Map<String, String> mSystemProperties = java.lang.management.ManagementFactory.getRuntimeMXBean()
				.getSystemProperties();

		Map mResult = new Map();
		mResult.Initialize();

		for (java.util.Map.Entry<String, String> entry : mSystemProperties.entrySet()) {
			mResult.Put(entry.getKey(), entry.getValue());
		}
		return mResult;
	}

	// Return VM arguments
	public List getJVMArguments() {
		java.util.List<String> InputArguments = java.lang.management.ManagementFactory.getRuntimeMXBean()
				.getInputArguments();

		List L = new List();
		L.Initialize();

		for (String InputArgument : InputArguments) {
			L.Add(InputArgument);
		}

		return L;
	}

	// Return a specific EnvironmentVariable
	public String EnvironmentVariable(String Name) {
		return System.getenv(Name);
	}

	// Return all EnvironmentVariables as a map
	public Map getEnvironmentVariables() {
		java.util.Map<String, String> env = System.getenv();

		Map mResult = new Map();
		mResult.Initialize();

		for (String envName : env.keySet()) {
			mResult.Put(envName, env.get(envName));
		}
		return mResult;
	}

	// Runs the garbage collector.
	public void JVMgc() {
		System.gc();
	}

	/**
	 * Tests if the String possibly represents a valid JSON String.<br>
	 * Valid JSON strings are:
	 * <ul>
	 * <li>"null"</li>
	 * <li>starts with "[" and ends with "]"</li>
	 * <li>starts with "{" and ends with "}"</li>
	 * </ul>
	 */
	public static boolean mayBeJSON(String string) {
		return string != null && string.length() > 0
				&& ("null".equals(string) || (string.startsWith("[") && string.endsWith("]"))
						|| (string.startsWith("{") && string.endsWith("}")));
	}
	
	public static boolean mayBeBinary(byte[] data) {
        for (byte b : data) {
            // Check if the byte falls outside the range of printable ASCII characters
            if (b < 32 || b > 126) {
                return true; // Byte is outside the ASCII range, indicating binary data
            }
        }
        return false; // All bytes fall within the ASCII range, indicating ASCII characters
    }

	public static String statusWindowsService(String ServiceName) {
		String Result = "NOT FOUND";

		try {
			Process process = Runtime.getRuntime().exec("sc query " + ServiceName);
			Scanner reader = new Scanner(process.getInputStream(), "UTF-8");
			while (reader.hasNextLine()) {
				String Line = reader.nextLine().trim();
				if (Line.contains("STATE")) {
					Result = Line.substring(Line.lastIndexOf(" "));
					// if(Line.contains("RUNNING")) Result = "RUNNING";
					// if(Line.contains("STOPPED")) Result = "STOPPED";
				}
			}
		} catch (Exception ex) {
			Result = "ERROR";
		}

		return Result.trim();
	}

	public static String ToPrettyPrintXML(String xmlString, int Indent) {
		try {
			Source xmlInput = new StreamSource(new StringReader(xmlString));
			StringWriter stringWriter = new StringWriter();
			StreamResult xmlOutput = new StreamResult(stringWriter);
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			transformerFactory.setAttribute("indent-number", Indent);
			//transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
			//transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
			Transformer transformer = transformerFactory.newTransformer(); 
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			transformer.transform(xmlInput, xmlOutput);
			return xmlOutput.getWriter().toString();
		} catch (Exception e) {
			throw new RuntimeException(e); // simple exception handling, please review it
		}
	}

	public Map ReadPropertiesFile(String filename) {
		Map mResult = new Map();
		mResult.Initialize();

		try (InputStream input = new FileInputStream(filename)) {
			Properties prop = new Properties();

			if (input == null)
				return mResult;
			prop.load(input);

			// Java 8 , print key and values
			prop.forEach((key, value) -> mResult.Put(key, value));
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return mResult;
	}

	public List getJarContent(String jarPath) {
		List L = new List();
		L.Initialize();

		try {
			JarFile jarFile = new JarFile(jarPath);
			Enumeration<JarEntry> e = jarFile.entries();
			while (e.hasMoreElements()) {
				JarEntry entry = (JarEntry) e.nextElement();				
				String entryName = entry.getName();				
				if(entryName.startsWith("Files")) L.Add(entryName);
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		
		return L;
	}

	public static String FlattenToAscii(String string)
	{
		StringBuilder sb = new StringBuilder(string.length());
		string = Normalizer.normalize(string, Normalizer.Form.NFD);
		for (char c : string.toCharArray()) {
			if (c <= '\u007F') sb.append(c);
		}
		return sb.toString();
	}
	
	
	  public static String hexConvert(byte[] buf)
	  {
		if (buf == null) return null;
		int length = buf.length;		   
        StringBuffer stringBuffer = new StringBuffer(2 * length);
        for (byte b1 = 0; b1 < length; ) {
           stringBuffer.append("0123456789ABCDEF".charAt((buf[b1] & 0xF0) >> 4));
           stringBuffer.append("0123456789ABCDEF".charAt(buf[b1] & 0xF));
		   b1++; 
		}
		return stringBuffer.toString();
    }
	
	public static String getIntArrayCode(String string) {

        int[] result = new int[string.length()];
        for (int i = 0; i < string.length(); i++) {

            int numericValue = Character.codePointAt(string, i);
            result[i] = numericValue << 3;
        }
        
        StringBuffer arrayCode = new StringBuffer();
        arrayCode.append("new int[]{");
        for (int i = 0; i < result.length; i++) {
            arrayCode.append(result[i]);
            if (i < result.length - 1) {
                arrayCode.append(",");
            }
        }

        arrayCode.append("}");

        return arrayCode.toString();
    }

	public static Map getFileAttributes(String FilePath)
	{
		Map mResult = new Map();
		mResult.Initialize();

		try{
			Path filePath = Paths.get(FilePath);		
	
			// Read the file attributes
			BasicFileAttributes basicAttributes = Files.readAttributes(filePath, BasicFileAttributes.class);
			DosFileAttributes dosAttributes = Files.readAttributes(filePath, DosFileAttributes.class);
	
			mResult.Put("creationTime", basicAttributes.creationTime().toMillis());
			mResult.Put("isRegularFile", basicAttributes.isRegularFile());
			mResult.Put("isSymbolicLink", basicAttributes.isSymbolicLink());
			mResult.Put("lastAccessTime", basicAttributes.lastAccessTime().toMillis());
			mResult.Put("lastModifiedTime", basicAttributes.lastModifiedTime().toMillis());
	
			mResult.Put("isHidden", dosAttributes.isHidden());
			mResult.Put("isArchive", dosAttributes.isArchive());
			mResult.Put("isReadOnly", dosAttributes.isReadOnly());
			mResult.Put("isSystem", dosAttributes.isSystem());
		}
		catch (Exception e) {
			Common.Log(e.toString());
		}			

		return mResult;
	}

	public static String getCallerMethodName() {
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        StackTraceElement caller = stackTrace[3];
        return caller.getMethodName();
    }

	public List getStackTrace() {
		List L = new List();
		L.Initialize();

        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();

		for (int i = 0; i < stackTrace.length; i++) {
            StackTraceElement caller = stackTrace[i];
			String MethodName = caller.getMethodName();
			if (MethodName.startsWith("_")) L.Add(MethodName);            
        }
        
        return L;
    }

	/**
	 * Parse a DateTime string with timezone offset (by name) and return Epoch
	 */
	public long DateTime_ZoneName(String DateTimeString, String DateTimeFormat, String TimeZoneName)
	{
		try
		{			
			TimeZone timeZone = TimeZone.getTimeZone(TimeZoneName);
        	int rawOffsetMillis = timeZone.getRawOffset();
        	int dstOffsetMillis = timeZone.getDSTSavings();
        	long TimeZoneOffset = rawOffsetMillis + dstOffsetMillis;
			
			SimpleDateFormat sdf = new SimpleDateFormat(DateTimeFormat);
			sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
			Date date = sdf.parse(DateTimeString);
			long epoch = date.getTime();
			
			// Adjust epoch time based on timezone offset
			epoch -= TimeZoneOffset;
			
			return epoch;
		}
		catch (Exception e)
		{
			Common.Log(e.toString());
			return -1L;
		}		
	}
	
	/**
	 * Parse a DateTime string with timezone offest (in hours) and return Epoch
	 */
	public long DateTime_ZoneOffset(String DateTimeString, String DateTimeFormat, double TimeZoneOffset)
	{
		try {			
			SimpleDateFormat sdf = new SimpleDateFormat(DateTimeFormat);
			sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
			Date date = sdf.parse(DateTimeString);
			long epoch = date.getTime();
			
			// Adjust epoch time based on timezone offset
			epoch -= (long)(TimeZoneOffset * 3600000L); // Convert hours to milliseconds	
			
			return epoch;
		}
		catch (Exception e) {
            Common.Log(e.toString());
			return -1L;
        }        
	}

	/**
	 * Parse a DateTime string with timezone offest (in hours) and return Epoch
	 */
	public long DateTime_Local(String DateTimeString, String DateTimeFormat)
	{
		try {		
			OffsetDateTime currentTime = OffsetDateTime.now();
			ZoneOffset offset = currentTime.getOffset();
			double TimeZoneOffset = offset.getTotalSeconds() / 3600.0;			
			
			SimpleDateFormat sdf = new SimpleDateFormat(DateTimeFormat);
			sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
			Date date = sdf.parse(DateTimeString);
			long epoch = date.getTime();
			
			// Adjust epoch time based on timezone offset
			epoch -= (long)(TimeZoneOffset * 3600000L); // Convert hours to milliseconds	
			
			return epoch;
		}
		catch (Exception e) {
            Common.Log(e.toString());
			return -1L;
        }        
	}

	/**
	 * Parse a DateTime string (in UTC) and return Epoch
	 */
	public long DateTime_UTC(String DateTimeString, String DateTimeFormat)
	{
        SimpleDateFormat sdf = new SimpleDateFormat(DateTimeFormat);
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));

        try {
            Date date = sdf.parse(DateTimeString);
            long epoch = date.getTime();
            return epoch;
        }
		catch (Exception e) {
            Common.Log(e.toString());
			return -1L;
        }
	}

	/**
	 * Get the short date format for the default locale, falls back to 
	 */
	public String DateTime_ShortDateFormat()
	{
		try	{
			Locale locale = Locale.getDefault();
			DateFormat shortDateFormat = DateFormat.getDateInstance(DateFormat.MEDIUM,locale);
			String shortDateFormatPattern = ((SimpleDateFormat) shortDateFormat).toPattern();
			return shortDateFormatPattern;
		}
		catch (Exception e) {
            Common.Log(e.toString());
			return "yyyy-mm-dd";
        }        
	}

	public static String StringCompress(String Data) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		
        try (GZIPOutputStream gzipOutputStream = new GZIPOutputStream(outputStream)) {
            gzipOutputStream.write(Data.getBytes());
        }

        return Base64.getEncoder().encodeToString(outputStream.toByteArray());
    }

    public static String StringDecompress(String Data) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(Data));
             GZIPInputStream gzipInputStream = new GZIPInputStream(inputStream)) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = gzipInputStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, length);
            }
        }
        return outputStream.toString();
    }
}