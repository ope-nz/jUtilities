package nz.ope.jutilities;

import anywheresoftware.b4a.BA;
import anywheresoftware.b4a.BA.Author;
import anywheresoftware.b4a.BA.DependsOn;
import anywheresoftware.b4a.BA.ShortName;
import anywheresoftware.b4a.BA.Version;
import anywheresoftware.b4a.keywords.Common;

import java.net.URI;
import java.net.URL;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.net.URLDecoder;
import java.net.URLEncoder;

import javax.net.ssl.HttpsURLConnection;

import java.awt.Desktop;

import java.io.File;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.BufferedInputStream;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;

import java.util.UUID;
import java.util.Date;

import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.ProtectionDomain;
import java.security.CodeSource;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.MessageDigest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.CopyOption;
import java.nio.file.StandardCopyOption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

@Version(1.1f)
@ShortName(&quot;jUtilities&quot;)

public class jUtilities {
	public void OpenAddressInBrowser(String paramString) {
		try {
			Desktop localDesktop = Desktop.getDesktop();
			localDesktop.browse(new URI(paramString));
		} catch (Exception e) {
			Common.Log(e.toString());
		}
	}

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
		uuid = uuid.replace(&quot;-&quot;, &quot;&quot;);
		uuid = uuid.replace(&quot;{&quot;, &quot;&quot;);
		uuid = uuid.replace(&quot;}&quot;, &quot;&quot;);
		return uuid;
	}

	public String randomPasswordString(int Length) {
		String AB = &quot;0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz&quot;;
		SecureRandom rnd = new SecureRandom();

		StringBuilder sb = new StringBuilder(Length);
		for (int i = 0; i &lt; Length; i++)
			sb.append(AB.charAt(rnd.nextInt(AB.length())));
		return sb.toString();
	}

	public String FileExt(String paramString) {
		int i = paramString.lastIndexOf(File.separator);
		int j;
		if (((j = paramString.lastIndexOf(&quot;.&quot;)) &gt; i ? 1 : 0) != 0) {
			return paramString.substring(j);
		}
		return &quot;&quot;;
	}

	public String FileName(String paramString) {
		int i;
		if (((i = paramString.lastIndexOf(File.separator)) &lt; 0 ? 1 : 0) != 0) {
			return paramString;
		}
		if (paramString.endsWith(File.separator)) {
			return &quot;&quot;;
		}
		return paramString.substring(i + File.separator.length());
	}

	public String FileDir(String paramString) {
		int i;
		if (((i = paramString.lastIndexOf(File.separator)) &lt; 0 ? 1 : 0) != 0) {
			return &quot;&quot;;
		}
		return paramString.substring(0, i);
	}

	public String JavaVersion() {
		return System.getProperty(&quot;java.version&quot;);
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
			URL url = new URL(&quot;http://checkip.amazonaws.com/&quot;);
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
			return &quot;&quot;;
		}
	}

	public String getCanonicalHostName() {
		try {
			InetAddress localInetAddress = InetAddress.getLocalHost();
			return localInetAddress.getCanonicalHostName();
		} catch (Exception e) {
			Common.Log(e.toString());
		}
		return &quot;&quot;;
	}

	public String getCanonicalHostNameFromIP(String IP) {
		try {
			InetAddress addr = InetAddress.getByName(IP);
			return addr.getCanonicalHostName();
		} catch (Exception e) {
			Common.Log(&quot;ERROR: &quot; + e.getMessage());
		}
		return &quot;&quot;;
	}

	public String getHostNameFromIP(String IP) {
		try {
			InetAddress addr = InetAddress.getByName(IP);
			return addr.getHostName();
		} catch (Exception e) {
			Common.Log(&quot;ERROR: &quot; + e.getMessage());
		}
		return &quot;&quot;;
	}

	public String MacAddressFromClient() {
		String macAddress = &quot;&quot;;
		String str = &quot;&quot;;
		try {
			InetAddress localInetAddress = InetAddress.getLocalHost();

			macAddress += localInetAddress.getHostAddress();
			NetworkInterface localNetworkInterface = NetworkInterface.getByInetAddress(localInetAddress);
			byte[] arrayOfByte1 = localNetworkInterface.getHardwareAddress();

			int i = 0;
			for (int m : arrayOfByte1) {
				if (m &lt; 0) {
					m = 256 + m;
				}
				if (m == 0) {
					str = str.concat(&quot;00&quot;);
				}
				if (m &gt; 0) {
					int n = m / 16;
					if (n == 10) {
						str = str.concat(&quot;A&quot;);
					} else if (n == 11) {
						str = str.concat(&quot;B&quot;);
					} else if (n == 12) {
						str = str.concat(&quot;C&quot;);
					} else if (n == 13) {
						str = str.concat(&quot;D&quot;);
					} else if (n == 14) {
						str = str.concat(&quot;E&quot;);
					} else if (n == 15) {
						str = str.concat(&quot;F&quot;);
					} else {
						str = str.concat(String.valueOf(n));
					}
					n = m % 16;
					if (n == 10) {
						str = str.concat(&quot;A&quot;);
					} else if (n == 11) {
						str = str.concat(&quot;B&quot;);
					} else if (n == 12) {
						str = str.concat(&quot;C&quot;);
					} else if (n == 13) {
						str = str.concat(&quot;D&quot;);
					} else if (n == 14) {
						str = str.concat(&quot;E&quot;);
					} else if (n == 15) {
						str = str.concat(&quot;F&quot;);
					} else {
						str = str.concat(String.valueOf(n));
					}
				}
				if (i &lt; arrayOfByte1.length - 1) {
					str = str.concat(&quot;-&quot;);
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

	public static String GetTimeStamp() {
		String _day = &quot;&quot;;
		String _mon = &quot;&quot;;
		String _yr = &quot;&quot;;
		String _hr = &quot;&quot;;
		String _mi = &quot;&quot;;
		String _ss = &quot;&quot;;
		long _now = 0L;

		_day = &quot;&quot;;
		_mon = &quot;&quot;;
		_yr = &quot;&quot;;
		_hr = &quot;&quot;;
		_mi = &quot;&quot;;
		_ss = &quot;&quot;;

		_now = anywheresoftware.b4a.keywords.Common.DateTime.getNow();

		_day = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetDayOfMonth(_now));
		if (_day.length() == 1)
			_day = &quot;0&quot; + _day;

		_mon = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetMonth(_now));
		if (_mon.length() == 1)
			_mon = &quot;0&quot; + _mon;

		_yr = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetYear(_now));

		_hr = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetHour(_now));
		if (_hr.length() == 1)
			_hr = &quot;0&quot; + _hr;

		_mi = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetMinute(_now));
		if (_mi.length() == 1)
			_mi = &quot;0&quot; + _mi;

		_ss = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetSecond(_now));
		if (_ss.length() == 1)
			_ss = &quot;0&quot; + _ss;

		return _yr + _mon + _day + &quot;_&quot; + _hr + _mi + &quot;_&quot; + _ss;
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

		for (_i = (int) (0); (step7 &gt; 0 &amp;&amp; _i &lt;= limit7)
				|| (step7 &lt; 0 &amp;&amp; _i &gt;= limit7); _i = ((int) (0 + _i + step7))) {
			if ((sPattern).equals(sText.substring(_i, (int) (_i + _spatternlength))))
				_result = (int) (_result + 1);
		}

		return _result;
	}

	public static String Boolean2Required(boolean Input) {
		if (Input == anywheresoftware.b4a.keywords.Common.True)
			return &quot; required&quot;;
		return &quot;&quot;;
	}

	public static String Boolean2Text(boolean Input) {
		if (Input == anywheresoftware.b4a.keywords.Common.True)
			return &quot;True&quot;;
		return &quot;False&quot;;
	}

	public static boolean Int2Boolean(int Input) {
		if (Input == 1)
			return anywheresoftware.b4a.keywords.Common.True;
		return anywheresoftware.b4a.keywords.Common.False;
	}

	public static String ReverseBoolean2Required(boolean Input) {
		if (Input == anywheresoftware.b4a.keywords.Common.True)
			return &quot;&quot;;
		return &quot; required&quot;;
	}

	public static String ReverseBoolean2Text(boolean Input) {
		if (Input == anywheresoftware.b4a.keywords.Common.True)
			return &quot;False&quot;;
		return &quot;True&quot;;
	}

	public String EncodeUrl(String Url, String CharSet)
	{
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
		SecretKeyFactory factory = SecretKeyFactory.getInstance(&quot;PBKDF2WithHmacSHA1&quot;);
		KeySpec keySpec = new PBEKeySpec(Password.toCharArray(), salt, 1024, 128);
		SecretKey tmp = factory.generateSecret(keySpec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), &quot;AES&quot;);
		Cipher d = Cipher.getInstance(&quot;AES/CBC/PKCS5Padding&quot;);
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
		SecretKeyFactory factory = SecretKeyFactory.getInstance(&quot;PBKDF2WithHmacSHA1&quot;);
		KeySpec keySpec = new PBEKeySpec(Password.toCharArray(), salt, 1024, 128);
		SecretKey tmp = factory.generateSecret(keySpec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), &quot;AES&quot;);
		Cipher d = Cipher.getInstance(&quot;AES/CBC/PKCS5Padding&quot;);
		d.init(1, secret, new IvParameterSpec(iv));
		byte[] enc = d.doFinal(Data);
		byte[] plain = new byte[enc.length + 24];
		System.arraycopy(salt, 0, plain, 0, 8);
		System.arraycopy(iv, 0, plain, 8, 16);
		System.arraycopy(enc, 0, plain, 24, enc.length);

		return EncodeBase64(plain);
	}

	public String EncodeBase64(byte[] Data) {
		return Base64.encodeBytes(Data);
	}

	public byte[] DecodeBase64(String Data) throws IOException {
		return Base64.decode(Data);
	}

	public static boolean IsAdmin() {
		String groups[] = (new com.sun.security.auth.module.NTSystem()).getGroupIDs();
		for (String group : groups) {
			if (group.equals(&quot;S-1-5-32-544&quot;))
				return true;
		}
		return false;
	}

	/*
	 * public static boolean IsAdmin2(){ Preferences prefs =
	 * Preferences.systemRoot(); PrintStream systemErr = System.err;
	 * synchronized(systemErr){ // better synchroize to avoid problems with other
	 * threads that access System.err System.setErr(null); try{ prefs.put(&quot;foo&quot;,
	 * &quot;bar&quot;); // SecurityException on Windows prefs.remove(&quot;foo&quot;); prefs.flush();
	 * // BackingStoreException on Linux return true; }catch(Exception e){ return
	 * false; }finally{ System.setErr(systemErr); } } }
	 */

	public void extractFolder(String zipFile, String extractFolder) {
		try {
			int BUFFER = 2048;
			File file = new File(zipFile);

			ZipFile zip = new ZipFile(file);
			String newPath = extractFolder;

			newPath = newPath.replaceAll(&quot; - /&quot;, &quot; - Blank/&quot;);

			Common.Log(newPath);

			new File(newPath).mkdir();
			Enumeration zipFileEntries = zip.entries();

			// Process each entry
			while (zipFileEntries.hasMoreElements()) {
				// grab a zip file entry
				ZipEntry entry = (ZipEntry) zipFileEntries.nextElement();
				String currentEntry = entry.getName();

				File destFile;

				// if (currentEntry.endsWith(&quot; - &quot;)) currentEntry = currentEntry+&quot;_&quot;;

				currentEntry = currentEntry.replaceAll(&quot; - /&quot;, &quot; - Blank/&quot;);

				Common.Log(currentEntry);

				// if (currentEntry.endsWith(&quot;.json&quot;) || currentEntry.endsWith(&quot;.arc&quot;))
				// {
				// URI outputURI = new URI((&quot;file:///&quot;+ newPath.replaceAll(&quot; &quot;,
				// &quot;%20&quot;).replaceAll(&quot;\\&quot;, &quot;/&quot;) + &quot;/&quot; + currentEntry));
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
			Common.Log(&quot;ERROR: &quot; + e.getMessage());
		}
	}

	public long getServerCertificateExpiry(String URL) throws Exception
	{
		URL destinationURL = new URL(URL);

		HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
		conn.connect();

		Certificate[] certs = conn.getServerCertificates();
		for (Certificate cert : certs)
		{
			if(cert instanceof X509Certificate)
			{
				X509Certificate x509cert = (X509Certificate) cert;				
				Date date = x509cert.getNotAfter();
				long epoch = date.getTime();

				conn.disconnect();
				return epoch;
			}
		}

		return -1;
	}

	// Java method to create SHA-25 checksum
    public String getSHA256Hash(String data) {
        String result = null;
        try {
            MessageDigest digest = MessageDigest.getInstance(&quot;SHA-256&quot;);
            byte[] hash = digest.digest(data.getBytes(&quot;UTF-8&quot;));
			
			StringBuilder sb = new StringBuilder();
			for (byte b : hash) {
				sb.append(String.format(&quot;%02x&quot;, b));
			}
			return sb.toString();

        }catch(Exception ex) {
            ex.printStackTrace();
        }
        return result;
    }
 
    // Java method to create MD5 checksum
    public String getMD5Hash(String data) {
        String result = null;
        try {
            MessageDigest digest = MessageDigest.getInstance(&quot;MD5&quot;);
            byte[] hash = digest.digest(data.getBytes(&quot;UTF-8&quot;));
			
			StringBuilder sb = new StringBuilder();
			for (byte b : hash) {
				sb.append(String.format(&quot;%02x&quot;, b));
			}
			return sb.toString();
        }catch(Exception ex) {
            ex.printStackTrace();
        }
        return result;
    }
}