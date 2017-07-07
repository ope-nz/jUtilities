package com.tchart.jutilities;

import anywheresoftware.b4a.BA;
import anywheresoftware.b4a.BA.Author;
import anywheresoftware.b4a.BA.DependsOn;
import anywheresoftware.b4a.BA.ShortName;
import anywheresoftware.b4a.BA.Version;
import anywheresoftware.b4a.keywords.Common;

import java.net.URI;
import java.awt.Desktop;
import java.io.File;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.UUID;
import java.security.ProtectionDomain;
import java.security.CodeSource;
import java.security.SecureRandom;
import java.nio.file.Files;
import java.nio.file.Path;

import java.net.URL;
import java.nio.file.CopyOption;
import java.nio.file.StandardCopyOption;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;

@Version(1.0f)
@ShortName("jUtilities")

public class jUtilities
{
	public void OpenAddressInBrowser(String paramString)
	{
		try
		{
			Desktop localDesktop = Desktop.getDesktop();
			localDesktop.browse(new URI(paramString));
		}
		catch (Exception e)
		{
			Common.Log(e.toString());
		}
	}
  
	public void Sleep(int milliseconds)
	{
		try
		{
			Thread.sleep(milliseconds);
		}
		catch (Exception e)
		{	
			Common.Log(e.toString());
		}
	}
	
	public String PathSeparator()
	{
		return File.pathSeparator;
	}
	
	public String FileSeparator()
	{
		return File.separator;
	}
	
	public boolean Rename(String From, String To)
	{
		try
		{
			File fileFrom = new File(From);
			File fileTo = new File(To);
			//if ((fileFrom.exists() ? 0 : !fileTo.exists() ? 1 : 0) != 0)
			//{
				return fileFrom.renameTo(fileTo);
			//}
		}
		catch (Exception e)
		{
			Common.Log(e.toString());
		}
		
		return false;
	}  
	
	public String randomUUID()
	{
		UUID uuid = UUID.randomUUID();
		return uuid.toString();	
	}
	
	public String randomPasswordString(int Length ){
	String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	SecureRandom rnd = new SecureRandom();

   StringBuilder sb = new StringBuilder( Length );
   for( int i = 0; i < Length; i++ ) 
      sb.append( AB.charAt( rnd.nextInt(AB.length()) ) );
   return sb.toString();
}
	
	public String FileExt(String paramString)
	{
		int i = paramString.lastIndexOf(File.separator);
		int j;
		if (((j = paramString.lastIndexOf(".")) > i ? 1 : 0) != 0)
		{
			return paramString.substring(j);
		}
		return "";
	}
	
	public String FileName(String paramString)
	{
		int i;
		if (((i = paramString.lastIndexOf(File.separator)) < 0 ? 1 : 0) != 0)
		{
			return paramString;
		}
		if (paramString.endsWith(File.separator))
		{
			return "";
		}
		return paramString.substring(i + File.separator.length());
	}
	
	public String FileDir(String paramString)
	{
		int i;
		if (((i = paramString.lastIndexOf(File.separator)) < 0 ? 1 : 0) != 0)
		{
			return "";
		}
		return paramString.substring(0, i);
	}
	
	public String JavaVersion()
	{
		return System.getProperty("java.version");
	}
	
	public String getHostAddress()
	{
		try
		{
			InetAddress localInetAddress = InetAddress.getLocalHost();
			return localInetAddress.getHostAddress();
		}
		catch (Exception e)
		{
			return e.toString();
		}
	}
	
	public String getExternalAddress()
	{
		try
		{
			URL url = new URL("http://checkip.amazonaws.com/");
			BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));
			return br.readLine();
		}
		catch (Exception e)
		{
			return e.toString();
		}
	}
	
  public String MacAddressFromClient()
  {
	String macAddress = "";
    String str = "";
    try
    {
      InetAddress localInetAddress = InetAddress.getLocalHost();
      
      macAddress += localInetAddress.getHostAddress();
      NetworkInterface localNetworkInterface = NetworkInterface.getByInetAddress(localInetAddress);
      byte[] arrayOfByte1 = localNetworkInterface.getHardwareAddress();
      
      int i = 0;
      for (int m : arrayOfByte1)
      {
        if (m < 0) {
          m = 256 + m;
        }
        if (m == 0) {
          str = str.concat("00");
        }
        if (m > 0)
        {
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
    }
    catch (UnknownHostException localUnknownHostException)
    {
      str = localUnknownHostException.getMessage();
    }
    catch (SocketException localSocketException)
    {
      str = localSocketException.getMessage();
    }
    return str;
  }
  
	public static String GetTimeStamp()
	{
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
		if (_day.length()==1) _day = "0"+_day;

		_mon = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetMonth(_now));
		if (_mon.length()==1) _mon = "0"+_mon;

		_yr = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetYear(_now));
		
		_hr = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetHour(_now));
		if (_hr.length()==1) _hr = "0"+_hr;

		_mi = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetMinute(_now));
		if (_mi.length()==1) _mi = "0"+_mi;

		_ss = BA.NumberToString(anywheresoftware.b4a.keywords.Common.DateTime.GetSecond(_now));
		if (_ss.length()==1) _ss = "0"+_ss;

		return _yr+_mon+_day+"_"+_hr+_mi+"_"+_ss;
	}

	public static int CountOccurences(String sPattern,String sText)
	{
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
		final int limit7 = (int) (_stextlength-_spatternlength);
		
		for (_i = (int) (0) ; (step7 > 0 && _i <= limit7) || (step7 < 0 && _i >= limit7); _i = ((int)(0 + _i + step7)) )
		{
			if ((sPattern).equals(sText.substring(_i,(int) (_i+_spatternlength)))) _result = (int) (_result+1);
		}

		return _result;
	}
	
	public static String Boolean2Required(boolean Input)
	{
		if (Input==anywheresoftware.b4a.keywords.Common.True) return " required";
		return "";
	}
	
	public static String Boolean2Text(boolean Input)
	{
		if (Input==anywheresoftware.b4a.keywords.Common.True) return "True";
		return "False";
	}
	
	public static boolean Int2Boolean(int Input)
	{
		if (Input==1) return anywheresoftware.b4a.keywords.Common.True;
		return anywheresoftware.b4a.keywords.Common.False;
	}

	public static String ReverseBoolean2Required(boolean Input)
	{
		if (Input==anywheresoftware.b4a.keywords.Common.True) return "";
		return " required";
	}
	
	public static String ReverseBoolean2Text(boolean Input)
	{
		if (Input==anywheresoftware.b4a.keywords.Common.True) return "False";
		return "True";
	}

}