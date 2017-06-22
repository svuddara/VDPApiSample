package api.vdp.visa.com.visadirectapi;

import android.content.Context;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


public class MainActivity extends AppCompatActivity {


    private static String USER_ID = "TZNRHY1UAOWWFX5YP4D521IrJPpDJ51s4eMlJK0FCWReMXBDg"; //-for qaperf
    private static String PASSWORD = "lvB5CuZ02ki63ZB59wFHu3Bgutck6"; //-for qaperf
    private static String ENVURL="https://sandbox.api.visa.com/";
    private static String PAN = "4817808869241027";//-for qaperf

    // Key store settings
    private static String KEY_STORE_PATH = "/Users/svuddara/Documents/VDP/VDnew/myapp_keyAndCertBundle.jks";// -for qaperf
    private static String KEY_STORE_PASSWORD = "password"; //-sbx
    private static String PRIVATE_KEY_PASSWORD = "password"; //-sbx The password to decrypt the client's private key
    public static boolean wsi_client_cert = false;
    public static boolean useCal = false;
    //-for qaint
    private static String CERT = "MIIDzjCCAragAwIBAgIIWrOBEu/WhPUwDQYJKoZIhvcNAQELBQAwMTEOMAwGA1UEAwwFVkRQQ0Ex EjAQBgNVBAoMCVZEUFZJU0FDQTELMAkGA1UEBhMCVVMwHhcNMTYwMTI2MDAwNzU4WhcNMTgwMTI1 MDAwNzU4WjCBmzE0MDIGCgmSJomT8ixkAQEMJDNmNWI5MmJlLTkxYzYtNGZmNi1iNjU1LWVkY2Qx MjVjYjlkZTEWMBQGA1UEAwwNZGlwcy52aXNhLmNvbTENMAsGA1UECwwEYW5ldDENMAsGA1UECgwE dmlzYTELMAkGA1UEBwwCZmMxEzARBgNVBAgMCmNhbGlmb3JuaWExCzAJBgNVBAYTAnVzMIIBIjAN BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArdPl4LE1LMf/oyJD9TL1CQtus8ClcxE10HQNBCEn 57Xjs1ATIEqb8qV8SQqmImd7oRaoNID3TvQ46Sv2PElkF8AeOuY+hgRh0BrPRdrc8FGpkOBkM0q1 wdJxdYn+UDUK4mkt40NHN5+ccaVi8DB5/un4M+bpf+f2BZ045aRbKFIM0W9dd12a83TZjpw/qTyx Kqf7TffCKuPsmCJf+YXMol7ZuDdT+D4KX1Ex/M9PVw1cDnZXP7FkVld56X3NKHoUB5oYO40csqPF 2412gJMCZ1j7zLIyatPSFNRG1Qk755855r5jgOHeDIHOS5xljCiaErHTl627GUjgTgAvgp7D5wID AQABo38wfTAdBgNVHQ4EFgQUxy9qHpqhHmRFihcra2xMxreVPHswDAYDVR0TAQH/BAIwADAfBgNV HSMEGDAWgBQ1T9S3Tbegt4qNjRhLzUkty1E4rzAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYI KwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4IBAQCMZI6GKwrUhtloVfJ/8e8aCYWO 0KCetXvcfYugJahQNUdUudCPqeIdF+GkVVF47HEXw5Uzozz8jtYJPP4RqbjVFlX1RfJymFJr8v1E cdZEBniQGLvOIHSXVC2wIsL2tYSmbL3la8Vm01sQL+CivFShouEJQS6nnFo2MCFPjVY5Evqp/6sK EloJqIi0+8Jyy1chxyzSio21JV9uvNtqniG1sfz+5nO4iz9hKk4d6KwajLEMc6du2r4i0upzNyCm WySmDrCpmVn0+Z0S3uy9QRLOLTigfSl5tBmUHAI6mc6+0tv9v37TdEalTiaFJr088zEvQc0FhxBc LXyCUR5G/+UR";
    private static String sponsorId = null;
    public static String sponsorHeaderText = "SPONSOR-ID";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Thread thread = new Thread(new Runnable() {

            @Override
            public void run() {
                try  {
                    //new ApacheWorks().callVisa();
                    //ssl();
                   new ConnectionFactory(getApplicationContext()).run();
                    disableSSLCertificateChecking();
                  //SSLHandshakeAuthentication();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        thread.start();

    }

    private void ssl(){
        // use local trust store (CA)
        try {
            // use local trust store (CA)
            TrustManagerFactory tmf;
            KeyStore trustedStore = null;
            InputStream in = getResources().openRawResource(R.raw.keystore); // BKS in res/raw
            trustedStore = KeyStore.getInstance("BKS");
            trustedStore.load(in, "password".toCharArray());
            tmf = TrustManagerFactory.getInstance("X509");
            tmf.init(trustedStore);

            // load client certificate
            KeyStore clientKeyStore = loadClientKeyStore(getApplicationContext());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
            kmf.init(clientKeyStore, "password".toCharArray());

            //////////////

//            SSLContext sslcontext = SSLContext.getInstance("TLSv1");
//
//            sslcontext.init(null,
//                    null,
//                    null);
//            SSLSocketFactory NoSSLv3Factory = new NoSSLv3SocketFactory(sslcontext.getSocketFactory());
//
//            HttpsURLConnection.setDefaultSSLSocketFactory(NoSSLv3Factory);
//            l_connection = (HttpsURLConnection) l_url.openConnection();
//            l_connection.connect();
//
            /////////////

           SSLContext context = SSLContext.getInstance("TLSv1");

            // provide client cert - if server requires client cert this will pass
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            HostnameVerifier hostnameVerifier = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;

            // connect to url
            URL u = new URL("https://sandbox.api.visa.com/vdp/helloworld");
            HttpsURLConnection urlConnection = (HttpsURLConnection) u.openConnection();
            urlConnection.setSSLSocketFactory(context.getSocketFactory());
            urlConnection.setHostnameVerifier(hostnameVerifier);
            urlConnection.connect();
            Log.d("done","connecetd");
            System.out.println("Response Code: " + urlConnection.getResponseCode());
        }
        catch (Exception e){
            Log.d("exception",e.getMessage());
        }
    }

    private KeyStore loadClientKeyStore(Context context) {
        KeyStore trusted = null;
        try {
            InputStream in = context.getResources().openRawResource(R.raw.clientkeystore);
            trusted = KeyStore.getInstance("BKS");
            trusted.load(in, "password".toCharArray());
            in.close();
            return trusted;
        }catch (Exception e){
            e.printStackTrace();
        }
        return trusted;
    }

    private void SSLHandshakeAuthentication(){
        // Load CAs from an InputStream
        // (could be from a resource or ByteArrayInputStream or ...)
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            // From https://www.washington.edu/itconnect/security/ca/load-der.crt
          // InputStream caInput = new BufferedInputStream(getResources().openRawResource(R.raw.cert));

            Certificate ca;
            try {
            //    ca = cf.generateCertificate(caInput);
           //     System.out.println("ca=" + ((X509Certificate) ca).getSubjectDN());
            } finally {
               // caInput.close();
            }

            TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    X509Certificate[] myTrustedAnchors = new X509Certificate[0];
                    return myTrustedAnchors;
                }

                @Override
                public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                    // Not implemented
                }

                @Override
                public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                    // Not implemented
                }
            } };



            // Create a KeyStore containing our trusted CAs
            String keyStoreType = KeyStore.getDefaultType();
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null, "password".toCharArray());
           // keyStore.setCertificateEntry("ca", ca);

            // Create a TrustManager that trusts the CAs in our KeyStore
            String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
            tmf.init(keyStore);

            // Create an SSLContext that uses our TrustManager
            SSLContext context = SSLContext.getInstance("TLSv1");
            context.init(null, trustAllCerts, new java.security.SecureRandom());
            // Tell the URLConnection to use a SocketFactory from our SSLContext
            // URL url = new URL("https://certs.cac.washington.edu/CAtest/");
            URL url = new URL("https://sandbox.api.visa.com/vdp/helloworld");
            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
            HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
            HttpsURLConnection urlConnection =
                    (HttpsURLConnection)url.openConnection();


            urlConnection.setSSLSocketFactory(context.getSocketFactory());


//            OutputStream out = new BufferedOutputStream(urlConnection.getOutputStream());
//            out.write("{ \"key\" : \"value\" }".getBytes());


            InputStream in = urlConnection.getInputStream();

            Log.d("done","done");
//            while(in.read() <= 0) {
//
//            }
            // copyInputStreamToOutputStream(in, System.out);
        }catch (Exception e){
            Log.d("done",e.getMessage());
        }

    }

    private static void disableSSLCertificateChecking() {
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                X509Certificate[] myTrustedAnchors = new X509Certificate[0];
                return myTrustedAnchors;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                // Not implemented
            }

            @Override
            public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                // Not implemented
            }
        } };

        try {
            SSLContext sc = SSLContext.getInstance("TLS");

            sc.init(null, trustAllCerts, new java.security.SecureRandom());

            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
             @Override
             public boolean verify(String hostname, SSLSession session) {
                 return true;
             }
         });
            URL url = new URL("https://sandbox.api.visa.com/vdp/helloworld");
            HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();
            //InputStream in = urlConnection.getInputStream();
            int status = urlConnection.getResponseCode();
            InputStream in = urlConnection.getErrorStream();
            Log.d("done","done");

        } catch (KeyManagementException e) {
            Log.d("done",e.getMessage());
        } catch (Exception e) {
            Log.d("done",e.getMessage());
        }
    }


    public void URLConnection(String webUrl) throws IOException, NoSuchAlgorithmException, KeyManagementException {
        //TLSSocketFactory objTlsSocketFactory = new TLSSocketFactory();
        URL url = new URL(webUrl);
        HttpsURLConnection urlConnection = (HttpsURLConnection)url.openConnection();
        urlConnection.setRequestMethod("GET");
        //urlConnection.setSSLSocketFactory(objTlsSocketFactory);

        int responseCode = urlConnection.getResponseCode();
        System.out.println("\nSending 'GET' request to URL : " + url);
        System.out.println("Response Code : " + responseCode);

        BufferedReader in = new BufferedReader(
                new InputStreamReader(urlConnection.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        //print result
        System.out.println(response.toString());
    }
}
