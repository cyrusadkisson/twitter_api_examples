package net.adkitech;


import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.StringTokenizer;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.MultipartEntity;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.DefaultHttpClientConnection;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.params.SyncBasicHttpParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpRequestExecutor;
import org.apache.http.protocol.ImmutableHttpProcessor;
import org.apache.http.protocol.RequestConnControl;
import org.apache.http.protocol.RequestContent;
import org.apache.http.protocol.RequestExpectContinue;
import org.apache.http.protocol.RequestTargetHost;
import org.apache.http.protocol.RequestUserAgent;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;



/***
 *    ______ _____  ___ ______   _____ _   _ _____ _____ 
 *    | ___ \  ___|/ _ \|  _  \ |_   _| | | |_   _/  ___|
 *    | |_/ / |__ / /_\ \ | | |   | | | |_| | | | \ `--. 
 *    |    /|  __||  _  | | | |   | | |  _  | | |  `--. \
 *    | |\ \| |___| | | | |/ /    | | | | | |_| |_/\__/ /
 *    \_| \_\____/\_| |_/___/     \_/ \_| |_/\___/\____/ 
 *----------------------------------------------------------------------                                                       
 *   While you're struggling to get this working, I highly recommend three things:
 *   
 *   1. First, use HTTP, not HTTPS so you can see what you're doing, then switch back to HTTPS once it's working
 *   2. Use Fiddler or Wireshark to see your actual requests and the Twitter responses
 *   3. Use the example data from the following address. Get that working first as a baseline, then use your own credentials: 
 *   		https://dev.twitter.com/docs/auth/implementing-sign-twitter
 *
 *
// REQUIRED LIBRARIES
// Apache commons codec
// Apache HTTP Core
// JSON
 *
 */



public class Twitter {
	
	
	private String twitter_consumer_key = "YOURS HERE";
	private String twitter_consumer_secret = "YOURS HERE";	
	
	public String encode(String value) 
	{
        String encoded = null;
        try {
            encoded = URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException ignore) {
        }
        StringBuilder buf = new StringBuilder(encoded.length());
        char focus;
        for (int i = 0; i < encoded.length(); i++) {
            focus = encoded.charAt(i);
            if (focus == '*') {
                buf.append("%2A");
            } else if (focus == '+') {
                buf.append("%20");
            } else if (focus == '%' && (i + 1) < encoded.length()
                    && encoded.charAt(i + 1) == '7' && encoded.charAt(i + 2) == 'E') {
                buf.append('~');
                i += 2;
            } else {
                buf.append(focus);
            }
        }
        return buf.toString();
    }
	
	private static String computeSignature(String baseString, String keyString) throws GeneralSecurityException, UnsupportedEncodingException 
	{
	    SecretKey secretKey = null;

	    byte[] keyBytes = keyString.getBytes();
	    secretKey = new SecretKeySpec(keyBytes, "HmacSHA1");

	    Mac mac = Mac.getInstance("HmacSHA1");
	    mac.init(secretKey);

	    byte[] text = baseString.getBytes();

	    return new String(Base64.encodeBase64(mac.doFinal(text))).trim();
	}
	
	// the first step in the twitter oauth flow is to get a request token with a call to api.twitter.com/oauth/request_token
	// INPUT: nothing
	// OUTPUT: if successful, twitter API will return oauth_token, oauth_token_secret and oauth_token_confirmed
	
	public JSONObject startTwitterAuthentication()
	{
		JSONObject jsonresponse = new JSONObject();
		
		// this particular request uses POST
		String get_or_post = "POST";
		
		// I think this is the signature method used for all Twitter API calls
		String oauth_signature_method = "HMAC-SHA1";
		
		// generate any fairly random alphanumeric string as the "nonce". Nonce = Number used ONCE.
		String uuid_string = UUID.randomUUID().toString();
		uuid_string = uuid_string.replaceAll("-", "");
		String oauth_nonce = uuid_string; // any relatively random alphanumeric string will work here
		
		// get the timestamp
		Calendar tempcal = Calendar.getInstance();
		long ts = tempcal.getTimeInMillis();// get current time in milliseconds
		String oauth_timestamp = (new Long(ts/1000)).toString(); // then divide by 1000 to get seconds
		
		// assemble the proper parameter string, which must be in alphabetical order, using your consumer key
		String parameter_string = "oauth_consumer_key=" + twitter_consumer_key + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method + "&oauth_timestamp=" + oauth_timestamp + "&oauth_version=1.0";		
		System.out.println("parameter_string=" + parameter_string); // print out parameter string for error checking, if you want
		
		// specify the proper twitter API endpoint at which to direct this request
		String twitter_endpoint = "https://api.twitter.com/oauth/request_token";
		String twitter_endpoint_host = "api.twitter.com";
		String twitter_endpoint_path = "/oauth/request_token";
		
		// assemble the string to be signed. It is METHOD & percent-encoded endpoint & percent-encoded parameter string
		// Java's native URLEncoder.encode function will not work. It is the wrong RFC specification (which does "+" where "%20" should be)... 
		// the encode() function included in this class compensates to conform to RFC 3986 (which twitter requires)
		String signature_base_string = get_or_post + "&"+ encode(twitter_endpoint) + "&" + encode(parameter_string);
		
		// now that we've got the string we want to sign (see directly above) HmacSHA1 hash it against the consumer secret
		String oauth_signature = "";
		try {
			oauth_signature = computeSignature(signature_base_string, twitter_consumer_secret + "&");  // note the & at the end. Normally the user access_token would go here, but we don't know it yet for request_token
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}	   
		catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		// each request to the twitter API 1.1 requires an "Authorization: BLAH" header. The following is what BLAH should look like
		String authorization_header_string = "OAuth oauth_consumer_key=\"" + twitter_consumer_key + "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"" + 
				oauth_timestamp + "\",oauth_nonce=\"" + oauth_nonce + "\",oauth_version=\"1.0\",oauth_signature=\"" + encode(oauth_signature) + "\"";
		System.out.println("authorization_header_string=" + authorization_header_string); 	// print out authorization_header_string for error checking
		     
		String oauth_token = "";
		String oauth_token_secret = "";
		//String oauth_callback_confirmed = "";
		  
		// I'm using Apache HTTPCore to make the connection and process the request. In theory, you could use HTTPClient, but HTTPClient defaults to the wrong RFC encoding, which has to be tweaked.
		HttpParams params = new SyncBasicHttpParams();
		HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
		HttpProtocolParams.setContentCharset(params, "UTF-8");
		HttpProtocolParams.setUserAgent(params, "HttpCore/1.1");
		HttpProtocolParams.setUseExpectContinue(params, false);
			 
		HttpProcessor httpproc = new ImmutableHttpProcessor(new HttpRequestInterceptor[] {
				// Required protocol interceptors
				new RequestContent(),
				new RequestTargetHost(),
				// Recommended protocol interceptors
				new RequestConnControl(),
				new RequestUserAgent(),
				new RequestExpectContinue()});

		HttpRequestExecutor httpexecutor = new HttpRequestExecutor();
		HttpContext context = new BasicHttpContext(null);
		HttpHost host = new HttpHost(twitter_endpoint_host, 443); // use 80 if you want regular HTTP (not HTTPS)
		DefaultHttpClientConnection conn = new DefaultHttpClientConnection();

		context.setAttribute(ExecutionContext.HTTP_CONNECTION, conn);
		context.setAttribute(ExecutionContext.HTTP_TARGET_HOST, host);

		try{ // jsonexception block
			try 
			{
				// initialize the HTTPS connection
				SSLContext sslcontext = SSLContext.getInstance("TLS");
				sslcontext.init(null, null, null);
				SSLSocketFactory ssf = sslcontext.getSocketFactory();
				Socket socket = ssf.createSocket();
				socket.connect(new InetSocketAddress(host.getHostName(), host.getPort()), 0);
				conn.bind(socket, params);
				 
				 // for HTTP, use this instead of the above.
				 // Socket socket = new Socket(host.getHostName(), host.getPort());
				 // conn.bind(socket, params);
				 
				BasicHttpEntityEnclosingRequest request2 = new BasicHttpEntityEnclosingRequest("POST", twitter_endpoint_path);
				request2.setEntity( new StringEntity("", "application/x-www-form-urlencoded", "UTF-8"));
				request2.setParams(params);
				request2.addHeader("Authorization", authorization_header_string); // this is where we're adding that required "Authorization: BLAH" header.
				httpexecutor.preProcess(request2, httpproc, context);
				HttpResponse response2 = httpexecutor.execute(request2, conn, context);
				response2.setParams(params);
				httpexecutor.postProcess(response2, httpproc, context);
				
				if(response2.getStatusLine().toString().indexOf("200") == -1) // if it wasn't a successful request, then this error code will be something other than 200, return indicating as such
				{
					jsonresponse.put("response_status", "error");
					jsonresponse.put("message", "Twitter request_token request failed. Response was !200.");
				}
				else // returned 200 (good)
				{
					String responseBody = EntityUtils.toString(response2.getEntity());
					System.out.println("endpoint startTwitterAuthentication responsebody=" + responseBody); // print out the response
					
					if(responseBody.indexOf("oauth_callback_confirmed=") == -1) // if this were true, that would be weird. Successful (200) response, but no oauth_callback_confirmed? 
					{
						jsonresponse.put("response_status", "error");
						jsonresponse.put("message", "Twitter request_token request failed. response was 200 but did not contain oauth_callback_confirmed");
					}
					else
					{
						// this assumes that oauth_callback_confirmed is always the last of the three values returned. I don't know 100% that is true, but it seems to be. 					
						String occ_val = responseBody.substring(responseBody.indexOf("oauth_callback_confirmed=") + 25);
						if(!occ_val.equals("true"))
						{
							jsonresponse.put("response_status", "error");
							jsonresponse.put("message", "Twitter request_token response was 200 and contained oauth_callback_confirmed but it was not \"true\".");
						}
						else // everything seems a-ok. look for values and return them.
						{
							// using the tokenizer takes away the need for the values to be in any particular order.
							StringTokenizer st = new StringTokenizer(responseBody, "&");
							String currenttoken = "";
							while(st.hasMoreTokens())
							{
								currenttoken = st.nextToken();
								if(currenttoken.startsWith("oauth_token="))
									oauth_token = currenttoken.substring(currenttoken.indexOf("=") + 1);
								else if(currenttoken.startsWith("oauth_token_secret="))
									oauth_token_secret = currenttoken.substring(currenttoken.indexOf("=") + 1);
								else if(currenttoken.startsWith("oauth_callback_confirmed="))
								{
									//oauth_callback_confirmed = currenttoken.substring(currenttoken.indexOf("=") + 1);
								}
								else
								{
									System.out.println("Warning... twitter returned a key we weren't looking for.");
								}
							}
							if(oauth_token.equals("") || oauth_token_secret.equals("")) // if either key is empty, that's weird and bad
							{
								jsonresponse.put("response_status", "error");
								jsonresponse.put("message", "oauth tokens in response were invalid");
							}
							else // otherwise, we're all good. Return the values (did not include oauth_token_confirmed here. no need)
							{
								jsonresponse.put("response_status", "success");
								jsonresponse.put("oauth_token", oauth_token);
								//jsonresponse.put("oauth_token_secret", oauth_token);
							}
						 }
					 }
				 }
				 conn.close();
			 }   
			catch(HttpException he) 
			{	
				System.out.println(he.getMessage());
				jsonresponse.put("response_status", "error");
				jsonresponse.put("message", "startTwitterAuthentication HttpException message=" + he.getMessage());
			} 
			catch(NoSuchAlgorithmException nsae) 
			{	
				System.out.println(nsae.getMessage());
				jsonresponse.put("response_status", "error");
				jsonresponse.put("message", "startTwitterAuthentication NoSuchAlgorithmException message=" + nsae.getMessage());
			} 					
			catch(KeyManagementException kme) 
			{	
				System.out.println(kme.getMessage());
				jsonresponse.put("response_status", "error");
				jsonresponse.put("message", "startTwitterAuthentication KeyManagementException message=" + kme.getMessage());
			} 	
			finally 
			{
				conn.close();
			}		
		} 
		catch(JSONException jsone)
		{
			
		}
		catch(IOException ioe)
		{
			
		}
		return jsonresponse;
	}
	
	// once you've got the generic request token, send the user to the authorization page. They grant access and either
	// a) are shown a pin number 
	// b) sent to the callback url with information
	// In either case, turn the authorization code into a twitter access token for that user. 
	
	// My example here is uses a pin and oauth_token (from the previous request token call)
	// INPUT: pin, generic request token
	// OUTPUT: if successful, twitter API will return access_token, access_token_secret, screen_name and user_id
	
	public JSONObject getTwitterAccessTokenFromAuthorizationCode(String verifier_or_pin, String oauth_token)
	{
		JSONObject jsonresponse = new JSONObject();
		
		// this particular request uses POST
		String get_or_post = "POST";
		
		// I think this is the signature method used for all Twitter API calls
		String oauth_signature_method = "HMAC-SHA1";
		
		// generate any fairly random alphanumeric string as the "nonce". Nonce = Number used ONCE.
		String uuid_string = UUID.randomUUID().toString();
		uuid_string = uuid_string.replaceAll("-", "");
		String oauth_nonce = uuid_string; // any relatively random alphanumeric string will work here
		
		// get the timestamp
		Calendar tempcal = Calendar.getInstance();
		long ts = tempcal.getTimeInMillis();// get current time in milliseconds
		String oauth_timestamp = (new Long(ts/1000)).toString(); // then divide by 1000 to get seconds
		
		
		// the parameter string must be in alphabetical order
		String parameter_string = "oauth_consumer_key=" + twitter_consumer_key + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method + 
		    		"&oauth_timestamp=" + oauth_timestamp + "&oauth_token=" + encode(oauth_token) + "&oauth_version=1.0";		
		System.out.println("parameter_string=" + parameter_string);
		
		String twitter_endpoint = "https://api.twitter.com/oauth/access_token";
		String twitter_endpoint_host = "api.twitter.com";
		String twitter_endpoint_path = "/oauth/access_token";
		String signature_base_string = get_or_post + "&"+ encode(twitter_endpoint) + "&" + encode(parameter_string);
			
		String oauth_signature = "";
		try {
			oauth_signature = computeSignature(signature_base_string, twitter_consumer_secret + "&");  // note the & at the end. Normally the user access_token would go here, but we don't know it yet
			System.out.println("oauth_signature=" + encode(oauth_signature));
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		String authorization_header_string = "OAuth oauth_consumer_key=\"" + twitter_consumer_key + "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"" + oauth_timestamp + 
				"\",oauth_nonce=\"" + oauth_nonce + "\",oauth_version=\"1.0\",oauth_signature=\"" + encode(oauth_signature) + "\",oauth_token=\"" + encode(oauth_token) + "\"";
		// System.out.println("authorization_header_string=" + authorization_header_string);
			
		String access_token = "";
		String access_token_secret = "";
		String user_id = "";
		String screen_name = "";
		    
		 HttpParams params = new SyncBasicHttpParams();
		 HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
		 HttpProtocolParams.setContentCharset(params, "UTF-8");
		 HttpProtocolParams.setUserAgent(params, "HttpCore/1.1");
		 HttpProtocolParams.setUseExpectContinue(params, false);

		 HttpProcessor httpproc = new ImmutableHttpProcessor(new HttpRequestInterceptor[] {
	                // Required protocol interceptors
	                new RequestContent(),
	                new RequestTargetHost(),
	                // Recommended protocol interceptors
	                new RequestConnControl(),
	                new RequestUserAgent(),
	                new RequestExpectContinue()});	

		 HttpRequestExecutor httpexecutor = new HttpRequestExecutor();
		 HttpContext context = new BasicHttpContext(null);
		 HttpHost host = new HttpHost(twitter_endpoint_host,443);
		 DefaultHttpClientConnection conn = new DefaultHttpClientConnection();

		 context.setAttribute(ExecutionContext.HTTP_CONNECTION, conn);
		 context.setAttribute(ExecutionContext.HTTP_TARGET_HOST, host);

		 try{
			 try {
				 SSLContext sslcontext = SSLContext.getInstance("TLS");
				 sslcontext.init(null, null, null);
				 SSLSocketFactory ssf = sslcontext.getSocketFactory();
				 Socket socket = ssf.createSocket();
				 socket.connect(
				   new InetSocketAddress(host.getHostName(), host.getPort()), 0);
				 conn.bind(socket, params);
				 
				 BasicHttpEntityEnclosingRequest request2 = new BasicHttpEntityEnclosingRequest("POST", twitter_endpoint_path);
				 // this time, we've got to include the oauth_verifier value with the request
				 request2.setEntity( new StringEntity("oauth_verifier=" + encode(verifier_or_pin), "application/x-www-form-urlencoded", "UTF-8"));
				 request2.setParams(params);
				 request2.addHeader("Authorization", authorization_header_string);
				 httpexecutor.preProcess(request2, httpproc, context);
				 HttpResponse response2 = httpexecutor.execute(request2, conn, context);
				 System.out.println("getTwitterAccessTokenFromAuthorizationCode response.getStatusLine()=" + response2.getStatusLine());
				 response2.setParams(params);
				 httpexecutor.postProcess(response2, httpproc, context);
				 String responseBody = EntityUtils.toString(response2.getEntity());
				 
				 if(response2.getStatusLine().toString().indexOf("200") == -1) // response from twitter wasn't 200, that's bad
				 {
					 jsonresponse.put("response_status", "error");
					 jsonresponse.put("message", "getTwitterAccessTokenFromAuthorizationCode request failed. Response was !200.");
				 }
				 else
				 {
					 StringTokenizer st = new StringTokenizer(responseBody,"&");
					 String currenttoken = "";
					 while(st.hasMoreTokens())
					 {
						 currenttoken = st.nextToken();
						 if(currenttoken.startsWith("oauth_token="))
							 access_token = currenttoken.substring(currenttoken.indexOf("=") + 1);
						 else if(currenttoken.startsWith("oauth_token_secret="))
							 access_token_secret = currenttoken.substring(currenttoken.indexOf("=") + 1);
						 else if(currenttoken.startsWith("user_id="))
							 user_id = currenttoken.substring(currenttoken.indexOf("=") + 1);
						 else if(currenttoken.startsWith("screen_name="))
							 screen_name = currenttoken.substring(currenttoken.indexOf("=") + 1);
						 else
						 {
							 // something else. The 4 values above are the only ones twitter should return, so this case would be weird.
							 // skip
						 }
					 }
				 }	
				 
				 if(access_token.equals("") || access_token_secret.equals("")) // if either of these values is empty, that's bad
				 {
					 jsonresponse.put("response_status", "error");
					 jsonresponse.put("message", "code into access token failed. oauth tokens in response were invalid");
				 }
				 else
				 {
					 jsonresponse.put("response_status", "success");
					 jsonresponse.put("access_token", access_token);
					 jsonresponse.put("access_token_secret", access_token_secret);
					 jsonresponse.put("user_id", user_id);
					 jsonresponse.put("screen_name", screen_name);
				 }
				 conn.close();
			 }   
			 catch(HttpException he) 
			 {	
				 System.out.println(he.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "getTwitterAccessTokenFromAuthorizationCode HttpException message=" + he.getMessage());
			 } 
			 catch(NoSuchAlgorithmException nsae) 
			 {	
				 System.out.println(nsae.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "getTwitterAccessTokenFromAuthorizationCode NoSuchAlgorithmException message=" + nsae.getMessage());
			 } 					
			 catch(KeyManagementException kme) 
			 {	
				 System.out.println(kme.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "getTwitterAccessTokenFromAuthorizationCode KeyManagementException message=" + kme.getMessage());
			 } 	
			 finally {
				 conn.close();
			 }
		 } 
		 catch(JSONException jsone)
		 {
			 
		 }
		 catch(IOException ioe)
		 {
			 
		 }
		 return jsonresponse;
	}

	// This is the search example, using a GET call
	// INPUT: the search query (q), the user's access_token and the user's access_token_secret
	// OUTPUT: if successful, twitter API will return a json object of tweets
		
	public JSONObject searchTweets(String q, String access_token, String access_token_secret)
	{
		JSONObject jsonresponse = new JSONObject();
		
		String oauth_token = access_token;
		String oauth_token_secret = access_token_secret;

		// generate authorization header
		String get_or_post = "GET";
		String oauth_signature_method = "HMAC-SHA1";
		
		String uuid_string = UUID.randomUUID().toString();
		uuid_string = uuid_string.replaceAll("-", "");
		String oauth_nonce = uuid_string; // any relatively random alphanumeric string will work here
		
		// get the timestamp
		Calendar tempcal = Calendar.getInstance();
		long ts = tempcal.getTimeInMillis();// get current time in milliseconds
		String oauth_timestamp = (new Long(ts/1000)).toString(); // then divide by 1000 to get seconds

		// the parameter string must be in alphabetical order
		// this time, I add 3 extra params to the request, "lang", "result_type" and "q".
		String parameter_string = "lang=en&oauth_consumer_key=" + twitter_consumer_key + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method + 
			"&oauth_timestamp=" + oauth_timestamp + "&oauth_token=" + encode(oauth_token) + "&oauth_version=1.0&q=" + encode(q) + "&result_type=mixed";	
		System.out.println("parameter_string=" + parameter_string);
		String twitter_endpoint = "https://api.twitter.com/1.1/search/tweets.json";
		String twitter_endpoint_host = "api.twitter.com";
		String twitter_endpoint_path = "/1.1/search/tweets.json";
		String signature_base_string = get_or_post + "&"+ encode(twitter_endpoint) + "&" + encode(parameter_string);
		System.out.println("signature_base_string=" + signature_base_string);
		
		// this time the base string is signed using twitter_consumer_secret + "&" + encode(oauth_token_secret) instead of just twitter_consumer_secret + "&"
		String oauth_signature = "";
		try {
			oauth_signature = computeSignature(signature_base_string, twitter_consumer_secret + "&" + encode(oauth_token_secret));  // note the & at the end. Normally the user access_token would go here, but we don't know it yet for request_token
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		String authorization_header_string = "OAuth oauth_consumer_key=\"" + twitter_consumer_key + "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"" + oauth_timestamp + 
				"\",oauth_nonce=\"" + oauth_nonce + "\",oauth_version=\"1.0\",oauth_signature=\"" + encode(oauth_signature) + "\",oauth_token=\"" + encode(oauth_token) + "\"";
		System.out.println("authorization_header_string=" + authorization_header_string);


		 HttpParams params = new SyncBasicHttpParams();
		 HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
		 HttpProtocolParams.setContentCharset(params, "UTF-8");
		 HttpProtocolParams.setUserAgent(params, "HttpCore/1.1");
		 HttpProtocolParams.setUseExpectContinue(params, false);

		 HttpProcessor httpproc = new ImmutableHttpProcessor(new HttpRequestInterceptor[] {
	                // Required protocol interceptors
	                new RequestContent(),
	                new RequestTargetHost(),
	                // Recommended protocol interceptors
	                new RequestConnControl(),
	                new RequestUserAgent(),
	                new RequestExpectContinue()});

		 HttpRequestExecutor httpexecutor = new HttpRequestExecutor();
		 HttpContext context = new BasicHttpContext(null);
		 HttpHost host = new HttpHost(twitter_endpoint_host,443);
		 DefaultHttpClientConnection conn = new DefaultHttpClientConnection();

		 context.setAttribute(ExecutionContext.HTTP_CONNECTION, conn);
		 context.setAttribute(ExecutionContext.HTTP_TARGET_HOST, host);

		 try {
			 try {
				 SSLContext sslcontext = SSLContext.getInstance("TLS");
				 sslcontext.init(null, null, null);
				 SSLSocketFactory ssf = sslcontext.getSocketFactory();
				 Socket socket = ssf.createSocket();
				 socket.connect(
				   new InetSocketAddress(host.getHostName(), host.getPort()), 0);
				 conn.bind(socket, params);
				 
				 // the following line adds 3 params to the request just as the parameter string did above. They must match up or the request will fail.
				 BasicHttpEntityEnclosingRequest request2 = new BasicHttpEntityEnclosingRequest("GET", twitter_endpoint_path + "?lang=en&result_type=mixed&q=" + encode(q));
				 request2.setParams(params);
				 request2.addHeader("Authorization", authorization_header_string); // always add the Authorization header
				 httpexecutor.preProcess(request2, httpproc, context);
				 HttpResponse response2 = httpexecutor.execute(request2, conn, context);
				 response2.setParams(params);
				 httpexecutor.postProcess(response2, httpproc, context);

				 if(response2.getStatusLine().toString().indexOf("500") != -1)
				 {
					 jsonresponse.put("response_status", "error");
					 jsonresponse.put("message", "Twitter auth error.");
				 }
				 else
				 {
					 // if successful, the response should be a JSONObject of tweets
					 JSONObject jo = new JSONObject(EntityUtils.toString(response2.getEntity()));
					 if(jo.has("errors"))
					 {
						 jsonresponse.put("response_status", "error");
						 String message_from_twitter = jo.getJSONArray("errors").getJSONObject(0).getString("message");
						 if(message_from_twitter.equals("Invalid or expired token") || message_from_twitter.equals("Could not authenticate you"))
							 jsonresponse.put("message", "Twitter auth error.");
						 else
							 jsonresponse.put("message", jo.getJSONArray("errors").getJSONObject(0).getString("message"));
					 }
					 else
					 {
						 jsonresponse.put("twitter_jo", jo); // this is the full result object from Twitter
					 }
					 
					 conn.close();
				 }   
			 }
			 catch(HttpException he) 
			 {	
				 System.out.println(he.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "searchTweets HttpException message=" + he.getMessage());
			 } 
			 catch(NoSuchAlgorithmException nsae) 
			 {	
				 System.out.println(nsae.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "searchTweets NoSuchAlgorithmException message=" + nsae.getMessage());
			 } 					
			 catch(KeyManagementException kme) 
			 {	
				 System.out.println(kme.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "searchTweets KeyManagementException message=" + kme.getMessage());
			 } 	
			 finally {
				 conn.close();
			 }
		 } 
		 catch(JSONException jsone)
		 {
			 
		 }
		 catch(IOException ioe)
		 {
			 
		 }
		 return jsonresponse;
	}
	
	// This is the update status example
	// Urls (even short ones) will be wrapped and be counted as a certain length defined by Twitter configuration (~22 chars as of this writing). There is a 140 char max, including this limitation
	// INPUT:the user's access_token and the user's access_token_secret and the text of the status update
	// OUTPUT: if successful, the tweet gets posted.
		
	public JSONObject updateStatus(String access_token, String access_token_secret, String text)
	{
		JSONObject jsonresponse = new JSONObject();
		
		String oauth_token = access_token;
		String oauth_token_secret = access_token_secret;

		// generate authorization header
		String get_or_post = "POST";
		String oauth_signature_method = "HMAC-SHA1";
		
		String uuid_string = UUID.randomUUID().toString();
		uuid_string = uuid_string.replaceAll("-", "");
		String oauth_nonce = uuid_string; // any relatively random alphanumeric string will work here
		
		// get the timestamp
		Calendar tempcal = Calendar.getInstance();
		long ts = tempcal.getTimeInMillis();// get current time in milliseconds
		String oauth_timestamp = (new Long(ts/1000)).toString(); // then divide by 1000 to get seconds
		
		// the parameter string must be in alphabetical order, "text" parameter added at end
		String parameter_string = "oauth_consumer_key=" + twitter_consumer_key + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method + 
		    		"&oauth_timestamp=" + oauth_timestamp + "&oauth_token=" + encode(oauth_token) + "&oauth_version=1.0&status=" + encode(text);	
		System.out.println("parameter_string=" + parameter_string);
		
		String twitter_endpoint = "https://api.twitter.com/1.1/statuses/update.json";
		String twitter_endpoint_host = "api.twitter.com";
		String twitter_endpoint_path = "/1.1/statuses/update.json";
		String signature_base_string = get_or_post + "&"+ encode(twitter_endpoint) + "&" + encode(parameter_string);
		System.out.println("signature_base_string=" + signature_base_string);
	    String oauth_signature = "";
	    try {
	    	oauth_signature = computeSignature(signature_base_string, twitter_consumer_secret + "&" + encode(oauth_token_secret));  
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	    catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	    String authorization_header_string = "OAuth oauth_consumer_key=\"" + twitter_consumer_key + "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"" + oauth_timestamp + 
	    		"\",oauth_nonce=\"" + oauth_nonce + "\",oauth_version=\"1.0\",oauth_signature=\"" + encode(oauth_signature) + "\",oauth_token=\"" + encode(oauth_token) + "\"";
	    System.out.println("authorization_header_string=" + authorization_header_string);
		
		
	    HttpParams params = new SyncBasicHttpParams();
	    HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
	    HttpProtocolParams.setContentCharset(params, "UTF-8");
	    HttpProtocolParams.setUserAgent(params, "HttpCore/1.1");
	    HttpProtocolParams.setUseExpectContinue(params, false);	
	    HttpProcessor httpproc = new ImmutableHttpProcessor(new HttpRequestInterceptor[] {
	                // Required protocol interceptors
	                new RequestContent(),
	                new RequestTargetHost(),
	                // Recommended protocol interceptors
	                new RequestConnControl(),
	                new RequestUserAgent(),
	                new RequestExpectContinue()});

		 HttpRequestExecutor httpexecutor = new HttpRequestExecutor();
		 HttpContext context = new BasicHttpContext(null);
		 HttpHost host = new HttpHost(twitter_endpoint_host,443);
		 DefaultHttpClientConnection conn = new DefaultHttpClientConnection();

		 context.setAttribute(ExecutionContext.HTTP_CONNECTION, conn);
		 context.setAttribute(ExecutionContext.HTTP_TARGET_HOST, host);

		 try 
		 {
			 try 
			 {
				 SSLContext sslcontext = SSLContext.getInstance("TLS");
				 sslcontext.init(null, null, null);
				 SSLSocketFactory ssf = sslcontext.getSocketFactory();
				 Socket socket = ssf.createSocket();
				 socket.connect(
				   new InetSocketAddress(host.getHostName(), host.getPort()), 0);
				 conn.bind(socket, params);
				 BasicHttpEntityEnclosingRequest request2 = new BasicHttpEntityEnclosingRequest("POST", twitter_endpoint_path);
				 // need to add status parameter to this POST
				 request2.setEntity( new StringEntity("status=" + encode(text), "application/x-www-form-urlencoded", "UTF-8"));
				 request2.setParams(params);
				 request2.addHeader("Authorization", authorization_header_string);
				 httpexecutor.preProcess(request2, httpproc, context);
				 HttpResponse response2 = httpexecutor.execute(request2, conn, context);
				 response2.setParams(params);
				 httpexecutor.postProcess(response2, httpproc, context);
				 String responseBody = EntityUtils.toString(response2.getEntity());
				 System.out.println("response=" + responseBody);
				 // error checking here. Otherwise, status should be updated.
				 jsonresponse = new JSONObject(responseBody);
				 conn.close();
			 }   
			 catch(HttpException he) 
			 {	
				 System.out.println(he.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "updateStatus HttpException message=" + he.getMessage());
			 } 
			 catch(NoSuchAlgorithmException nsae) 
			 {	
				 System.out.println(nsae.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "updateStatus NoSuchAlgorithmException message=" + nsae.getMessage());
			 } 					
			 catch(KeyManagementException kme) 
			 {	
				 System.out.println(kme.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "updateStatus KeyManagementException message=" + kme.getMessage());
			 } 	
			 finally 
			 {
				 conn.close();
			 }	
		 } 
		 catch(JSONException jsone)
		 {
			 jsone.printStackTrace();
		 }
		 catch(IOException ioe)
		 {
			 ioe.printStackTrace();
		 }
		 return jsonresponse;
	}

	// does not work with absolute (i.e. http://) urls. Only local files.
	// returns a valid JSONObject, regardless
	// if it spoke to twitter and did the update succesfully, it returns just the object.
	// if any error occurs, whether from twitter or failing to talk to twitter entirely, an response_status=error is sent back
	public JSONObject updateStatusWithMedia(String access_token, String access_token_secret, String text, File file) throws JSONException
	{
		JSONObject jsonresponse = new JSONObject();
		
		String oauth_token = access_token;
		String oauth_token_secret = access_token_secret;

		// generate authorization header
		String get_or_post = "POST";
		String oauth_signature_method = "HMAC-SHA1";
		
		String uuid_string = UUID.randomUUID().toString();
		uuid_string = uuid_string.replaceAll("-", "");
		String oauth_nonce = uuid_string; // any relatively random alphanumeric string will work here
		
		// get the timestamp
		Calendar tempcal = Calendar.getInstance();
		long ts = tempcal.getTimeInMillis();// get current time in milliseconds
		String oauth_timestamp = (new Long(ts/1000)).toString(); // then divide by 1000 to get seconds
		
		// the parameter string must be in alphabetical order, "text" parameter added at end
		String parameter_string = "oauth_consumer_key=" + twitter_consumer_key + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method + 
		    		"&oauth_timestamp=" + oauth_timestamp + "&oauth_token=" + encode(oauth_token) + "&oauth_version=1.0";//&status=" + encode(text);	
		System.out.println("Twitter.updateStatusWithMedia(): parameter_string=" + parameter_string);
		
		String twitter_endpoint = "https://api.twitter.com/1.1/statuses/update_with_media.json";
		String twitter_endpoint_host = "api.twitter.com";
		String twitter_endpoint_path = "/1.1/statuses/update_with_media.json";
		String signature_base_string = get_or_post + "&"+ encode(twitter_endpoint) + "&" + encode(parameter_string);
		 System.out.println("Twitter.updateStatusWithMedia(): signature_base_string=" + signature_base_string);
	    String oauth_signature = "";
	    try {
	    	oauth_signature = computeSignature(signature_base_string, twitter_consumer_secret + "&" + encode(oauth_token_secret));  
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	    catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	    String authorization_header_string = "OAuth oauth_consumer_key=\"" + twitter_consumer_key + "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"" + oauth_timestamp + 
	    		"\",oauth_nonce=\"" + oauth_nonce + "\",oauth_version=\"1.0\",oauth_signature=\"" + encode(oauth_signature) + "\",oauth_token=\"" + encode(oauth_token) + "\"";
	    System.out.println("Twitter.updateStatusWithMedia(): authorization_header_string=" + authorization_header_string);
		
		
	    HttpParams params = new SyncBasicHttpParams();
	    HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
	    HttpProtocolParams.setContentCharset(params, "UTF-8");
	    HttpProtocolParams.setUserAgent(params, "HttpCore/1.1");
	    HttpProtocolParams.setUseExpectContinue(params, false);
	    HttpProcessor httpproc = new ImmutableHttpProcessor(new HttpRequestInterceptor[] {
	                // Required protocol interceptors
	                new RequestContent(),
	                new RequestTargetHost(),
	                // Recommended protocol interceptors
	                new RequestConnControl(),
	                new RequestUserAgent(),
	                new RequestExpectContinue()});

		 HttpRequestExecutor httpexecutor = new HttpRequestExecutor();
		 HttpContext context = new BasicHttpContext(null);
		 HttpHost host = new HttpHost(twitter_endpoint_host,443);
		 DefaultHttpClientConnection conn = new DefaultHttpClientConnection();

		 context.setAttribute(ExecutionContext.HTTP_CONNECTION, conn);
		 context.setAttribute(ExecutionContext.HTTP_TARGET_HOST, host);

		 try 
		 {
			 try 
			 {
				 SSLContext sslcontext = SSLContext.getInstance("TLS");
				 sslcontext.init(null, null, null);
				 SSLSocketFactory ssf = sslcontext.getSocketFactory();
				 Socket socket = ssf.createSocket();
				 socket.connect(
				   new InetSocketAddress(host.getHostName(), host.getPort()), 0);
				 conn.bind(socket, params);
				 
				// System.out.println("Twitter.updateStatusWithMedia(): params all set, creating socket.");
				// Socket socket = new Socket(host.getHostName(), host.getPort());
				// conn.bind(socket, params);
				 
				 BasicHttpEntityEnclosingRequest request2 = new BasicHttpEntityEnclosingRequest("POST", twitter_endpoint_path);
				 // need to add status parameter to this POST
				 MultipartEntity reqEntity = new MultipartEntity();
				 FileBody sb_image = new FileBody(file);
				 StringBody sb_status = new StringBody(text);
				 reqEntity.addPart("status", sb_status);
				 reqEntity.addPart("media[]", sb_image);
				 request2.setEntity(reqEntity);
				 
				
				 //request2.setEntity( new StringEntity("media[]=" + encode(image_url) + "&status=" + encode(text), "multipart/form-data; boundary=---1234", "UTF-8"));
				 request2.setParams(params);
				
				 request2.addHeader("Authorization", authorization_header_string);
				 System.out.println("Twitter.updateStatusWithMedia(): Entity, params and header added to request. Preprocessing and executing...");
				 httpexecutor.preProcess(request2, httpproc, context);
				 HttpResponse response2 = httpexecutor.execute(request2, conn, context);
				 System.out.println("Twitter.updateStatusWithMedia(): ... done. Postprocessing...");
				 response2.setParams(params);
				 httpexecutor.postProcess(response2, httpproc, context);
				 String responseBody = EntityUtils.toString(response2.getEntity());
				 System.out.println("Twitter.updateStatusWithMedia(): done. response=" + responseBody);
				 // error checking here. Otherwise, status should be updated.
				 jsonresponse = new JSONObject(responseBody);
				 if(jsonresponse.has("errors"))
				 {
					 JSONObject temp_jo = new JSONObject();
					 temp_jo.put("response_status","error");
					 temp_jo.put("message", jsonresponse.getJSONArray("errors").getJSONObject(0).getString("message"));
					 temp_jo.put("twitter_code", jsonresponse.getJSONArray("errors").getJSONObject(0).getInt("code"));
					 jsonresponse = temp_jo;
				 }
				 conn.close();
			 }   
			 catch(HttpException he) 
			 {	
				 System.out.println(he.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "updateStatusWithMedia HttpException message=" + he.getMessage());
			 } 
			 catch(NoSuchAlgorithmException nsae) 
			 {	
				 System.out.println(nsae.getMessage());
				  jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "updateStatusWithMedia NoSuchAlgorithmException message=" + nsae.getMessage());
			 } 					
			 catch(KeyManagementException kme) 
			 {	
				 System.out.println(kme.getMessage());
				  jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "updateStatusWithMedia KeyManagementException message=" + kme.getMessage());
			 } 	
			 finally 
			 {
				 conn.close();
			 }	
		 }
		 catch(IOException ioe)
		 {
			 ioe.printStackTrace();
			 jsonresponse.put("response_status", "error");
			 jsonresponse.put("message", "updateStatusWithMedia IOException message=" + ioe.getMessage());
		 }
		 return jsonresponse;
	}

	public JSONObject deleteStatus(String access_token, String access_token_secret, String id)
	{
		JSONObject jsonresponse = new JSONObject();
		
		String oauth_token = access_token;
		String oauth_token_secret = access_token_secret;

		// generate authorization header
		String get_or_post = "POST";
		String oauth_signature_method = "HMAC-SHA1";
		
		String uuid_string = UUID.randomUUID().toString();
		uuid_string = uuid_string.replaceAll("-", "");
		String oauth_nonce = uuid_string; // any relatively random alphanumeric string will work here
		
		// get the timestamp
		Calendar tempcal = Calendar.getInstance();
		long ts = tempcal.getTimeInMillis();// get current time in milliseconds
		String oauth_timestamp = (new Long(ts/1000)).toString(); // then divide by 1000 to get seconds
		
		// the parameter string must be in alphabetical order, "text" parameter added at end
		String parameter_string = "oauth_consumer_key=" + twitter_consumer_key + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method + 
		    		"&oauth_timestamp=" + oauth_timestamp + "&oauth_token=" + encode(oauth_token) + "&oauth_version=1.0";	
		System.out.println("parameter_string=" + parameter_string);
		
		String twitter_endpoint = "https://api.twitter.com/1.1/statuses/destroy/" + id + ".json";
		String twitter_endpoint_host = "api.twitter.com";
		String twitter_endpoint_path = "/1.1/statuses/destroy/" + id + ".json";
		String signature_base_string = get_or_post + "&"+ encode(twitter_endpoint) + "&" + encode(parameter_string);
		System.out.println("signature_base_string=" + signature_base_string);
	    String oauth_signature = "";
	    try {
	    	oauth_signature = computeSignature(signature_base_string, twitter_consumer_secret + "&" + encode(oauth_token_secret));  
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	    catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	    String authorization_header_string = "OAuth oauth_consumer_key=\"" + twitter_consumer_key + "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"" + oauth_timestamp + 
	    		"\",oauth_nonce=\"" + oauth_nonce + "\",oauth_version=\"1.0\",oauth_signature=\"" + encode(oauth_signature) + "\",oauth_token=\"" + encode(oauth_token) + "\"";
	    System.out.println("authorization_header_string=" + authorization_header_string);
		
		
	    HttpParams params = new SyncBasicHttpParams();
	    HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
	    HttpProtocolParams.setContentCharset(params, "UTF-8");
	    HttpProtocolParams.setUserAgent(params, "HttpCore/1.1");
	    HttpProtocolParams.setUseExpectContinue(params, false);	
	    HttpProcessor httpproc = new ImmutableHttpProcessor(new HttpRequestInterceptor[] {
	                // Required protocol interceptors
	                new RequestContent(),
	                new RequestTargetHost(),
	                // Recommended protocol interceptors
	                new RequestConnControl(),
	                new RequestUserAgent(),
	                new RequestExpectContinue()});

		 HttpRequestExecutor httpexecutor = new HttpRequestExecutor();
		 HttpContext context = new BasicHttpContext(null);
		 HttpHost host = new HttpHost(twitter_endpoint_host,443);
		 DefaultHttpClientConnection conn = new DefaultHttpClientConnection();

		 context.setAttribute(ExecutionContext.HTTP_CONNECTION, conn);
		 context.setAttribute(ExecutionContext.HTTP_TARGET_HOST, host);

		 try 
		 {
			 try 
			 {
				 SSLContext sslcontext = SSLContext.getInstance("TLS");
				 sslcontext.init(null, null, null);
				 SSLSocketFactory ssf = sslcontext.getSocketFactory();
				 Socket socket = ssf.createSocket();
				 socket.connect(
				   new InetSocketAddress(host.getHostName(), host.getPort()), 0);
				 conn.bind(socket, params);
				 BasicHttpEntityEnclosingRequest request2 = new BasicHttpEntityEnclosingRequest("POST", twitter_endpoint_path);
				 // need to add status parameter to this POST
				// request2.setEntity( new StringEntity("id=" + encode(id), "application/x-www-form-urlencoded", "UTF-8"));
				 request2.setParams(params);
				 request2.addHeader("Authorization", authorization_header_string);
				 httpexecutor.preProcess(request2, httpproc, context);
				 HttpResponse response2 = httpexecutor.execute(request2, conn, context);
				 response2.setParams(params);
				 httpexecutor.postProcess(response2, httpproc, context);
				 String responseBody = EntityUtils.toString(response2.getEntity());
				 System.out.println("response=" + responseBody);
				 // error checking here. Otherwise, status should be updated.
				 jsonresponse = new JSONObject(responseBody);
				 conn.close();
			 }   
			 catch(HttpException he) 
			 {	
				 System.out.println(he.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "updateStatus HttpException message=" + he.getMessage());
			 } 
			 catch(NoSuchAlgorithmException nsae) 
			 {	
				 System.out.println(nsae.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "updateStatus NoSuchAlgorithmException message=" + nsae.getMessage());
			 } 					
			 catch(KeyManagementException kme) 
			 {	
				 System.out.println(kme.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "updateStatus KeyManagementException message=" + kme.getMessage());
			 } 	
			 finally 
			 {
				 conn.close();
			 }	
		 } 
		 catch(JSONException jsone)
		 {
			 
		 }
		 catch(IOException ioe)
		 {
			 
		 }
		 return jsonresponse;
	}
	
	public JSONObject verifyCredentials(String access_token, String access_token_secret)
	{
		JSONObject jsonresponse = new JSONObject();
		
		String oauth_token = access_token;
		String oauth_token_secret = access_token_secret;

		// generate authorization header
		String get_or_post = "GET";
		String oauth_signature_method = "HMAC-SHA1";
		
		String uuid_string = UUID.randomUUID().toString();
		uuid_string = uuid_string.replaceAll("-", "");
		String oauth_nonce = uuid_string; // any relatively random alphanumeric string will work here
		
		// get the timestamp
		Calendar tempcal = Calendar.getInstance();
		long ts = tempcal.getTimeInMillis();// get current time in milliseconds
		String oauth_timestamp = (new Long(ts/1000)).toString(); // then divide by 1000 to get seconds

		// the parameter string must be in alphabetical order
		// this time, I add 3 extra params to the request, "lang", "result_type" and "q".
		String parameter_string = "oauth_consumer_key=" + twitter_consumer_key + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method + 
			"&oauth_timestamp=" + oauth_timestamp + "&oauth_token=" + encode(oauth_token) + "&oauth_version=1.0";	
		//System.out.println("parameter_string=" + parameter_string);
		String twitter_endpoint = "https://api.twitter.com/1.1/account/verify_credentials.json";
		String twitter_endpoint_host = "api.twitter.com";
		String twitter_endpoint_path = "/1.1/account/verify_credentials.json";
		String signature_base_string = get_or_post + "&"+ encode(twitter_endpoint) + "&" + encode(parameter_string);
		//System.out.println("signature_base_string=" + signature_base_string);
		
		// this time the base string is signed using twitter_consumer_secret + "&" + encode(oauth_token_secret) instead of just twitter_consumer_secret + "&"
		String oauth_signature = "";
		try {
			oauth_signature = computeSignature(signature_base_string, twitter_consumer_secret + "&" + encode(oauth_token_secret));  // note the & at the end. Normally the user access_token would go here, but we don't know it yet for request_token
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		String authorization_header_string = "OAuth oauth_consumer_key=\"" + twitter_consumer_key + "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"" + oauth_timestamp + 
				"\",oauth_nonce=\"" + oauth_nonce + "\",oauth_version=\"1.0\",oauth_signature=\"" + encode(oauth_signature) + "\",oauth_token=\"" + encode(oauth_token) + "\"";
		//System.out.println("authorization_header_string=" + authorization_header_string);


		 HttpParams params = new SyncBasicHttpParams();
		 HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
		 HttpProtocolParams.setContentCharset(params, "UTF-8");
		 HttpProtocolParams.setUserAgent(params, "HttpCore/1.1");
		 HttpProtocolParams.setUseExpectContinue(params, false);

		 HttpProcessor httpproc = new ImmutableHttpProcessor(new HttpRequestInterceptor[] {
	                // Required protocol interceptors
	                new RequestContent(),
	                new RequestTargetHost(),
	                // Recommended protocol interceptors
	                new RequestConnControl(),
	                new RequestUserAgent(),
	                new RequestExpectContinue()});

		 HttpRequestExecutor httpexecutor = new HttpRequestExecutor();
		 HttpContext context = new BasicHttpContext(null);
		 HttpHost host = new HttpHost(twitter_endpoint_host,443);
		 DefaultHttpClientConnection conn = new DefaultHttpClientConnection();

		 context.setAttribute(ExecutionContext.HTTP_CONNECTION, conn);
		 context.setAttribute(ExecutionContext.HTTP_TARGET_HOST, host);

		 try {
			 try {
				 SSLContext sslcontext = SSLContext.getInstance("TLS");
				 sslcontext.init(null, null, null);
				 SSLSocketFactory ssf = sslcontext.getSocketFactory();
				 Socket socket = ssf.createSocket();
				 socket.connect(
				   new InetSocketAddress(host.getHostName(), host.getPort()), 0);
				 conn.bind(socket, params);
				 
				 // the following line adds 3 params to the request just as the parameter string did above. They must match up or the request will fail.
				 BasicHttpEntityEnclosingRequest request2 = new BasicHttpEntityEnclosingRequest("GET", twitter_endpoint_path);
				 request2.setParams(params);
				 request2.addHeader("Authorization", authorization_header_string); // always add the Authorization header
				 httpexecutor.preProcess(request2, httpproc, context);
				 HttpResponse response2 = httpexecutor.execute(request2, conn, context);
				 response2.setParams(params);
				 httpexecutor.postProcess(response2, httpproc, context);

				 if(response2.getStatusLine().toString().indexOf("500") != -1)
				 {
					 jsonresponse.put("response_status", "error");
					 jsonresponse.put("message", "Twitter auth error.");
				 }
				 else
				 {
					 // if successful, the response should be a JSONObject of tweets
					 JSONObject jo = new JSONObject(EntityUtils.toString(response2.getEntity()));
					 if(jo.has("errors"))
					 {
						 jsonresponse.put("response_status", "error");
						 String message_from_twitter = jo.getJSONArray("errors").getJSONObject(0).getString("message");
						 if(message_from_twitter.equals("Invalid or expired token") || message_from_twitter.equals("Could not authenticate you"))
							 jsonresponse.put("message", "Twitter auth error.");
						 else
							 jsonresponse.put("message", jo.getJSONArray("errors").getJSONObject(0).getString("message"));
					 }
					 else
					 {
						 jsonresponse.put("twitter_jo", jo); // this is the full result object from Twitter
					 }
					 
					 conn.close();
				 }   
			 }
			 catch(HttpException he) 
			 {	
				 System.out.println(he.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "verifyCredentials HttpException message=" + he.getMessage());
			 } 
			 catch(NoSuchAlgorithmException nsae) 
			 {	
				 System.out.println(nsae.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "verifyCredentials NoSuchAlgorithmException message=" + nsae.getMessage());
			 } 					
			 catch(KeyManagementException kme) 
			 {	
				 System.out.println(kme.getMessage());
				 jsonresponse.put("response_status", "error");
				 jsonresponse.put("message", "verifyCredentials KeyManagementException message=" + kme.getMessage());
			 } 	
			 finally {
				 conn.close();
			 }
		 } 
		 catch(JSONException jsone)
		 {
			 
		 }
		 catch(IOException ioe)
		 {
			 
		 }
		 return jsonresponse;
	}
	
	
	public static void main(String[] args) {

		Twitter twitter = new Twitter();
		
	}

}
