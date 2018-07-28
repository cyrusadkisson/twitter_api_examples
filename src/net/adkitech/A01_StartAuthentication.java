package net.adkitech;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.UUID;

import org.apache.http.Header;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;

public class A01_StartAuthentication {
	
	private PostExecutionHandler postExecutionHandler;
	private UtilsForTwitterAPI utils;
	
	public A01_StartAuthentication()
	{
		postExecutionHandler = new PostExecutionHandler();
		utils = new UtilsForTwitterAPI();
	}	
	
	// the first step in the twitter oauth flow is to get a request token with a call to api.twitter.com/oauth/request_token
	// INPUT: nothing
	// OUTPUT: if successful, twitter API will return oauth_token, oauth_token_secret and oauth_token_confirmed
	
	public Map<String,String> startTwitterAuthentication()
	{
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
		String parameter_string = "oauth_callback=oob&oauth_consumer_key=" + A00_ConstantsEditMe.twitter_consumer_key + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method + "&oauth_timestamp=" + oauth_timestamp + "&oauth_version=1.0";		
		System.out.println("twitter_api_examples: (startTwitterAuthentication) parameter_string=" + parameter_string); // print out parameter string for error checking, if you want
		
		
		// specify the proper twitter API endpoint at which to direct this request
		String twitter_endpoint = "https://api.twitter.com/oauth/request_token";
		System.out.println("twitter_api_examples: (startTwitterAuthentication) targetting api.twitter.com/oauth/request_token");
		
		// assemble the string to be signed. It is METHOD & percent-encoded endpoint & percent-encoded parameter string
		// Java's native URLEncoder.encode function will not work. It is the wrong RFC specification (which does "+" where "%20" should be)... 
		// the encode() function included in this class compensates to conform to RFC 3986 (which twitter requires)
		String signature_base_string = get_or_post + "&"+ utils.encode(twitter_endpoint) + "&" + utils.encode(parameter_string);
		
		// now that we've got the string we want to sign (see directly above) HmacSHA1 hash it against the consumer secret
		String oauth_signature = "";
		try {
			oauth_signature = utils.computeSignature(signature_base_string, A00_ConstantsEditMe.twitter_consumer_secret + "&");  // note the & at the end. Normally the user access_token would go here, but we don't know it yet for request_token
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}	   
		catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		// each request to the twitter API 1.1 requires an "Authorization: BLAH" header. The following is what BLAH should look like
		String authorization_header_string = "OAuth oauth_callback=\"oob\",oauth_consumer_key=\"" + A00_ConstantsEditMe.twitter_consumer_key + "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"" + 
				oauth_timestamp + "\",oauth_nonce=\"" + oauth_nonce + "\",oauth_version=\"1.0\",oauth_signature=\"" + utils.encode(oauth_signature) + "\"";
		System.out.println("twitter_api_examples: (startTwitterAuthentication) authorization_header_string=" + authorization_header_string); 	// print out authorization_header_string for error checking
		     
		String url = twitter_endpoint; 
		HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
		CloseableHttpClient httpclient = httpClientBuilder.build();
		HttpPost httpPost = null; 
		httpPost = new HttpPost(url);

		List<NameValuePair> headers = new ArrayList<NameValuePair>();	 										// create an empty list
		NameValuePair authorizationPair = new BasicNameValuePair("Authorization", authorization_header_string);	// add the "Authorization" header with the string created above.
		headers.add(authorizationPair);																			// add the pair to the list of headers
		
		// now loop the header pairs and add them to the post
		NameValuePair current = null;
		Iterator<NameValuePair> header_it = headers.iterator();
		while(header_it.hasNext())
		{
			current = header_it.next();
			System.out.println("Adding header " + current.getName() + ":" + current.getValue());
			httpPost.setHeader(current.getName(), current.getValue());
		}

		// print request as we have it so far
		System.out.println("\n**************");
		System.out.println(httpPost.getRequestLine());
		Header[] headers2 = httpPost.getAllHeaders();
		int h = 0;
		while(h < headers2.length)
		{
			System.out.println("name=" +headers2[h].getName() + " value=" + headers2[h].getValue());
			h++;
		}
		System.out.println("\n**************");
		
		HttpPostTriad triad = null;
		try {
			triad = postExecutionHandler.doExecution(httpclient, httpPost);
		} catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		Map<String,String> responseMap = new HashMap<String,String>();
		
		if(triad == null || triad.getResponseString() == null)
			System.out.println("triad or triad.getResponseString() was null. Suppressing response squelch.");
		else
		{
			System.out.println("response string:" + triad.getResponseString());
			if(triad.getResponseStatusCode() != 200) // if it wasn't a successful request, then this error code will be something other than 200, return indicating as such
			{
				responseMap.put("response_status", "error");
				responseMap.put("message", "Twitter request_token request failed. Response was !200.");
			}
			else // returned 200 (good)
			{
				String responseBody = triad.getResponseString();
				System.out.println("endpoint startTwitterAuthentication responsebody=" + responseBody); // print out the response
					
				if(responseBody.indexOf("oauth_callback_confirmed=") == -1) // if this were true, that would be weird. Successful (200) response, but no oauth_callback_confirmed? 
				{
					responseMap.put("response_status", "error");
					responseMap.put("message", "Twitter request_token request failed. response was 200 but did not contain oauth_callback_confirmed");
				}
				else
				{
					// this assumes that oauth_callback_confirmed is always the last of the three values returned. I don't know 100% that is true, but it seems to be. 					
					String occ_val = responseBody.substring(responseBody.indexOf("oauth_callback_confirmed=") + 25);
					if(!occ_val.equals("true"))
					{
						responseMap.put("response_status", "error");
						responseMap.put("message", "Twitter request_token response was 200 and contained oauth_callback_confirmed but it was not \"true\".");
					}
					else // everything seems a-ok. look for values and return them.
					{
						String oauth_token = "";
						String oauth_token_secret = "";
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
							responseMap.put("response_status", "error");
							responseMap.put("message", "oauth tokens in response were invalid");
						}
						else // otherwise, we're all good. Return the values (did not include oauth_token_confirmed here. no need)
						{
							responseMap.put("response_status", "success");
							responseMap.put("oauth_token", oauth_token);
						}
					}
				 }
			 }  
		}		  
		return responseMap;
	}
	
	public static void main(String[] args) {

		A01_StartAuthentication twitter = new A01_StartAuthentication();
		Map<String,String> requestTokenResponseMap = twitter.startTwitterAuthentication();
		System.out.println("now visit https://www.twitter.com/oauth/authorize?oauth_token=" + requestTokenResponseMap.get("oauth_token") + ", then paste PIN and oauth_token into ConstantsEditMe to continue.");
	}

}
