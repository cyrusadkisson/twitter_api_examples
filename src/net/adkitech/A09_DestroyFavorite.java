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
import java.util.UUID;

import org.apache.http.Header;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONObject;

// this endpoint was confusing as hell bc it doesn't follow the same form as delete tweet or unretweet. This time, the id goes in the request line.
// but then that screws up the authentication part. Here is the formula that worked.
// 1. Though the Twitter API docs say to call "https://api.twitter.com/1.1/favorites/destroy.json?id=131312312312", 
//		base_url is just https://api.twitter.com/1.1/favorites/destroy.json for authentication purposes.
//		Thus "?id=1312312321" is NOT included in the base_url when hashed for oauth.
// 2. The "id=1312312321" IS included in the parameter_string (then signature_base_string) when hashed for oauth.
// 3. Additionally, id="1312312321" should be included in the authorization_header_string to match the oauth_signature.
// 4. Finally, ?id=13123112312 is tacked onto base_url late in the game, at the time the call is actually made. 
// Now it works. Thanks for the amazing documentation, Twitter! I love trial and error!

public class A09_DestroyFavorite {
	
	private PostExecutionHandler postExecutionHandler;
	private UtilsForTwitterAPI utils;
	
	public A09_DestroyFavorite()
	{
		postExecutionHandler = new PostExecutionHandler();
		utils = new UtilsForTwitterAPI();
	}	

	public boolean destroyFavorite(String id)
	{
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

		// the parameter string must be in alphabetical order
		// this time, I add 3 extra params to the request, "lang", "result_type" and "q".
		String parameter_string = 
				"id=" + id + "&" +  // this is not a "parameter" in the HTTP sense (i.e. it does not come after the ? in the query string nor as a post param. It is just part of the base URL. Twitter's docs are confusing on this.)
				"oauth_consumer_key=" + A00_ConstantsEditMe.twitter_consumer_key + "&" + 
				"oauth_nonce=" + oauth_nonce + "&" +
				"oauth_signature_method=" + oauth_signature_method + "&" + 
				"oauth_timestamp=" + oauth_timestamp + "&" +
				"oauth_token=" + utils.encode(A00_ConstantsEditMe.access_token) + "&" + 
				"oauth_version=1.0";	
		String base_url = "https://api.twitter.com/1.1/favorites/destroy.json";
		String signature_base_string = get_or_post + "&"+ utils.encode(base_url) + "&" + utils.encode(parameter_string);
		
		// this time the base string is signed using twitter_consumer_secret + "&" + encode(oauth_token_secret) instead of just twitter_consumer_secret + "&"
		String oauth_signature = "";
		try {
			oauth_signature = utils.computeSignature(signature_base_string, A00_ConstantsEditMe.twitter_consumer_secret + "&" + utils.encode(A00_ConstantsEditMe.access_token_secret));  // note the & at the end. Normally the user access_token would go here, but we don't know it yet for request_token
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		String authorization_header_string = "OAuth id=\"" + id + "\",oauth_consumer_key=\"" + A00_ConstantsEditMe.twitter_consumer_key + "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"" + oauth_timestamp + 
				"\",oauth_nonce=\"" + oauth_nonce + "\",oauth_version=\"1.0\",oauth_signature=\"" + utils.encode(oauth_signature) + "\",oauth_token=\"" + utils.encode(A00_ConstantsEditMe.access_token) + "\"";
		    
		HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
		CloseableHttpClient httpclient = httpClientBuilder.build();
		HttpPost httpPost = null; 
		httpPost = new HttpPost(base_url + "?id=" + id);

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
		
		if(triad == null || triad.getResponseString() == null)
		{
			System.out.println("triad or triad.getResponseString() was null. Suppressing response squelch.");
			return false;
		}
		else
		{
			System.out.println("response string:" + triad.getResponseString());
			JSONObject response = new JSONObject(triad.getResponseString());
			System.out.println(response);
			if(response.has("error"))
			{
				return false;
			}
			else
			{
				return true;
			}
		}
	}
	
	public static void main(String[] args) {

		A09_DestroyFavorite tweetDestroyer = new A09_DestroyFavorite();
		boolean destroyed = tweetDestroyer.destroyFavorite("1156381814522621952"); //access_token and access_token_secret should be pasted into A00_ConstantsEditMe for this
	}

}
