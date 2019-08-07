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
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;

// note this class is identical to GetTweet... because a favorite is just a pointer to a tweet (which can be yours or someone else's).

public class A08_GetFavorite {
	
	private GetExecutionHandler getExecutionHandler;
	private UtilsForTwitterAPI utils;
	
	public A08_GetFavorite()
	{
		getExecutionHandler = new GetExecutionHandler();
		utils = new UtilsForTwitterAPI();
	}	

	public Map<String,String> getTweet(String id)
	{
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
		String parameter_string = "id=" + id + "&oauth_consumer_key=" + A00_ConstantsEditMe.twitter_consumer_key + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method + 
			"&oauth_timestamp=" + oauth_timestamp + "&oauth_token=" + utils.encode(A00_ConstantsEditMe.access_token) + "&oauth_version=1.0";	
		String twitter_endpoint = "https://api.twitter.com/1.1/statuses/show.json";
		String signature_base_string = get_or_post + "&"+ utils.encode(twitter_endpoint) + "&" + utils.encode(parameter_string);
		
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
		
		String authorization_header_string = "OAuth oauth_consumer_key=\"" + A00_ConstantsEditMe.twitter_consumer_key + "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"" + oauth_timestamp + 
				"\",oauth_nonce=\"" + oauth_nonce + "\",oauth_version=\"1.0\",oauth_signature=\"" + utils.encode(oauth_signature) + "\",oauth_token=\"" + utils.encode(A00_ConstantsEditMe.access_token) + "\"";
		    
		String url = twitter_endpoint; 
		HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
		CloseableHttpClient httpclient = httpClientBuilder.build();
		HttpGet httpGet = null; 
		httpGet = new HttpGet(url + "?id=" + id);

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
			httpGet.setHeader(current.getName(), current.getValue());
		}

		// print request as we have it so far
		System.out.println("\n**************");
		System.out.println(httpGet.getRequestLine());
		Header[] headers2 = httpGet.getAllHeaders();
		int h = 0;
		while(h < headers2.length)
		{
			System.out.println("name=" +headers2[h].getName() + " value=" + headers2[h].getValue());
			h++;
		}
		System.out.println("\n**************");
		
		HttpGetTriad triad = null;
		try {
			triad = getExecutionHandler.doExecution(httpclient, httpGet);
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
		}
		
		return responseMap;
	}
	
	public static void main(String[] args) {

		A08_GetFavorite getFavorite = new A08_GetFavorite();
		Map<String,String> responseMap = getFavorite.getTweet("1065962440951762944"); //access_token and access_token_secret should be pasted into A00_ConstantsEditMe for this
	}

}
