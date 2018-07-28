package net.adkitech;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
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
import org.apache.http.ParseException;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

public class A02_CompleteAuthentication {
	
	private PostExecutionHandler postExecutionHandler;
	private UtilsForTwitterAPI utils;
	
	public A02_CompleteAuthentication()
	{
		postExecutionHandler = new PostExecutionHandler();
		utils = new UtilsForTwitterAPI();
	}	
	
	public Map<String,String> getTwitterAccessTokenFromAuthorizationCode()
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
		
		
		// the parameter string must be in alphabetical order
		String parameter_string = "oauth_consumer_key=" + A00_ConstantsEditMe.twitter_consumer_key + "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method=" + oauth_signature_method + 
		    		"&oauth_timestamp=" + oauth_timestamp + "&oauth_token=" + utils.encode(A00_ConstantsEditMe.oauth_token) + "&oauth_version=1.0";		
		System.out.println("twitter_api_examples: (getTwitterAccessTokenFromAuthorizationCode) parameter_string=" + parameter_string);
		
		String twitter_endpoint = "https://api.twitter.com/oauth/access_token";
		String signature_base_string = get_or_post + "&"+ utils.encode(twitter_endpoint) + "&" + utils.encode(parameter_string);
			
		String oauth_signature = "";
		try {
			oauth_signature = utils.computeSignature(signature_base_string, A00_ConstantsEditMe.twitter_consumer_secret + "&");  // note the & at the end. Normally the user access_token would go here, but we don't know it yet
			System.out.println("twitter_api_examples: (getTwitterAccessTokenFromAuthorizationCode) oauth_signature=" + utils.encode(oauth_signature));
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		String authorization_header_string = "OAuth oauth_consumer_key=\"" + A00_ConstantsEditMe.twitter_consumer_key + "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"" + oauth_timestamp + 
				"\",oauth_nonce=\"" + oauth_nonce + "\",oauth_version=\"1.0\",oauth_signature=\"" + utils.encode(oauth_signature) + "\",oauth_token=\"" + utils.encode(A00_ConstantsEditMe.oauth_token) + "\"";
		    
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

		List<NameValuePair> bodyParams = new ArrayList<NameValuePair>();										// create an empty list of bodyparams
		//"oauth_verifier=" + encode(verifier_or_pin)
		NameValuePair verifierParam = new BasicNameValuePair("oauth_verifier", utils.encode(A00_ConstantsEditMe.verifier_or_pin));
		bodyParams.add(verifierParam);
		// this is just a printout
		Iterator<NameValuePair> requestparams_it = bodyParams.iterator();
		while(requestparams_it.hasNext())
		{
			current = requestparams_it.next();
			System.out.println("Body param " + current.getName() + ":" + current.getValue());
		}
		
		UrlEncodedFormEntity uefe = new UrlEncodedFormEntity(bodyParams,StandardCharsets.UTF_8);
		try {
			System.out.println("Body entity: " + EntityUtils.toString(uefe));
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		httpPost.setEntity(uefe);
		
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
		}
		
		return responseMap;
	}
	
	public static void main(String[] args) {

		A02_CompleteAuthentication completeAuthentication = new A02_CompleteAuthentication();
		Map<String,String> responseMap = completeAuthentication.getTwitterAccessTokenFromAuthorizationCode(); // PIN AND OAUTH_TOKEN should be pasted into A00_ConstantsEditMe when this is run.
	}

}
