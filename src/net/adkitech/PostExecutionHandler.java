package net.adkitech;

import java.io.IOException;

import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

public class PostExecutionHandler {
	
	public HttpPostTriad doExecution(CloseableHttpClient httpclient, HttpPost httpPost) throws ClientProtocolException, IOException 
	{
		HttpPostTriad triad = new HttpPostTriad();
		CloseableHttpResponse response = httpclient.execute(httpPost);
		String responseString = EntityUtils.toString(response.getEntity());
		StatusLine sl = response.getStatusLine();
		triad.setHttpPost(httpPost);
		triad.setResponseStatusCode(sl.getStatusCode());
		triad.setResponseString(responseString);
		return triad;
	}
	
}