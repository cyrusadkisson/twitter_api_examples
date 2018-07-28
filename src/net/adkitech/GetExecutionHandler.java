package net.adkitech;

import java.io.IOException;

import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

public class GetExecutionHandler {

	public HttpGetTriad doExecution(CloseableHttpClient httpclient, HttpGet httpGet) throws ClientProtocolException, IOException
	{
		HttpGetTriad triad = new HttpGetTriad();
		triad.setHttpGet(httpGet);
		CloseableHttpResponse response = httpclient.execute(httpGet);
		String responseString = EntityUtils.toString(response.getEntity());
		StatusLine sl = response.getStatusLine();
		triad.setResponseStatusCode(sl.getStatusCode());
		triad.setResponseString(responseString);
		return triad;
	}
	
}
