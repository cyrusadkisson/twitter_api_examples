package net.adkitech;

import java.io.IOException;
import java.util.Formatter;
import java.util.Locale;

import org.apache.http.client.methods.HttpPost;
import org.apache.http.util.EntityUtils;

public class HttpPostTriad {

	private HttpPost httpPost; // url, headers, request entity
	private int responseStatusCode;
	private String responseString;
	
	public HttpPostTriad()
	{
		responseStatusCode = 0;
	}
	
	public HttpPost getHttpPost() {
		return httpPost;
	}

	public void setHttpPost(HttpPost httpPost) {
		this.httpPost = httpPost;
	}

	public int getResponseStatusCode() {
		return responseStatusCode;
	}
	
	public void setResponseStatusCode(int responseStatusCode) {
		this.responseStatusCode = responseStatusCode;
	}
	
	public String getResponseString() {
		return responseString;
	}
	
	public void setResponseString(String responseString) {
		this.responseString = responseString;
	}
	
	public String stringify(String prefix, boolean includeRequestString)
	{
		String returnString = "";
		String requestUrl = null;
		String requestString = null;
		String responseStatusCodeString = null;
		String responseString = null;
		if(this.httpPost != null)
		{	
			try {
				requestString = EntityUtils.toString(this.httpPost.getEntity());
			} catch (IOException e) {
				requestString = "IOException inside HttpPostTriad.stringify(prefix)(company,triad) e.getMessage()=" + e.getMessage();
			}
			requestUrl = this.httpPost.getURI().toString();
		}
		
		responseStatusCodeString = (new Integer(this.responseStatusCode).toString());
		if(this.responseString != null)
			responseString = this.responseString;
		StringBuilder sb = new StringBuilder();
		Formatter formatter = new Formatter(sb, Locale.US);
		if(includeRequestString)
			returnString = returnString + formatter.format("%1$40s: %2$s%n    %1$40s: %3$s%n    %1$40s: %4$s%n    %1$40s: %5$s%n", prefix, requestUrl, requestString, responseStatusCodeString, responseString).toString();
		else
			returnString = returnString + formatter.format("%1$40s: %2$s%n    %1$40s: %3$s%n    %1$40s: %4$s%n    %1$40s: %5$s%n", prefix, requestUrl, "(request string suppressed for brevity)", responseStatusCodeString, responseString).toString();
		formatter.close();
		return returnString;
	}
}