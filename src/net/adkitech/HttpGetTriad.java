package net.adkitech;

import java.util.Formatter;
import java.util.Locale;

import org.apache.http.client.methods.HttpGet;

public class HttpGetTriad {

	private HttpGet httpGet; // url, headers, request entity
	private int responseStatusCode;
	private String responseString;
	
	public HttpGetTriad()
	{
		this.responseStatusCode = 0;
	}

	public HttpGet getHttpGet() {
		return httpGet;
	}

	public void setHttpGet(HttpGet httpGet) {
		this.httpGet = httpGet;
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
	
	public String stringify(String prefix)
	{
		String returnString = "";
		String requestUrl = null;
		String responseStatusCodeString = null;
		String responseString = null;
		if(this.httpGet != null)
			requestUrl = this.httpGet.getURI().toString();
		responseStatusCodeString = (new Integer(this.responseStatusCode)).toString();
		if(this.responseString != null)
			responseString = this.responseString;
		StringBuilder sb = new StringBuilder();
		Formatter formatter = new Formatter(sb, Locale.US);
		returnString = returnString + formatter.format("%1$40s: %2$s%n%1$40s: %3$s%n%1$40s: %4$s%n", prefix, requestUrl, responseStatusCodeString, responseString).toString();
		formatter.close();
		return returnString;
	}
}

