package net.adkitech;

public class A00_ConstantsEditMe {
	
	// FIRST, set up your app in Twitter. These two bits of info will be generated for you. Paste them here before running anything.
	public static String twitter_consumer_key = "";
	public static String twitter_consumer_secret = "";
	
	// SECOND, run StartAuthentication. If successful, it will generate an oauth_token. Paste it here.
	public static String oauth_token = "";
	
	// THIRD, visit https://www.twitter.com/oauth/authentication?oauth_token=YOUR_OAUTH_TOKEN to get a PIN. Paste it here.
	public static String verifier_or_pin = "";
	
	// FOURTH, run CompleteAuthentication. 	It will return a NEW "oauth_token" and "oauth_token_secret", which is confusing bc this oauth_token differs from the StartAuthentication one.
	// 										So, here, we'll call them "access_token" and "access_token_secret". Paste them here. (user_id and screen_name are provided as well, but you don't need them.)
	
	public static String access_token = "";
	public static String access_token_secret = "";
//	public static String user_id = "";
//	public static String screen_name = "";
}
