package net.adkitech;

import org.json.JSONArray;

public class A06_DestroyAllMyTweets {
	
	public A06_DestroyAllMyTweets()
	{
		
	}	
	
	public static void main(String[] args) {

		A03_GetMyTweets tweetsGetter = new A03_GetMyTweets();
		A05_DestroyTweet tweetDestroyer = new A05_DestroyTweet();
		boolean destroyed = false;
		
		int x = 0;
		int limit = 100;
		while(x < limit)
		{	
			JSONArray tweetsArray = tweetsGetter.getMyTweets();
			int t = 0;
			while(t < tweetsArray.length())
			{
				destroyed = tweetDestroyer.destroyTweet(tweetsArray.getJSONObject(t).getString("id_str"));
				System.out.println("Tweet " + tweetsArray.getJSONObject(t).getString("id_str") + " destroyed? " + destroyed);
				t++;
			}
			x++;
		}
	}

}
