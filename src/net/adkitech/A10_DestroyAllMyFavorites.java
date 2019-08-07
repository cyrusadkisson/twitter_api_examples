package net.adkitech;

import org.json.JSONArray;

public class A10_DestroyAllMyFavorites {
	
	public A10_DestroyAllMyFavorites()
	{
		
	}	
	
	public static void main(String[] args) {

		A07_GetMyFavorites favoritesGetter = new A07_GetMyFavorites();
		A09_DestroyFavorite favoriteDestroyer = new A09_DestroyFavorite();
		boolean destroyed = false;
		
		int x = 0;
		int limit = 100;
		while(x < limit)
		{	
			JSONArray tweetsArray = favoritesGetter.getMyTweets();
			int t = 0;
			while(t < tweetsArray.length())
			{
				destroyed = favoriteDestroyer.destroyFavorite(tweetsArray.getJSONObject(t).getString("id_str"));
				System.out.println("Favorite " + tweetsArray.getJSONObject(t).getString("id_str") + " destroyed? " + destroyed);
				t++;
			}
			x++;
		}
	}

}
