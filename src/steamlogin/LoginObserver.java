package steamlogin;

public interface LoginObserver {
	
	void onLoginDone();
	
	void onError(String message);
	
	void onSecondFactorRequired();
	
}
