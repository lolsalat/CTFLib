package http;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

public class Requests {
	
	private static Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
	
	/**
	 * Creates a new HttpSession
	 */
	public static HttpSession session() {
		return new HttpSession();
	}
	
	/**
	 * Post request with data
	 * @param url 
	 * @param data
	 * @param parameters
	 * @return a Response
	 * @throws IllegalStateException on Error
	 */
	public static Response post(String url, byte[] data, Parameters... parameters) {
		try {
			return postRequest(url, data, parameters);
		} catch (ClientProtocolException e) {
			throw new IllegalStateException("ClientProtocolException", e);
		} catch (URISyntaxException e) {
			throw new IllegalStateException("URISyntaxException (Your Uri or parameters might be broken / too long)", e);
		} catch (IOException e) {
			throw new IllegalStateException("IOException (check your internet connection)", e);
		}
	}
	
	/**
	 * Post request with data
	 * @param url
	 * @param data
	 * @param parameters
	 * @return a Response
	 * @throws URISyntaxException
	 * @throws ClientProtocolException
	 * @throws IOException
	 */
	public static Response postRequest(String url, byte[] data, Parameters... parameters) throws URISyntaxException, ClientProtocolException, IOException {
		CloseableHttpClient client = HttpClients.createDefault();
		URIBuilder builder = new URIBuilder(url);
	
		HttpPost request = new HttpPost();

		request.setEntity(new ByteArrayEntity(data));
		
		for(Parameters params : parameters) {
			switch(params.type) {
			case COOKIE:
				addCookieParams(request, params);
				break;
			case GET:
				addGetParams(builder, params);
				break;
			case HEADER:
				addHeaderParams(request, params);
				break;
			case POST:
				throw new IllegalStateException("POST request with data cannot have POST parameters");
			case UNKNOWN:
				throw new IllegalStateException("Cannot handle parameters with unknown type!");
			default:
				break;
			}
		}
		
		request.setURI(builder.build());
	
		CloseableHttpResponse response = client.execute(request);

		List<NameValuePair> response_headers = new ArrayList<>();
		
		for(Header header : response.getAllHeaders()) {
			response_headers.add(header);
		}
		
		Parameters setCookie = Parameters.COOKIE(response.getHeaders("Set-Cookie"));
		
		HttpEntity entity = response.getEntity();
		
		byte[] response_data = entity == null ? null : EntityUtils.toByteArray(entity);
		
		client.close();
		
		return new Response(new Parameters(response_headers, ParameterType.HEADER), setCookie, response.getStatusLine().getStatusCode(), response_data);
	}
	
	/**
	 * Post request without data
	 * @param url
	 * @param parameters
	 * @return a Response
	 * @throws IllegalStatException on Error
	 */
	public static Response post(String url, Parameters... parameters) {
		try {
			return postRequest(url, parameters);
		} catch (ClientProtocolException e) {
			throw new IllegalStateException("ClientProtocolException", e);
		} catch (URISyntaxException e) {
			throw new IllegalStateException("URISyntaxException (Your Uri or parameters might be broken / too long)", e);
		} catch (IOException e) {
			throw new IllegalStateException("IOException (check your internet connection)", e);
		}
	}
	
	/**
	 * Post request without data
	 * @param url
	 * @param parameters
	 * @return a Response
	 * @throws IllegalStatException on Error
	 */
	public static Response postRequest(String url, Parameters... parameters) throws URISyntaxException, ClientProtocolException, IOException {
		
		// TODO join code with code of other post request (no need to do the same stuff twice)
		
		CloseableHttpClient client = HttpClients.createDefault();
		URIBuilder builder = new URIBuilder(url);
	
		HttpPost request = new HttpPost();

		for(Parameters params : parameters) {
			switch(params.type) {
			case COOKIE:
				addCookieParams(request, params);
				break;
			case GET:
				addGetParams(builder, params);
				break;
			case HEADER:
				addHeaderParams(request, params);
				break;
			case POST:
				addPostParams(request, params);
				break;
			case UNKNOWN:
				throw new IllegalStateException("Cannot handle parameters with unknown type!");
			default:
				break;
			}
		}
		
		request.setURI(builder.build());
	
		CloseableHttpResponse response = client.execute(request);

		List<NameValuePair> response_headers = new ArrayList<>();
		
		for(Header header : response.getAllHeaders()) {
			response_headers.add(header);
		}
		
		Parameters setCookie = Parameters.COOKIE(response.getHeaders("Set-Cookie"));
		
		HttpEntity entity = response.getEntity();
		
		byte[] response_data = entity == null ? null : EntityUtils.toByteArray(entity);
		
		client.close();
		
		return new Response(new Parameters(response_headers, ParameterType.HEADER), setCookie, response.getStatusLine().getStatusCode(), response_data);
	}
	
	public static Response get(String url, Parameters... parameters) {
		try {
			return getRequest(url, parameters);
		} catch (ClientProtocolException e) {
			throw new IllegalStateException("ClientProtocolException", e);
		} catch (URISyntaxException e) {
			throw new IllegalStateException("URISyntaxException (Your Uri or parameters might be broken / too long)", e);
		} catch (IOException e) {
			throw new IllegalStateException("IOException (check your internet connection)", e);
		}
	}
		
	
	/**
	 * Get request
	 * @param url
	 * @param parameters
	 * @return a Response
	 * @throws URISyntaxException
	 * @throws ClientProtocolException
	 * @throws IOException
	 */
	public static Response getRequest(String url, Parameters... parameters) throws URISyntaxException, ClientProtocolException, IOException {
		CloseableHttpClient client = HttpClients.createDefault();
		URIBuilder builder = new URIBuilder(url);
	
		HttpGet request = new HttpGet();

		for(Parameters params : parameters) {
			switch(params.type) {
			case COOKIE:
				addCookieParams(request, params);
				break;
			case GET:
				addGetParams(builder, params);
				break;
			case HEADER:
				addHeaderParams(request, params);
				break;
			case POST:
				throw new IllegalStateException("Get-request cannot have POST parameters!");
			case UNKNOWN:
				throw new IllegalStateException("Cannot handle parameters with unknown type!");
			default:
				break;
			}
		}
		
		request.setURI(builder.build());
	
		CloseableHttpResponse response = client.execute(request);

		List<NameValuePair> response_headers = new ArrayList<>();
		
		for(Header header : response.getAllHeaders()) {
			response_headers.add(header);
		}
		
		HttpEntity entity = response.getEntity();
		
		Parameters setCookie = Parameters.COOKIE(response.getHeaders("Set-Cookie"));
		
		byte[] data = entity == null ? null : EntityUtils.toByteArray(entity);
		
		client.close();
		
		return new Response(new Parameters(response_headers, ParameterType.HEADER), setCookie, response.getStatusLine().getStatusCode(), data);
	}
	
	/**
	 * Adds post parameters to a post request <br>
	 * They will be added as UrlEncoded entity
	 * @param post
	 * @param params
	 */
	private static void addPostParams(HttpPost post, Parameters params) {
		assert(params.type == ParameterType.POST);
		UrlEncodedFormEntity entity = new UrlEncodedFormEntity(params.params);
		post.setEntity(entity);
	}
	
	/**
	 * Adds cookies to a request
	 * @param request
	 * @param params
	 */
	private static void addCookieParams(HttpRequestBase request, Parameters params) {
		assert(params.type == ParameterType.COOKIE);
		request.addHeader("Cookie", params.cookieString(DEFAULT_CHARSET));
	}
	
	/**
	 * Adds header fields to a request
	 * @param request
	 * @param params
	 */
	private static void addHeaderParams(HttpRequestBase request, Parameters params) {
		assert(params.type == ParameterType.HEADER);
		for(NameValuePair param : params.params)
			request.addHeader(param.getName(), param.getValue());
	}
	
	/**
	 * Adds get parameters to request
	 * @param uri
	 * @param params
	 */
	private static void addGetParams(URIBuilder uri, Parameters params) {
		assert(params.type == ParameterType.GET);
		for(NameValuePair param : params.params)
			uri.addParameter(param.getName(), param.getValue());
	}
	
}
