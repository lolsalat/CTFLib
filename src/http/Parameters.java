package http;

import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

public class Parameters {
	
	public final Collection<NameValuePair> params;
	public final ParameterType type;
	public boolean encode = true;
	
	public static Parameters POST(String ... params) {
		return new Parameters(ParameterType.POST, params);
	}
	
	public static Parameters GET(String ... params) {
		return new Parameters(ParameterType.GET, params);
	}
	
	public static Parameters COOKIE(String ... params) {
		return new Parameters(ParameterType.COOKIE, params);
	}
	
	public static Parameters COOKIE(Header[] headers) {
		Collection<NameValuePair> params = new ArrayList<>();
		
		if(headers != null)
			for(Header header : headers) {
				for(HeaderElement element : header.getElements()) {
					params.add(new BasicNameValuePair(element.getName(), element.getValue() == null ? "" : element.getValue()));
				}
			}

		return new Parameters(params, ParameterType.COOKIE);
	}
	
	public static Parameters HEADER(String ... params) {
		return new Parameters(ParameterType.HEADER, params);
	}	
	
	public Parameters(ParameterType type, String... params) {
		Collection<NameValuePair> p = new ArrayList<>(params.length / 2);
		
		for(int i = 0; i < params.length - 1 /* cause nothing can stop stupidity xD */; i+= 2) {
			p.add(new BasicNameValuePair(params[i], params[i+1]));
		}
		
		this.params = p;
		this.type = type;
	}
	
	public Parameters(Collection<NameValuePair> params, ParameterType type) {
		this.params = params;
		this.type = type;
	}
	
	public String cookieString(Charset charset) {
		if(params.isEmpty())
			return "";
		
		StringBuilder sb = new StringBuilder();
		
		for(NameValuePair param : params) {
			sb.append(';').append((encode ? URLEncoder.encode(param.getName(), charset) : param.getName())).append("=").append((encode ? URLEncoder.encode(param.getValue(), charset) : param.getValue()));
		}
		
		return sb.substring(1);
	}
	
	public boolean contains(String name) {
		return getOpt(name).isPresent();
	}
	
	public Collection<String> get(String name){
		return params.stream().filter(x -> x.getName().equals(name)).map(x -> x.getValue()).collect(Collectors.toList());
	}
	
	public Optional<String> getOpt(String name) {
		Optional<NameValuePair> item = params.stream().filter(x -> x.getName().equals(name)).findAny();
		if(item.isEmpty())
			return Optional.empty();
		return Optional.of(item.get().getValue());
	}
	
	public String getAny(String name) {
		return params.stream().filter(x -> x.getName().equals(name)).findAny().get().getValue();
	}

	public void addOrUpdate(NameValuePair param) {
		NameValuePair remove = null;
		
		for(NameValuePair p : params) {
			if(p.getName().equals(param.getName())) {
				if(p.getValue().equals(param.getValue()))
					return;
				remove = p;
			}
		}
		
		if(remove != null) {
			params.remove(remove);
		}
		
		params.add(param);
	}
	
	public void add(NameValuePair param) {
		params.add(param);
	}
	
	
}
