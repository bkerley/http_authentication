module HttpAuthentication
  module Digest
    module ControllerMethods
      def authenticate_or_request_with_http_digest(realm = "Application", &login_procedure)
        authenticate_with_http_digest(&login_procedure) || request_http_digest_authentication(realm)
      end
      
      def authenticate_with_http_digest(&login_procedure)
        HttpAuthentication::Digest.authenticate(self, &login_procedure)
      end

      def request_http_digest_authentication(realm = "Application")
        HttpAuthentication::Digest.authentication_request(self, realm)
      end
      
      def digest_credentials(username, password, realm = 'Application')
         HttpAuthentication::Digest.HA1(username, realm, password)
       end
    end

    extend self
    
    def authenticate(controller, &login_procedure)
      if authorization(controller.request)
        login_procedure.call(*user_name_and_verifier(controller.request))
      else
        false
      end
    end

    def user_name_and_verifier(request)
      creds = decode_credentials(request)
      username = creds['username']
      
      nonce = creds['nonce']
      nonce_count = creds['nc']
      client_nonce = creds['cnonce']
      qop = creds['qop']
      
      method = request.method.to_s.upcase
      request_uri = request.request_uri
      ha2 = HA2(method, request_uri)
      verifier = proc do |ha1|
        response_digest(ha1, nonce, nonce_count, client_nonce, qop, ha2) == creds['response']
      end
      
      return [username, verifier]
    end
  
    def authorization(request)
      request.env['HTTP_AUTHORIZATION']   ||
      request.env['X-HTTP_AUTHORIZATION'] ||
      request.env['X_HTTP_AUTHORIZATION']
    end
  
    def decode_credentials(request)
      parse_auth_string(authorization(request))
    end

    def encode_credentials(user_name, password, auth_response_str, method, request_uri)
      resp = parse_auth_string(auth_response_str)
      realm = resp['realm']
      ha1 = HA1(user_name, realm, password)
      ha2 = HA2(method, request_uri)
      
      # bogus nonce_count, encode_credentials isn't used except for testing
      nonce_count = '00000001'
      client_nonce = make_opaque
      nonce = resp['nonce']
      qop = resp['qop']
      opaque = resp['opaque']
      
      response = response_digest(ha1, nonce, nonce_count, client_nonce, qop, ha2)
      
      encode_hash = {'username'=>user_name, 'realm'=>realm, 'nonce'=>nonce,
        'uri'=> request_uri, 'qop'=>qop, 'nc'=>nonce_count, 'cnonce'=>client_nonce,
        'response'=>response, 'opaque'=>opaque}
      return "Digest " + encode_hash.map{|k,v| tuple(k,v)}.join(',')
    end

    def authentication_request(controller, realm)
      controller.headers["WWW-Authenticate"] = %(Digest #{challenge_response(realm)})
      controller.send(:render, :text => "HTTP Digest: Access denied.\n", :status => :unauthorized)
      return false
    end

		def response_digest(ha1, nonce, nonce_count, client_nonce, qop, ha2)
			OpenSSL::Digest::MD5.hexdigest("#{ha1}:#{nonce}:#{nonce_count}:#{client_nonce}:#{qop}:#{ha2}")
		end
		
		def HA1(username, realm, password)
			OpenSSL::Digest::MD5.hexdigest("#{username}:#{realm}:#{password}")
		end
		
		def HA2(method, digest_uri)
			OpenSSL::Digest::MD5.hexdigest("#{method}:#{digest_uri}")
		end

    def parse_auth_string(auth_string)
      return auth_string.gsub('Digest ', '').split(',').inject({}) do |acc, e|
        eql = (e =~ /=/)
        key = e[0..(eql-1)].strip
        value = e[(eql+1)..-1]
        acc[key] = value.gsub('"','')
        acc
      end
    end

		private
		# conditional quotation for certain values
		def tuple(key, value)
		  noquote_keys = %w{nc qop}
		  return %(#{key}=\"#{value.gsub(/"/, "")}\") unless noquote_keys.include? key
		  return %(#{key}=#{value.gsub(/"/, "")})
	  end
		
		# RFC 2617 3.2.1
		def challenge_response(realm)
			challenge = {'qop'=>'auth', 'algorithm'=>'MD5'}
			
			challenge['realm'] = realm
			
			# Using a random opaquifier string as a nonce this compromises this against
			# replay attacks since we have no way to know know if we've seen a particular
			# nonce before.  If this is a problem, you might just want to use HTTPS.
			challenge['nonce'] = make_opaque
			challenge['opaque'] = make_opaque
			
			return challenge.map{|k,v| %(#{k}=\"#{v.gsub(/"/, "")}\")}.join(',')
		end
		
		def make_opaque
			Base64.encode64(OpenSSL::Random.random_bytes(30)).strip
		end
		

  end
end